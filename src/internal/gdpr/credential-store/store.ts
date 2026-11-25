/**
 * Wallet がローカル保持する VC レコードの永続化・GDPR メタデータ操作を担う `CredentialStore`。
 *
 * 本モジュールでは以下を提供する:
 * - `store` / `get`: VC レコードの永続化・取得（GDPR 操作対象の VC を storage に保持する基盤）。
 * - `listActiveCredentials`: 処理制限がかかっていない保持 VC を列挙する。
 * - `markDisputed`: Art.16 訂正権フォールバック（`disputed: true` を設定し Dashboard ログに追記）。
 * - `setProcessingRestriction`: Art.18 処理制限権（`processingRestricted` で提示候補から除外、VC 本体は削除しない）。
 * - `recordPresentation`: VC の提示履歴（`presentedTo`）を記録する。`revokeConsent` のスコープ解決の入力。
 * - `revokeConsent`: Art.7(3) 同意撤回（`consentRevoked` を記録し対象 VC を処理制限する）。
 * - `deleteCredential`: Art.17 忘れられる権利（VC レコードと参照ログを物理削除し削除監査記録を残す）。
 * - `purgeDashboardLog`: Art.17 削除権（Dashboard ログをフィルタ指定で一括物理削除、監査記録は残す）。
 * - `exportDashboardLog`: Art.15/Art.20（Dashboard ログを JWS 署名付き NDJSON でエクスポート）。
 *
 * セキュリティ上の注意: レコード・例外に privateKey / seed 等の秘密を含めない
 * （委譲先が秘密を含まない `VericertsError` に正規化済みのため、本クラスはそのまま伝播させる）。
 */

import type { CredentialSigner, VerifiableCredential } from '../../credential/index.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { KeyLock } from '../../primitives/key-lock.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { resolveActiveCredentials } from '../active-credentials.js';
import { withPresentedTo } from '../codec.js';
import {
  hasConsentTarget,
  ownConsentScope,
  resolveConsentTargets,
} from '../consent-scope-resolver.js';
import type { DashboardLog } from '../dashboard-log/dashboard-log.js';
import type { DashboardLogVerifierKey } from '../dashboard-log/dashboard-log-import.js';
import type {
  ConsentRevokedPayload,
  ConsentScope,
  CorrectionRequestPayload,
  CredentialRecord,
  LogFilter,
  PresentedToEntry,
} from '../types.js';
import {
  CREDENTIAL_KEY_PREFIX,
  type CredentialStorage,
  readRecord,
  recordKey,
  writeRecord,
} from './records.js';

/**
 * VC レコードの永続化・GDPR メタデータ操作を統合する管理クラス。
 *
 * 状態は storage に永続化されるため、本インスタンス自体はステートレス（注入された依存のみ保持）。
 */
export class CredentialStore {
  /**
   * @param storage レコードの永続化先。
   * @param dashboardLog GDPR 操作を記録する Dashboard ログ。
   * @param now 現在時刻取得関数。既定は `() => new Date()`。テスト時に注入する。
   */
  constructor(
    private readonly storage: CredentialStorage,
    private readonly dashboardLog: DashboardLog,
    private readonly now: () => Date = () => new Date(),
  ) {}

  /** VC id 単位の更新直列化ロック（単一プロセス内のみ有効）。 */
  private readonly recordLock = new KeyLock();

  /**
   * VC をレコードとして永続化する。`id` は `vc.id` を用いる（`markCredentialDisputed` 等の vcId 基準）。
   *
   * 同一 `vc.id` のレコードが既にある場合（再受領・再同期）は `credential` のみ差し替え、`receivedAt` と
   * GDPR メタデータ（`processingRestricted` / `disputed` / `presentedTo` / `legalHold` 等）は保持する
   * （上書きで Art.18 処理制限が解除され提示候補へ戻る、`revokeConsent` の対象解決が漏れる事故を防ぐ）。
   * 他の更新系と同じ `recordLock` で直列化する。
   *
   * @param vc 保持する VC。`id` が必須（GDPR 操作の対象キーとなるため）。
   * @returns 永続化したレコード。
   * @throws `vc.id` 未設定の場合（VericertsError、code `3002`）、既存レコードが破損している場合（code `3070`）。
   */
  async store(vc: VerifiableCredential): Promise<CredentialRecord> {
    const id = ownProperty<string>(vc, 'id');
    if (id === undefined || id === '') {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    return this.recordLock.run(id, async () => {
      const existing = await this.get(id);
      const record: CredentialRecord =
        existing === null
          ? { id, credential: vc, receivedAt: this.now().toISOString() }
          : { ...existing, credential: vc };
      await writeRecord(this.storage, record);
      return record;
    });
  }

  /**
   * 保存済み VC レコードを取得する。未存在なら `null`。
   *
   * @param vcId 取得する VC の ID。
   * @returns 保存済みレコード、または未存在時 `null`。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `3070`）。
   */
  async get(vcId: string): Promise<CredentialRecord | null> {
    return readRecord(this.storage, vcId);
  }

  /**
   * VC 単位で read-modify-write を直列化して更新する（並行更新の lost update 防止）。
   * `presentedTo` は `revokeConsent` のスコープ解決の唯一の入力のため、取りこぼしは同意撤回漏れになる。
   *
   * @throws 指定 VC が見つからない場合（VericertsError、code `3070`）。
   */
  private updateRecord(
    vcId: string,
    patch: (record: CredentialRecord) => CredentialRecord | Promise<CredentialRecord>,
  ): Promise<void> {
    return this.recordLock.run(vcId, async () => {
      const record = await this.get(vcId);
      if (record === null) {
        throw new VericertsError(ErrorCodes.VC_NOT_FOUND);
      }
      await writeRecord(this.storage, await patch(record));
    });
  }

  /** 処理制限がかかっていない保持 VC を列挙する。 */
  listActiveCredentials(): Promise<VerifiableCredential[]> {
    return resolveActiveCredentials(this.storage, CREDENTIAL_KEY_PREFIX);
  }

  /**
   * VC に訂正要求中（disputed）フラグを付与する（Art.16 訂正権フォールバック）。
   *
   * VC メタデータに `disputed: true` / `disputeReason` / `disputedAt` を設定して永続化し、Dashboard ログに
   * `type: "correctionRequest"` エントリを JWS 署名付きで追記する。VC 本体の署名には影響しない。
   *
   * @param vcId 対象 VC の ID。
   * @param reason 訂正要求の理由（Dashboard ログに記録する）。
   * @param signer Dashboard ログ署名鍵（`CredentialSigner`）。
   * @throws 指定 VC が見つからない場合（VericertsError、code `3070`）、
   *         署名演算が失敗した場合（code `1020`）。
   */
  async markDisputed(vcId: string, reason: string, signer: CredentialSigner): Promise<void> {
    await this.updateRecord(vcId, async (record) => {
      // 監査ログ（correctionRequest）を先に記録してから disputed フラグを永続化する（署名失敗時に
      // フラグだけ立って記録が欠落する不整合を避けるため「記録 → フラグ」の順で行う）。
      const payload: CorrectionRequestPayload = { vcId, reason };
      await this.dashboardLog.append('correctionRequest', { ...payload }, signer);
      return {
        ...record,
        disputed: true,
        disputeReason: reason,
        disputedAt: this.now().toISOString(),
      };
    });
  }

  /**
   * VC の処理制限（processingRestricted）フラグを設定する（Art.18 処理制限権）。
   *
   * VC メタデータに `processingRestricted` / `restrictionUpdatedAt` を設定して永続化する。`restricted: true`
   * の VC は以降 `matchCredentials()` 等の提示候補から除外される（除外判定は提示系 API の責務）。VC 本体は
   * 削除せず、VC の署名にも影響しない。この操作は Dashboard ログに記録しない。
   *
   * @param vcId 対象 VC の ID。
   * @param restricted `true`: 提示対象から除外、`false`: 通常状態に戻す。
   * @throws `restricted` が boolean でない場合（code `3002`。`'true'` / `1` の永続化は処理制限が黙って効かない
   *         fail-open になる）、指定 VC が見つからない場合（code `3070`）。
   */
  async setProcessingRestriction(vcId: string, restricted: boolean): Promise<void> {
    if (typeof restricted !== 'boolean') {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    await this.updateRecord(vcId, (record) => ({
      ...record,
      processingRestricted: restricted,
      restrictionUpdatedAt: this.now().toISOString(),
    }));
  }

  /**
   * VC が実際に RP へ提示されたことを記録する。
   *
   * VC メタデータの `presentedTo` 配列へ `{ rpIdentifier, purpose?, presentedAt }` を追記して永続化する。
   * `revokeConsent` の `rpIdentifier` / `purpose` スコープ解決の入力になる（提示していない VC はどの
   * スコープでも撤回対象にならない）。VC 本体は不変で署名にも影響せず、Dashboard ログにも記録しない
   * （提示イベント自体のログ記録は `logPresentationEvent` の責務）。
   *
   * @param vcId 提示した VC の ID。
   * @param rpIdentifier 提示先 RP の識別子。
   * @param purpose 提示の目的（RP が宣言した purpose。省略可）。
   * @throws 指定 VC が見つからない場合（VericertsError、code `3070`）。
   */
  async recordPresentation(vcId: string, rpIdentifier: string, purpose?: string): Promise<void> {
    const entry: PresentedToEntry = {
      rpIdentifier,
      presentedAt: this.now().toISOString(),
      ...(purpose !== undefined ? { purpose } : {}),
    };
    await this.updateRecord(vcId, (record) => withPresentedTo(record, entry));
  }

  /**
   * 特定スコープの同意を撤回する（Art.7(3) 同意撤回）。
   *
   * Dashboard ログに `type: "consentRevoked"` エントリを JWS 署名付きで追記して撤回証跡を残し、対象 VC を
   * 処理制限（`processingRestricted: true`）して以降の自動再提示対象から除外する。VC 本体は削除せず
   * 署名にも影響しない。`scope.vcId` 指定時は当該 VC 1 件、`rpIdentifier` / `purpose` 指定時は
   * `presentedTo` 履歴から解決した VC 群が対象になる（解決ロジックは `consent-scope-resolver.ts` 参照。
   * `scope.pseudonym` のみ指定時に VC レベルの処理制限を行わない既知の設計境界もそこに記載）。
   * `markDisputed` と同様、署名失敗（1020）時にフラグだけ立って監査記録が欠落する不整合を避けるため
   * 副作用は「ログ記録 → フラグ」の順で行う（対象 VC が 0 件でもログ記録は行う）。スコープが空（全
   * フィールド未指定）の場合は `GDPR_CONSENT_NOT_FOUND`(10603) を送出する。
   *
   * @param scope 撤回する同意のスコープ（rpIdentifier / purpose / vcId / pseudonym のいずれか 1 つ以上）。
   * @param signer Dashboard ログ署名鍵（`CredentialSigner`）。
   * @throws スコープが空の場合（VericertsError、code `10603`）、
   *         `scope.vcId` 指定で当該 VC が見つからない場合（code `3070`）、
   *         署名演算が失敗した場合（code `1020`）。
   */
  async revokeConsent(consentScope: ConsentScope, signer: CredentialSigner): Promise<void> {
    // own 限定で読み直した scope を判定・記録の双方に使う（Object.prototype 汚染対策）。
    const scope = ownConsentScope(consentScope);
    if (!hasConsentTarget(scope)) {
      throw new VericertsError(ErrorCodes.GDPR_CONSENT_NOT_FOUND);
    }
    const targets = await resolveConsentTargets(this.storage, scope);
    // 監査ログ（consentRevoked）を先に記録してから提示制限フラグを永続化する（記録欠落を防ぐ）。
    const payload: ConsentRevokedPayload = { scope: { ...scope } };
    await this.dashboardLog.append('consentRevoked', { ...payload }, signer);
    const restrictionUpdatedAt = this.now().toISOString();
    for (const target of targets) {
      // 解決時点のレコードで上書きすると並行更新（presentedTo 等）を巻き戻すため、排他区間内で読み直す。
      await this.recordLock.run(target.id, async () => {
        const current = await this.get(target.id);
        if (current === null) return;
        await writeRecord(this.storage, {
          ...current,
          processingRestricted: true,
          restrictionUpdatedAt,
        });
      });
    }
  }

  /**
   * VC を物理削除する（Art.17 忘れられる権利）。
   *
   * 対象 VC の存在（未存在なら `VC_NOT_FOUND`(3070)）と法的保持（`legalHold`、Art.17(3)(b) 該当時は
   * `GDPR_LEGAL_OBLIGATION`(10602)）を確認したうえで、Dashboard ログの別パーティションに
   * `credentialDeleted` の削除監査記録を JWS 署名付きで残し、当該 VC を参照するユーザー制御 Dashboard
   * ログエントリ（`correctionRequest` / `consentRevoked` 等）と VC レコード本体を物理削除する（削除監査
   * 記録は残す）。署名失敗（1020）時に監査記録なしでデータだけ消える不整合を避けるため、副作用は
   * 「監査記録 → 削除」の順で行う（`markDisputed` / `revokeConsent` と同じ順序方針）。VC 専用に導出した
   * 署名鍵の破棄（`crypto.subtle.deleteKey()` 相当）は、本レコードストアが VC 専用鍵を保持しない設計の
   * ため対象外（鍵の破棄は keymanager の責務）。
   *
   * @param vcId 削除対象 VC の ID。
   * @param signer 削除監査記録の署名鍵（`CredentialSigner`）。
   * @throws 指定 VC が見つからない場合（VericertsError、code `3070`）、
   *         法的義務により削除拒否の場合（code `10602`）、署名演算が失敗した場合（code `1020`）。
   */
  async deleteCredential(vcId: string, signer: CredentialSigner): Promise<void> {
    await this.recordLock.run(vcId, async () => {
      const record = await this.get(vcId);
      if (record === null) {
        throw new VericertsError(ErrorCodes.VC_NOT_FOUND);
      }
      if (ownProperty<boolean>(record, 'legalHold') === true) {
        throw new VericertsError(ErrorCodes.GDPR_LEGAL_OBLIGATION);
      }
      // 監査記録（credentialDeleted）を別パーティションに残してから物理削除する（記録欠落を防ぐ）。
      await this.dashboardLog.appendDeletionRecord(vcId, signer);
      await this.dashboardLog.deleteEntriesForVc(vcId, signer);
      await this.storage.delete(recordKey(vcId));
    });
  }

  /**
   * ユーザー制御 Dashboard ログを一括削除する（Art.17 削除権）。
   *
   * `filter` に一致する（省略時は全）ユーザー制御 Dashboard ログエントリ（`dashboard-log/`）を物理削除し、
   * 削除件数を返す。監査用の Art.17 削除記録（`deletion-log/`）は常に対象外。VC レコード本体は削除しない
   * （VC の物理削除は `deleteCredential` の責務）。署名は不要（ログを追記せず削除のみ行うため）。
   * 復号不能（破損）なエントリは、`filter` が全件対象なら無条件に削除し、絞り込み条件があれば読み飛ばす
   * （破損 1 件で全体を失敗させない）。
   *
   * @param filter 削除対象を絞り込むフィルタ（省略時は全エントリ）。
   * @returns 物理削除したエントリ数。
   */
  purgeDashboardLog(filter?: LogFilter): Promise<number> {
    return this.dashboardLog.purge(filter);
  }

  /**
   * ユーザー制御 Dashboard ログを機械可読な JWS 署名付き NDJSON でエクスポートする
   * （Art.15 アクセス権、Art.20 データポータビリティ）。
   *
   * `filter` に一致する（省略時は全）ユーザー制御 Dashboard ログエントリ（`dashboard-log/`）を追記順で
   * 出力し、末尾に Merkle chain のルートハッシュ行を付与した NDJSON テキストを返す。監査用の Art.17 削除記録
   * （`deletion-log/`）は常に対象外。読み出しのみで storage・VC レコード本体は一切変更しない（署名も不要）。
   *
   * @param filter エクスポート対象を絞り込むフィルタ（省略時は全エントリ）。
   * @returns NDJSON テキスト（各行が JWS 署名付きエントリ、末尾行が Merkle ルートハッシュ）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  exportDashboardLog(filter?: LogFilter): Promise<string> {
    return this.dashboardLog.exportLog(filter);
  }

  /**
   * `exportDashboardLog` が出力した JWS 署名付き NDJSON を検証してユーザー制御 Dashboard ログへ
   * インポートする（Art.20 データポータビリティ）。
   *
   * 署名・Merkle chain・ルートハッシュ行の検証はすべて `DashboardLog.importLog` に委譲する。既存 chain との
   * 連結を避けるため空の Dashboard ログにのみ許可する。VC レコード本体は変更しない。
   *
   * @param ndjson `exportDashboardLog` が生成した NDJSON テキスト。
   * @param verifierKey 署名検証鍵（署名時のペルソナ / エフェメラル公開鍵）。
   * @returns インポートしたエントリ数。
   * @throws NDJSON 形式不正の場合（VericertsError、code `2001`）、署名 / Merkle 検証失敗の場合
   *         （code `3010`）、既存ログが空でない場合（code `10604`）。
   */
  importDashboardLog(ndjson: string, verifierKey: DashboardLogVerifierKey): Promise<number> {
    return this.dashboardLog.importLog(ndjson, verifierKey);
  }
}
