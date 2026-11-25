/**
 * Wallet に保存した VC の管理・提示と Dashboard ログの操作を実装する。
 * 訂正要求、同意撤回、削除の記録にはアクティブペルソナ鍵で JWS 署名する（ペルソナ未設定は 2005）。
 * 対象 VC の存在、撤回スコープ、法的保持の検証（3070 / 10603 / 10602）は `CredentialStore` が担う。
 */

import type { CreatedPresentation } from '../../internal/auth/create-presentation/index.js';
import type { PresentationRequestOptions } from '../../internal/auth/index.js';
import type { VerifiableCredential } from '../../internal/credential/index.js';
import type {
  ConsentScope,
  CredentialRecord,
  CredentialStore,
  DashboardLogVerifierKey,
  LogFilter,
} from '../../internal/gdpr/index.js';
import { DASHBOARD_LOG_EXPORT_MIME } from '../../internal/gdpr/index.js';
import type { KeyManager } from '../../internal/keymanager/keymanager.js';
import type { PersonaManager } from '../../internal/persona/persona.js';
import type { PresentationDefinition } from '../../internal/presentation-exchange/index.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import { createPresentationWith } from '../credential/create-presentation.js';
import { matchCredentialsWith } from '../credential/match.js';
import { matchCredentialsByPresentationDefinitionWith } from '../credential/match-by-presentation-definition.js';
import { type ActiveSignerOptions, resolveActiveSigner } from '../setup.js';

/** Wallet の GDPR 操作で使う VC ストアと署名鍵へのアクセスをまとめる。 */
export class GdprFacade {
  constructor(
    private readonly credentials: CredentialStore,
    private readonly personas: PersonaManager,
    private readonly keymanager: KeyManager,
    /** 取り込んだ DID のペルソナで署名するための Resolver・外部秘密鍵の提供元（`factory.ts` が組み立てる）。 */
    private readonly signing?: ActiveSignerOptions,
  ) {}

  /** VC を Wallet ローカルに永続化する。 */
  storeCredential(vc: VerifiableCredential): Promise<CredentialRecord> {
    return this.credentials.store(vc);
  }

  /** 保存済み VC レコードを取得する。 */
  getCredentialRecord(vcId: string): Promise<CredentialRecord | null> {
    return this.credentials.get(vcId);
  }

  /**
   * 処理制限中の VC を除き、Presentation Exchange v2 の PresentationDefinition に合致する保持 VC を返す。
   */
  async matchCredentialsByPresentationDefinition(
    pd: PresentationDefinition,
  ): Promise<VerifiableCredential[]> {
    const credentials = await this.credentials.listActiveCredentials();
    return matchCredentialsByPresentationDefinitionWith(pd, credentials);
  }

  /**
   * 処理制限中の VC を除き、Presentation Request に合致する保有 VC を返す。
   */
  matchCredentials(
    requestURI: string,
    opts?: PresentationRequestOptions,
  ): Promise<VerifiableCredential[]> {
    return matchCredentialsWith(this.credentials, requestURI, opts);
  }

  /**
   * 指定した VC から OID4VP リクエストに応じた VP を作成し、JWT-VP として署名する。
   */
  createPresentation(
    requestURI: string,
    vcIDs: string[],
    opts?: PresentationRequestOptions,
  ): Promise<CreatedPresentation> {
    return createPresentationWith(
      this.credentials,
      this.personas,
      this.keymanager,
      requestURI,
      vcIDs,
      opts,
      this.signing,
    );
  }

  /** VC に訂正要求中フラグを付与する（Art.16）。Dashboard ログをペルソナ鍵で署名する。 */
  async markCredentialDisputed(vcId: string, reason: string): Promise<void> {
    const { signer } = await resolveActiveSigner(this.personas, this.keymanager, this.signing);
    await this.credentials.markDisputed(vcId, reason, signer);
  }

  /** VC の処理制限フラグを設定する（Art.18）。Dashboard ログには記録しない。 */
  setCredentialProcessingRestriction(vcId: string, restricted: boolean): Promise<void> {
    return this.credentials.setProcessingRestriction(vcId, restricted);
  }

  /**
   * 特定スコープの同意を撤回する（Art.7(3)）。Dashboard ログをペルソナ鍵で署名する。
   *
   * `scope.rpIdentifier` 指定時は、対象 VC の処理制限（`credentials.revokeConsent` の責務）に加えて
   * 当該 RP に紐づく Pseudonym を破棄済みとしてマークする。
   */
  async revokeConsent(scope: ConsentScope): Promise<void> {
    const { signer } = await resolveActiveSigner(this.personas, this.keymanager, this.signing);
    await this.credentials.revokeConsent(scope, signer);
    // 継承値（Object.prototype 汚染）を RP 識別子として拾わない。
    const rpIdentifier = ownProperty<string>(scope, 'rpIdentifier');
    if (rpIdentifier !== undefined) {
      await this.personas.discardPseudonym(rpIdentifier);
    }
  }

  /**
   * VC が実際に RP へ提示されたことを記録する。`revokeConsent` の `rpIdentifier` /
   * `purpose` スコープ解決の入力になる（`presentedTo` 履歴への追記）。
   */
  recordPresentation(vcId: string, rpIdentifier: string, purpose?: string): Promise<void> {
    return this.credentials.recordPresentation(vcId, rpIdentifier, purpose);
  }

  /** VC を物理削除する（Art.17）。削除監査記録をペルソナ鍵で署名する。 */
  async deleteCredential(vcId: string): Promise<void> {
    const { signer } = await resolveActiveSigner(this.personas, this.keymanager, this.signing);
    await this.credentials.deleteCredential(vcId, signer);
  }

  /**
   * ユーザー制御 Dashboard ログを一括削除する（Art.17 削除権）。
   * ログ追記はなく削除のみのため署名鍵は不要（アクティブペルソナに依存しない）。
   */
  purgeDashboardLog(filter?: LogFilter): Promise<number> {
    return this.credentials.purgeDashboardLog(filter);
  }

  /**
   * ユーザー制御 Dashboard ログを JWS 署名付き NDJSON でエクスポートする（Art.15 アクセス権 /
   * Art.20 データポータビリティ）。読み出しのみのため署名鍵・アクティブペルソナに
   * 依存しない（`purgeDashboardLog` と同様に鍵不要）。NDJSON テキストを `application/x-ndjson` の `Blob`
   * として返す。
   */
  async exportDashboardLog(filter?: LogFilter): Promise<Blob> {
    const ndjson = await this.credentials.exportDashboardLog(filter);
    return new Blob([ndjson], { type: DASHBOARD_LOG_EXPORT_MIME });
  }

  /**
   * `exportDashboardLog` が出力した JWS 署名付き NDJSON を検証してユーザー制御 Dashboard ログへ
   * インポートする（Art.20 データポータビリティ）。署名・Merkle chain・ルート
   * ハッシュ行をすべて検証してから永続化する（検証は `CredentialStore` / `DashboardLog` に委譲）。
   * `Blob`（`exportDashboardLog` の戻り値）と NDJSON 文字列の両方を受け付ける。公開鍵で検証するため署名鍵は不要。
   */
  async importDashboardLog(
    ndjson: Blob | string,
    verifierKey: DashboardLogVerifierKey,
  ): Promise<number> {
    const text = typeof ndjson === 'string' ? ndjson : await ndjson.text();
    return this.credentials.importDashboardLog(text, verifierKey);
  }
}
