/**
 * Wallet に保存した VC と Dashboard ログに対して GDPR のデータ主体の権利を行使するための API。
 * VC の訂正要求（Art.16）、処理制限（Art.18）、同意撤回（Art.7(3)）、削除（Art.17）と、
 * Dashboard ログの削除（Art.17）、アクセス・移送（Art.15 / Art.20）を扱う。
 */

import type { VerifiableCredential } from '../../internal/credential/index.js';
import type {
  ConsentScope,
  CredentialRecord,
  DashboardLogVerifierKey,
  LogFilter,
} from '../../internal/gdpr/index.js';

/**
 * GDPR データ主体権利行使 API。
 */
export interface GdprApi {
  /**
   * VC を Wallet ローカルに永続化する（GDPR 操作の対象となる VC を保持する基盤）。
   *
   * `vc.id` をレコードキーとして storage に保存する。`markCredentialDisputed` 等の GDPR 操作は
   * このレコードを対象に行う。
   *
   * @param vc 保持する VC。`id` が必須。
   * @returns 永続化した VC レコード（Wallet メタデータ含む）。
   * @throws `vc.id` 未設定の場合（VericertsError、code `3002`）。
   */
  storeCredential(vc: VerifiableCredential): Promise<CredentialRecord>;
  /**
   * 保存済み VC レコードを取得する。
   *
   * @param vcId 取得する VC の ID。
   * @returns 保存済みレコード。未保存なら `null`。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `3070`）。
   */
  getCredentialRecord(vcId: string): Promise<CredentialRecord | null>;
  /**
   * VC が実際に RP へ提示されたことを記録する。
   *
   * VC の Wallet メタデータの `presentedTo` 履歴へ `{ rpIdentifier, purpose?, presentedAt }` を追記する。
   * `revokeConsent` の `rpIdentifier` / `purpose` スコープはこの履歴を走査して対象 VC を解決するため、
   * 提示を記録していない VC はスコープ撤回の対象にならない。VC 本体は不変で署名にも影響しない。
   *
   * @param vcId 提示した VC の ID。
   * @param rpIdentifier 提示先 RP の識別子。
   * @param purpose 提示の目的（RP が宣言した purpose。省略可）。
   * @throws 指定 VC が見つからない場合（VericertsError、code `3070`）。
   */
  recordPresentation(vcId: string, rpIdentifier: string, purpose?: string): Promise<void>;
  /**
   * VC に訂正要求中（disputed）フラグを付与する（GDPR Art.16 訂正権フォールバック）。
   *
   * VC の Wallet メタデータに `disputed: true` を設定して永続化し、Dashboard ログに
   * `type: "correctionRequest"` エントリをアクティブペルソナ鍵の JWS 署名付きで記録する。VC 本体の
   * 署名には影響しない。以降の提示時に警告表示・`disputed: true` 付与を行うのは提示系 API の責務。
   *
   * @param vcId 対象 VC の ID。
   * @param reason 訂正要求の理由（Dashboard ログに JWS 署名付きで記録する）。
   * @throws 指定 VC が見つからない場合（VericertsError、code `3070`）、
   *         アクティブペルソナ未設定の場合（code `2005`）、署名失敗の場合（code `1020`）。
   */
  markCredentialDisputed(vcId: string, reason: string): Promise<void>;
  /**
   * VC の処理制限フラグを設定する（GDPR Art.18 処理制限権）。
   *
   * VC の Wallet メタデータに `processingRestricted` を設定して永続化する。`restricted: true` の VC は
   * 以降 `matchCredentials()` / `matchCredentialsByPresentationDefinition()` の提示候補から除外される
   * （除外判定は提示系 API の責務）。VC 本体は削除せず署名にも影響しない。`markCredentialDisputed` と
   * 異なり Dashboard ログには記録しない。
   *
   * @param vcId 対象 VC の ID。
   * @param restricted `true`: 提示対象から除外、`false`: 通常状態に戻す。
   * @throws 指定 VC が見つからない場合（VericertsError、code `3070`）。
   */
  setCredentialProcessingRestriction(vcId: string, restricted: boolean): Promise<void>;
  /**
   * 特定スコープの同意を撤回する（GDPR Art.7(3) 同意撤回）。
   *
   * Dashboard ログに `type: "consentRevoked"` エントリをアクティブペルソナ鍵の JWS 署名付きで記録し、対象
   * VC を処理制限（提示対象から除外）する。`scope.vcId` 指定時は当該 VC 1 件、`rpIdentifier` / `purpose`
   * 指定時は `recordPresentation` が記録した提示履歴から解決した VC 群が対象になる。VC 本体は削除せず
   * 署名にも影響しない。`scope.rpIdentifier` 指定時は当該 RP に紐づく Pseudonym も破棄済みとしてマークする。
   * スコープには `rpIdentifier` / `purpose` / `vcId` / `pseudonym` のいずれか 1 つ以上を指定する。
   *
   * @param scope 撤回する同意のスコープ。全フィールド未指定は撤回対象を特定できない。
   * @throws スコープが空の場合（VericertsError、code `10603`）、`scope.vcId` 指定で当該 VC が
   *         見つからない場合（code `3070`）、アクティブペルソナ未設定の場合（code `2005`）、
   *         署名失敗の場合（code `1020`）。
   */
  revokeConsent(scope: ConsentScope): Promise<void>;
  /**
   * VC を物理削除する（GDPR Art.17 忘れられる権利）。
   *
   * VC レコード本体と、当該 VC を参照するユーザー制御 Dashboard ログエントリ（`correctionRequest` /
   * `consentRevoked` 等）を storage から物理削除する。削除の事実は監査用の別ログパーティションに
   * `type: "credentialDeleted"` エントリとしてアクティブペルソナ鍵の JWS 署名付きで残す（削除後も監査可能）。
   * 法的義務（Art.17(3)(b)）で保持中の VC は削除できず `GDPR_LEGAL_OBLIGATION`(10602) を送出する。
   *
   * @param vcId 削除対象 VC の ID。
   * @throws 指定 VC が見つからない場合（VericertsError、code `3070`）、法的義務により削除拒否の場合
   *         （code `10602`）、アクティブペルソナ未設定の場合（code `2005`）、署名失敗の場合（code `1020`）。
   */
  deleteCredential(vcId: string): Promise<void>;
  /**
   * ユーザー制御 Dashboard ログを一括削除する（GDPR Art.17 削除権）。
   *
   * `filter` に一致する（省略時は全）ユーザー制御 Dashboard ログエントリを storage から物理削除し、
   * 削除件数を返す。監査用の Art.17 削除記録（`credentialDeleted` の別ログパーティション）は常に対象外。
   * VC レコード本体は削除しない（VC の物理削除は `deleteCredential` の責務）。`filter` の各条件は AND で
   * 適用する（`olderThan`: 当該 ISO 8601 日時より前、`types`: 種別一致、`rpIdentifier`: RP 識別子一致）。
   *
   * @param filter 削除対象を絞り込むフィルタ（省略時は全エントリ）。
   * @returns 物理削除したエントリ数。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  purgeDashboardLog(filter?: LogFilter): Promise<number>;
  /**
   * ユーザー制御 Dashboard ログを機械可読形式でエクスポートする（GDPR Art.15 アクセス権 /
   * Art.20 データポータビリティ）。
   *
   * `filter` に一致する（省略時は全）ユーザー制御 Dashboard ログエントリ（`dashboard-log/`）を追記順に
   * 並べた JWS 署名付き NDJSON（`application/x-ndjson`）の `Blob` を返す。各行が 1 エントリの JSON
   * （追記時に署名した `signature` をそのまま含む）で、末尾に Merkle chain のルートハッシュ行
   * （`merkleRoot` と `count`）を付与する。絞り込みや削除により先頭からの連続性が失われた場合は、
   * 末尾の行に `partial: true` が付く。インポート側は各行の JWS 署名と `prevHash` を検証できる。
   * 監査用の Art.17 削除記録（`deletion-log/`）は常に対象外。読み出しのみで
   * storage は変更せず、アクティブペルソナ・署名鍵にも依存しない。`filter` の各条件は AND で適用する。
   *
   * @param filter エクスポート対象を絞り込むフィルタ（省略時は全エントリ）。
   * @returns JWS 署名付き NDJSON の `Blob`（MIME タイプ `application/x-ndjson`）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  exportDashboardLog(filter?: LogFilter): Promise<Blob>;
  /**
   * `exportDashboardLog` が出力した機械可読 Dashboard ログを検証しつつインポートする（GDPR Art.20
   * データポータビリティ）。
   *
   * `exportDashboardLog` の戻り値（`application/x-ndjson` の `Blob`）または NDJSON 文字列を受け取り、
   * 各行の JWS 署名を `verifierKey` で検証し、`prevHash` の連鎖と末尾のルートハッシュ・件数を確認する。
   * `partial: true` の場合は欠けた行を許容し、連番が隣り合うエントリ間の連鎖を確認する。検証に失敗すれば
   * インポートを拒否する。検証済みエントリは署名・`prevHash` を保ったまま（再署名せず）永続化し、改ざん
   * 検知の連続性を維持する。既存 chain との連結を避けるため、ユーザー制御 Dashboard ログが空の場合にのみ
   * 許可する（新規 / 復旧端末への移送を想定）。読み出し系の署名鍵は不要（署名検証のみ）。
   *
   * @param ndjson `exportDashboardLog` が生成した `Blob` または NDJSON 文字列。
   * @param verifierKey 署名検証鍵（署名時のペルソナ / エフェメラル公開鍵の alg + JWK）。
   * @returns インポートしたエントリ数。
   * @throws NDJSON 形式不正・ルートハッシュ行欠落の場合（VericertsError、code `2001`）、署名検証失敗・
   *         Merkle chain / ルートハッシュ不一致の場合（code `3010`）、既存 Dashboard ログが空でない場合
   *         （code `10604`）。
   */
  importDashboardLog(ndjson: Blob | string, verifierKey: DashboardLogVerifierKey): Promise<number>;
}
