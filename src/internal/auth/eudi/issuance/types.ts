/**
 * EUDI 受領フロー（OID4VCI Pre-Authorized Code Flow）の依存・オプション型。
 *
 * 受領フロー（`receive.ts`）は「署名」「Holder 識別子」「HTTP」「Wallet Attestation」の 4 つを
 * 外部から受け取る。生 privateKey は一切受け取らず、署名は `CredentialSigner`
 * （`credential/vc/signer.ts`）で DI する（keymanager / KMS が鍵を露出せず署名できる seam。
 * `generateProofJWT` が要求する型と同一である必要があるため、同じ型をそのまま用いる）。
 *
 * セキュリティ上の注意:
 * - 本型のフィールドは**分割代入で読まない**。`signer` / `fetchImpl` / `buildClientAttestation` は
 *   class の prototype メソッド・アクセサとして実装され得るため `nonObjectPrototypeProperty`、
 *   純データの `holderDid` / `keyId` は `ownProperty` で読む（`own-property.ts`）。
 */

import type { CredentialSigner } from '../../../credential/vc/signer.js';
import type { ClientAttestation } from '../../../eudi/wua/types.js';
import type { FetchLike } from '../../../fetch-di.js';
import type { Metrics } from '../../../observability/metrics.js';

/**
 * PID / (Q)EAA 受領フローの依存（`receivePIDCredential` / `receiveEAACredential`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface ReceiveDeps {
  /**
   * JWT Proof（`openid4vci-proof+jwt`）の署名鍵。`generateProofJWT` が要求する
   * `CredentialSigner` と同一型で、生 privateKey は渡さない。
   */
  readonly signer: CredentialSigner;
  /** Holder DID。JWT Proof payload の `iss` になる。 */
  readonly holderDid: string;
  /** 検証鍵 ID（`did#fragment` 形式）。JWT Proof の JWS ヘッダ `kid` になる。 */
  readonly keyId: string;
  /**
   * HTTP 呼び出しの差し替えシーム（Metadata 取得 / Token Request / Credential Request の
   * 3 経路すべてに伝播する）。省略時はグローバル `fetch`。
   */
  readonly fetchImpl?: FetchLike;
  /**
   * Token Request へ添付する `client_assertion` を組み立てる関数。指定した場合にのみ
   * `client_assertion` / `client_assertion_type` を送る。
   *
   * **組み立て済みの `ClientAttestation` ではなく関数を受け取る。** WUA-PoP の `aud` は
   * 「実際に Token Request を送る Token Endpoint」でなければならず、
   * その値が確定するのは Issuer Metadata を解決した**受領フローの内部**だけである。呼び出し側が
   * 事前に組み立てると `aud` は推測値になり、別 AS 向けに署名した PoP をそのまま送れてしまう
   * （`aud` に束縛されない PoP はリプレイ可能）。したがって `aud` の決定権をフロー側に残す。
   *
   * 引数は解決済みの Token Endpoint（= WUA-PoP の `aud`）1 つ。`nonce` は渡さない。
   * pre-authorized_code フローでは AS の `c_nonce` が **Token Response** で初めて得られるため、
   * その Token Request 自身を認証する PoP に載せられる `c_nonce` は存在しないからである
   * （nonce の供給は呼び出し側の責務）。
   */
  readonly buildClientAttestation?: (aud: string, nonce: string) => ClientAttestation;
  /**
   * `vericerts_oid4vci_token_duration_seconds{flow=pre-auth}` の記録先。
   * 未指定なら記録しない。
   */
  readonly metrics?: Metrics;
  /**
   * Credential Request の本文の形。省略時は `draft`（旧 Draft 形）。`1.0` で
   * OID4VCI 1.0 Final §8.2 の `{ credential_configuration_id, proofs: { jwt: [..] } }` で送る
   * （`credential_configuration_id` は Offer の `credential_configuration_ids[0]`）。SDK は Issuer の
   * バージョンを推測しないため明示する。
   */
  readonly credentialRequestVersion?: 'draft' | '1.0';
}
