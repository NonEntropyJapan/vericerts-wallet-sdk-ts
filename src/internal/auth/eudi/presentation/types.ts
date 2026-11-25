/**
 * EUDI 提示フロー（OID4VP）の依存・オプション型。
 *
 * 提示フロー（`present.ts`）は「Key Binding JWT の署名」と「VP Token の送信」の 2 つだけを
 * 外部から受け取る。生 privateKey は受け取らず、署名は `CredentialSigner`
 * （`credential/vc/signer.ts`）で DI する。`buildVPToken` の `SdJwtPresentationInput.signer` が
 * 要求する型と同一でなければならないため、同じ型をそのまま用いる。
 *
 * 送信シームだけ OID4VCI 側の `FetchLike` ではなく `SubmitFetchLike`（`auth/oid4vp/oid4vp-submit.ts`）
 * なのは、提示時にリダイレクトを拒否するため `redirect` を必ず渡すからで、
 * 型の揺れではない。同じ `fetchImpl` は参照形式（JAR）の `request_uri` GET にも使う
 * ―― 取得は `FetchLike`（`redirect` なし）で足りるので、`present.ts` が読み替えて渡す。
 * 呼び出し側に 2 つの fetch シームを持たせない（同じ HTTP スタックを使うのが自然であり、
 * 片方だけ差し替え忘れるとテストで実ネットワークへ出る）。
 *
 * セキュリティ上の注意:
 * - 本型のフィールドは**分割代入で読まない**。`signer` / `fetchImpl` は class の prototype
 *   メソッド・アクセサとして実装され得るため `nonObjectPrototypeProperty` で読む
 *   （`own-property.ts`「どちらのヘルパーを使うか」）。
 */

import type { CredentialSigner } from '../../../credential/vc/signer.js';
import type { PIDCredential } from '../../../eudi/pid/index.js';
import type { JarTrustOptions } from '../../jar/index.js';
import type { SubmitFetchLike } from '../../oid4vp/oid4vp-submit.js';

/**
 * `presentPID` の提示オプション。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface PresentOptions {
  /**
   * 提示する PID Credential。省略時は呼び出し側（facade）が保管済み PID から解決する。
   * 本モジュールの内部関数はいずれも解決済みの Credential を引数で受け取る。
   */
  readonly credential?: PIDCredential;
}

/**
 * PID / (Q)EAA 提示フローの依存（`presentPIDCredential` / `presentEAACredential`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface PresentDeps {
  /**
   * Key Binding JWT の署名鍵。SD-JWT VC の `cnf.jwk` に対応する Holder 鍵で、`kid`
   * （`did#fragment`）から提示者 DID（VP の `holder`）を導出する。
   */
  readonly signer: CredentialSigner;
  /** VP Token 送信の差し替えシーム（テスト注入用）。省略時はグローバル `fetch`。 */
  readonly fetchImpl?: SubmitFetchLike;
  /**
   * `request_uri` 参照形式（JAR）の提示要求で署名者を検証するための Trust Anchor と照合条件。
   *
   * HAIP §5.1 は OID4VP の提示要求について **JAR を `request_uri` 経由で使うことを
   * 必須**とする。したがって提示ファサードは参照形式を解決できなければならず、その解決は
   * JAR の署名検証を必ず経由する。検証の起点（Trust Anchor）は SDK が取得タイミングを
   * 決められないため呼び出し側から受け取る（`createWallet({ rpTrustAnchors })` が伝播する）。
   *
   * 未指定のまま参照形式の提示要求が届いた場合は `8030`
   * （`reason: "jar_trust_anchors_unconfigured"`）で拒否される（fail-closed）。直接形式には
   * 署名対象が無いため本メンバは不要である。
   */
  readonly jarTrust?: JarTrustOptions;
  /**
   * 利用者が同意画面で見て承認した `transaction_data`（要求上の生 base64url 文字列配列。要求に無ければ空配列）。
   * 指定時は、署名対象として取得・解析した要求の `transaction_data` が**完全に同一**でなければ提示を拒否する
   * （`10402`）。承認後に `request_uri` の応答が差し替わっても、承認した取引と別の取引へ署名しないための照合。
   * **要求が `transaction_data` を持つ場合は必須**。省略すると署名前に `10402`
   * （`reason: "transaction_data_consent_required"`）で拒否する（fail-closed）。
   * 照合なしで進めると、Verifier は `request_uri` の 2 回目の GET で取引内容を差し替えられる。
   * `transaction_data` を持たない要求では省略してよい。
   */
  readonly consentedTransactionData?: readonly string[];
}
