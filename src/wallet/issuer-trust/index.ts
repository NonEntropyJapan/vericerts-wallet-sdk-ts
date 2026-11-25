/**
 * 受領した Credential の Issuer 署名検証（sub-barrel）。
 *
 * `wallet.receiveCredential`、`wallet.receivePID`、`wallet.receiveEAA` で同じ署名検証を使う。
 *
 * - received-signature.ts: 既定検証の共通規則（鍵解決と照合の分離・`3010` への正規化・明示フック）。
 * - resolve.ts:            Issuer 鍵の解決経路の分岐順序と、その信頼材料（`ReceivedIssuerTrust`）。
 * - x5c.ts:                `x5c` → ETSI TSL Trust Anchor 経路（分岐 1）。
 * - jwt-vc-issuer.ts: opt-in の JWT VC Issuer Metadata 経路（分岐 2）。
 * - unresolvable.ts:       経路をまたいで共有する「鍵を解決できなかった」内部例外。
 *
 * 両受領経路（`wallet/credential/receive.ts` と `wallet/eudi/receive-verify.ts`）がここだけを参照
 * することで、規則の複製による「片方だけ fail-closed が緩む」事故を防ぐ。テストも同様にここを
 * 参照する（深いパス直参照が増えると、本バレルが公開面の実体でなくなる）。
 */

export {
  type ResolvedVerifyReceived,
  readVerifyReceived,
  receivedSignatureInvalid,
  runVerifyReceivedHook,
  type VerifyReceivedHook,
  verifyReceivedCredential,
  verifyReceivedSdJwt,
} from './received-signature.js';
export { buildReceivedIssuerTrust, type ReceivedIssuerTrust } from './resolve.js';
export { resolveX5cIssuerKey } from './x5c.js';
