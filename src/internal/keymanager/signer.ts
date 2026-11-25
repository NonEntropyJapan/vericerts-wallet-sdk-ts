/**
 * ECDSA 署名・検証の公開 API 入口（secp256k1 / P-256）。
 *
 * 曲線ごとの実装は責務分離のため以下へ分割し、本モジュールはそれらを再エクスポートして
 * 公開 API の入口を一本化する薄い facade に徹する（`Linterly` の行数上限対応）:
 * - `ecdsa/secp256k1-signer.ts`: secp256k1 recoverable 署名・検証・鍵導出・鍵復元。
 * - `ecdsa/p256-signer.ts`: P-256 署名・検証・鍵導出。
 * - `ecdsa/signature-format.ts`: 署名エンコーディングの正準性ルール・DER ⇔ P1363 変換・
 *   low-S 正規化・digest 長ガード。
 *
 * スコープ境界:
 * - Ethereum アドレス導出（keccak256(publicKey)）は本モジュールの責務外（KeyManager 領域）。
 *   本モジュールは recovery からの公開鍵復元までを提供する。
 * - KeyManager クラス / getSigner / Signer インターフェースは作らない。純粋関数のみを公開する。
 *
 * セキュリティ上の注意:
 * - privateKey / digest などの秘密・入力データは、例外メッセージや `context` に一切含めない
 *   （委譲先の各モジュールが遵守する）。
 */

export { getP256PublicKey, signP256, verifyP256 } from './ecdsa/p256-signer.js';
export {
  getSecp256k1PublicKey,
  type RecoverableSignature,
  recoverSecp256k1PublicKey,
  signSecp256k1Recoverable,
  verifySecp256k1,
} from './ecdsa/secp256k1-signer.js';
export {
  derToP1363,
  type EcdsaCurve,
  type EcdsaSignatureEncoding,
  normalizeLowS,
  p1363ToDer,
  type VerifyP256Options,
  type VerifySecp256k1Options,
} from './ecdsa/signature-format.js';
