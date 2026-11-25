/**
 * DIDベース SIOPv2 モジュールの公開エントリ（内部バレル）。
 *
 * 本モジュールは `errors.js` / `non-empty-string.js` /
 * `own-property.js`（横断）と `credential/vc/*`（Domain）にのみ閉じ、ethers / viem 等の重い
 * 推移依存を持たない。
 */

export { type GenerateIdTokenOptions, generateIDToken } from './id-token.js';
export { parseSIOPv2Request } from './parse.js';
export { processSIOPv2Request } from './process.js';
export { assertValidRPRegistration } from './rp-registration.js';
export type { RPRegistration, SIOPv2Request, SIOPv2Response } from './types.js';
export {
  type VerifiedIdToken,
  type VerifyIdTokenOptions,
  verifyIDToken,
} from './verify-id-token.js';
export { generateVpToken } from './vp-token.js';
