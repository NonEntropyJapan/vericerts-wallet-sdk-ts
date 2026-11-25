/**
 * eudi/wua モジュールの公開エントリ。
 *
 * Wallet Provider Backend からの WUA 取得（`obtain.ts`。HTTP）・JWT 解析・検証・WSCD バインド
 * 検証・WUA-PoP 生成・OAuth2 Attestation-Based Client Authentication 組み立てを再エクスポートする。
 * 取得と現行 WUA の保持は Wallet ファサード（`wallet/eudi/facade.ts` の `EudiFacade`）が
 * `obtainWalletAttestation` / `getWalletAttestation` として配線済みで、`wallet.ts` の `WalletImpl`
 * がそこへ素通し委譲する。
 */

export {
  type ObtainWalletAttestationOptions,
  obtainWalletUnitAttestation,
} from './obtain.js';
export {
  buildClientAttestation,
  buildWuaProofOfPossession,
} from './proof.js';
export {
  type ClientAttestation,
  type WalletUnitAttestation,
  WUA_CLIENT_ASSERTION_TYPE,
  WUA_VCT,
  type WuaClaims,
  type WuaConfirmation,
  type WuaPopClaims,
  type WuaPopOptions,
} from './types.js';
export {
  isWalletAttestationExpired,
  parseWalletUnitAttestation,
  refreshWalletAttestation,
  verifyWalletUnitAttestation,
  verifyWscdBinding,
} from './wua.js';
