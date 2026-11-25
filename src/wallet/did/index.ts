/**
 * wallet の did サブモジュールの公開エントリ（sub-barrel）。
 *
 * DID / controller のファサード API 型（`api.ts`）と、`WalletImpl` が委譲する実装（`facade.ts`）を
 * 再エクスポートする。
 */

export type { DidApi } from './api.js';
export { DidFacade } from './facade.js';
