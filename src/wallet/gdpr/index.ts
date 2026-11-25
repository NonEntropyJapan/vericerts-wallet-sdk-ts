/**
 * wallet の gdpr サブモジュールの公開エントリ（sub-barrel）。
 *
 * GDPR Compliance API のファサード API 型（`api.ts`）と、`WalletImpl` が委譲する
 * 実装（`facade.ts`）を再エクスポートする。
 */

export type { GdprApi } from './api.js';
export { GdprFacade } from './facade.js';
