/**
 * wallet の status サブモジュールの公開エントリ（sub-barrel）。
 *
 * Status List Resolver 生成 API の型（`api.ts`）と、`WalletImpl` が委譲する実装（`facade.ts`）を
 * 再エクスポートする。
 */

export type { CreateStatusListResolverOptions, StatusApi } from './api.js';
export { StatusFacade } from './facade.js';
