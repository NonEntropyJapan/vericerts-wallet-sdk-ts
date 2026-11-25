/**
 * wallet の eudi サブモジュールの公開エントリ（sub-barrel）。
 *
 * EUDI PID / (Q)EAA API のファサード API 型（`api.ts`）と、`WalletImpl` が委譲する
 * 実装（`facade.ts`）を再エクスポートする。
 *
 * - api.ts:      ファサード API 型（`EudiApi`）。
 * - facade.ts:   `WalletImpl` が委譲する実装（`EudiFacade`）。
 * - rp-trust.ts: `rpTrustAnchors` から提示経路の JAR 検証材料への写像。
 * - wua-holder.ts: WUA の取得・検証・有効性判定。
 */

export type { EudiApi } from './api.js';
export { EudiFacade } from './facade.js';
