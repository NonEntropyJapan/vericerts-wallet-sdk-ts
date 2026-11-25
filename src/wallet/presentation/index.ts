/**
 * wallet の presentation サブモジュールの内部専用エントリ。
 *
 * VP に内包された VC の検証結果を提示へ紐付ける処理（`embedded-credentials.ts`）を
 * 再エクスポートするが、`wallet/index.ts`（公開バレル）からは re-export しない。
 * 利用者は `credential/verify-result.ts`（`attachCredentialResults`）と
 * `credential/presentation-envelope.ts`（型 `PresentationBinding`）で、いずれも
 * `../presentation/index.js` を直接 import する内部利用に留まる。`credential/ops.ts` は
 * JWT-VP の検証を持たないため利用者ではない。
 */

export { attachCredentialResults, type PresentationBinding } from './embedded-credentials.js';
