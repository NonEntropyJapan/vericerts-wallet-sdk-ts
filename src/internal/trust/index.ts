/**
 * trust ドメインの公開エントリ（内部バレル）。
 *
 * EUDI Wallet 認定レディの Trust Framework を担うモジュール群。OpenID Federation
 * （`federation/`）・ETSI Trusted List（`etsi-tsl/`）・ARF Trust Anchor（`arf/`）を提供
 * する。3 層統合信頼判定（evaluateTrust）への配線は後続スコープの責務とする。
 * etsi-tsl / arf は `exports/trust.ts` からサブパスを直接 re-export するため、本バレルでは federation
 * のみを束ねる。
 */

export * from './federation/index.js';
