/**
 * eudi/presentation モジュールの公開エントリ。
 *
 * `presentPID` / `presentEAA` は VP Token を構成し、Verifier に提示する。
 *
 * OID4VP で PID / (Q)EAA を選択的開示して提示する内部フローを再エクスポートする。
 * 本モジュールは内部プリミティブで、Wallet facade（`presentPID` / `presentEAA`）への配線は
 * `wallet/eudi/facade.ts` が担う。`PresentOptions` は `presentPID` の引数型として利用者に
 * 必要なため `exports/eudi.ts` から公開している。
 *
 * `eudi/pid` が受領済み PID / (Q)EAA の型定義・スキーマ検証・Catalogue 参照だけを担い、提示の
 * 手続き（要求解析・選択的開示・Key Binding・送信）を持たないため、その手続きをここに分ける。
 *
 * - present.ts:         要求解析 → VP Token 構成 → 送信 → 提示記録の生成。
 * - request-options.ts: `PresentDeps` から提示要求パースのオプションへの写像。
 * - types.ts:           依存・オプションの型（`PresentDeps` / `PresentOptions`）。
 *
 * 提示要求は `parsePresentationRequest`（`auth/jar/`）で解くため、`request_uri` 参照形式（JAR）
 * も直接形式と同じ 1 本で扱える（HAIP §5.1 必須）。参照形式は JAR の署名検証を
 * 必ず経由し、Trust Anchor は `PresentDeps.jarTrust` から受け取る。
 */

export { presentEAACredential, presentPIDCredential } from './present.js';
export type { PresentDeps, PresentOptions } from './types.js';
