/**
 * 「配列を除く非 null オブジェクトか」を判定するヘルパー `isPlainObject` の SSOT。
 *
 * `wallet/did/facade.ts`（`ownObject` 内でインライン） / `presentation-exchange/evaluate.ts`
 * （`matchesType` の `'object'` ケース） / `presentation-exchange/definition.ts` /
 * `credential/json-schema/object-properties.ts`（`toSchemaMap`） /
 * `credential/manifest/parse.ts`（`export function isPlainObject`） /
 * `credential/sdjwt/claims.ts`（`isObject` という名だが本体は同一） /
 * `credential/schema-validation/dispatch.ts`（`isRecord`） /
 * `credential/evidence-tou/evidence.ts`（`isRecord`） /
 * `credential/evidence-tou/odrl.ts`（`export function isRecord`） /
 * `wallet-migration/backup-serialize.ts`（`isPlainObject`）の 10 箇所に、
 * `typeof value === 'object' && value !== null && !Array.isArray(value)` という同一ロジックが
 * 重複実装されていたため、ここへ集約した（`hex-codec.ts` / `asset/bytes.ts`）。
 *
 * `manifest/parse.ts` の `export function isPlainObject` と `evidence-tou/odrl.ts` の
 * `export function isRecord` は、それぞれの公開 API を re-export で維持する。
 *
 * `src/internal/` 直下ではなく `credential/` に置くのは、`asset/bytes.ts` と同じ理由
 * （`.linterly.yml` の `max_lines_per_directory` を `src/internal/` 直下がすでに
 * warning_threshold 間際まで消費しているため、新規ファイル追加で誤って error 化させないための
 * 配置）。重複実装の過半数（10 箇所中 6 箇所）が `credential/` 配下のため、ここを再利用する
 * （依存ゼロの純粋関数のため、`wallet/did/facade.ts` や `wallet-migration/` など他ドメインからの
 * cross-import も `asset/bytes.ts` と同様に問題ない）。
 *
 * 配列を除外しない簡易版（`auth/jar/jar-trust-arf.ts` / `auth/jar/jar-trust-evaluation.ts` /
 * `trust/arf/catalogue.ts` の `isObject`）は用途（`ownProperty` へ渡せるかの判定のみで、配列を
 * 弾く必要がない）が異なる意図的な別物のため、ここへは統合しない
 * （`trust/arf/catalogue.ts` の `isObject` を SSOT とする）。
 */

/** 値が配列を除く非 null オブジェクトか。 */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
