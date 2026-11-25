/**
 * スキーマ検証経路の自動判定（ディスパッチャ）の内部バレル。
 *
 * `vc/credential-schema/` と `sdjwt/type-metadata/` の両方に依存するため、どちらの配下にも置かず
 * 独立ディレクトリとする（依存の逆流を避けるため）。
 *
 * - types.ts:     経路の列挙・入力の union 型・オプション型・`route` 付き結果型。
 * - dispatch.ts:  形式判定（`Object.hasOwn` ベース）と、選ばれた経路への委譲・結果の合成。
 * - fail-safe.ts: 両経路が共有する FO-3 / FO-4 の適用（`internal/failsafe-policy/` の正準判定を利用）。
 *   ディスパッチャ専用ではなく**両経路から import される**ため、バレルからは再公開しない
 *   （経路実装 → `fail-safe.ts` の一方向依存を保つ）。
 * - factory.ts:   Fail-open ウィンドウをインスタンスへ閉じ込める `createSchemaValidator`
 *   （`internal/issuer/status-list-resolver.ts` の `createStatusListResolver` と同じパターン）。
 */

export {
  detectSchemaValidationRoute,
  validateClaimsAgainstSchema,
} from './dispatch.js';
export {
  type CreateSchemaValidatorOptions,
  createSchemaValidator,
  type SchemaValidator,
} from './factory.js';
export type {
  RoutedSchemaValidationOptions,
  RoutedSchemaValidationResult,
  SchemaValidatableCredential,
  SchemaValidationRoute,
  SharedSchemaValidationOptions,
} from './types.js';
