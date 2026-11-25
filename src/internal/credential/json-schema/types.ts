/**
 * JSON Schema（Draft 2020-12 サブセット）検証の共有型。
 *
 * W3C VC の `credentialSchema` と SD-JWT VC の Type Metadata で共有する検証結果の形式。
 * 各経路が対象のクレームを取り出し、JSON Schema 検証器へ渡す。
 */

/** JSON Schema 文書（未検証の生 JSON）。 */
export type JsonSchema = Readonly<Record<string, unknown>>;

/**
 * 検証違反 1 件。
 *
 * `path` の形式は経路によって違う（`path` の JSDoc 参照。JSON Schema 経路は JSON Pointer、
 * PID Rulebook 経路は属性名そのもの）。`message` は秘密を含まない静的な日本語で、
 * **インスタンスの値を埋め込まない**。VC のクレーム値には PII が含まれ得る。
 */
export interface SchemaError {
  /**
   * 違反箇所。**経路によって形式が違う**。
   *
   * - JSON Schema 経路（`credential-schema/validate.ts` / `sdjwt/type-metadata/resolve.ts`）は
   *   JSON Pointer（RFC 6901）。ただし検証対象の instance は `vc.credentialSubject` 自体、または
   *   SD-JWT の claims なので、**ルート直下は `/name` の形**になる。ルート自体の違反は空文字列。
   * - PID Rulebook 経路（`eudi/pid/schema.ts`。本 interface を再エクスポートして使う）は
   *   **属性名そのもの**（`family_name` / `vct` 等）で JSON Pointer ではない。
   */
  readonly path: string;
  /** 違反内容（値を含まない静的メッセージ）。 */
  readonly message: string;
  /**
   * 必須属性に対する違反かどうか。
   *
   * FO-4（`credentialSchema` の**任意**属性バリデーション違反 = 警告通過）と
   * 必須属性違反（3002 で fail-closed）を呼び出し側が区別できるようにするための分類。
   *
   * `true`（必須違反 = FO-4 の対象外）になるのは次のいずれか:
   *
   * - `required` キーワードの違反（列挙されたプロパティの欠落）。
   * - `required` に列挙されたプロパティ配下の違反。
   * - **ルート（`path` が空文字列）の違反**。インスタンス全体の構造がスキーマと矛盾している。
   * - **論理結合キーワード（`anyOf` / `oneOf` / `not`）の失敗**。「いずれかを満たすこと」自体が
   *   構造制約であり、任意属性の型違反とは意味が異なる。
   * - 深さ上限・評価量上限による打ち切り（DoS 対策の打ち切りを fail-open にしない）。
   *
   * `false`（任意違反 = FO-4 で警告通過）になるのは、`required` に列挙されていない任意プロパティ
   * 配下の型・形式違反だけである。
   */
  readonly required: boolean;
}

/** 検証結果。 */
export interface SchemaValidationResult {
  /** 違反が 1 件も無ければ `true`。 */
  readonly valid: boolean;
  /** 違反の一覧（`valid` が `true` のときは省略する）。 */
  readonly errors?: readonly SchemaError[];
}

/**
 * fail-safe（fail-open）を前提としたスキーマ検証結果。
 *
 * W3C VC の `credentialSchema` と SD-JWT VC の Type Metadata で共有する。
 * 取得失敗（FO-3）を警告付きで許可した場合、`schemaAvailable: false` と警告キー
 * `schema_fetch_failed` を返す。任意属性の違反（FO-4）を許可した場合の警告キーは
 * `schema_optional_invalid`。必須属性の違反は `errors` の `required: true` で報告する。
 * この型は `validateClaimsAgainstCredentialSchema` と `validateClaimsAgainstTypeMetadata` が返す。
 * `validateCredentialSchema` は {@link SchemaValidationResult} を返す。
 */
export interface SchemaFailSafeResult {
  /** スキーマに適合したか。スキーマが存在しない / 取得できない場合は `true`（検証していない）。 */
  readonly valid: boolean;
  /** 検証に用いるスキーマを取得できたか。`false` なら `valid` は検証結果ではない。 */
  readonly schemaAvailable: boolean;
  /** 違反の一覧（`valid` が `false` のときのみ）。 */
  readonly errors?: readonly SchemaError[];
  /** fail-open で通過させた事象の監査キー。 */
  readonly warnings: readonly string[];
}
