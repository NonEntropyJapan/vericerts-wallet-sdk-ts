/**
 * VC JSON Schema 検証（`validateCredentialSchema` / `validateClaimsAgainstCredentialSchema`）。
 *
 * 準拠規格: [W3C Verifiable Credentials JSON Schema](https://www.w3.org/TR/vc-json-schema/)。
 *
 * `credentialSchema`（または明示引数）が指す JSON Schema を HTTPS で取得し、
 * **`credentialSubject`** を検証する（VC 全体ではない。スキーマはクレーム構造を定義するため）。
 *
 * `validateCredentialSchema` はスキーマを解決できない場合に 3016、取得できない場合に 3015 を投げる。
 * `validateClaimsAgainstCredentialSchema` は取得失敗（FO-3）と任意属性の違反（FO-4）について
 * 同意・監査記録・`failSafePolicy.escalate` の設定に従って判定する。
 * Type Metadata 経路の `validateClaimsAgainstTypeMetadata` と同じ `SchemaFailSafeResult` を返す。
 *
 * セキュリティ上の注意:
 * - スキーマ URL は Issuer 由来 = 攻撃者が影響し得る値。取得は共有プリミティブ
 *   （`json-schema/fetch-document.ts`）に委譲し、HTTPS 限定・リダイレクト後も HTTPS・
 *   JSON Content-Type 必須・10 秒タイムアウト・本文 1 MiB 上限を課す。
 * - スキーマ内の**リモート `$ref` は解決しない**（違反として報告する）。スキーマ検証中に
 *   任意 URL への副次的な取得を発生させないため（SSRF 防止）。
 * - 例外メッセージ・`context`・`cause` に URL・`credentialSubject` の値を含めない。
 * - VC からの `credentialSchema` / `credentialSubject` の読み取りは `ownProperty` で **own 限定**に
 *   する。鎖経由で読むと、`credentialSchema` を持たない VC でも `Object.prototype` の
 *   汚染値を「VC が指定したスキーマ参照」として採用し、攻撃者の URL からスキーマを取得して
 *   しまう（`credentialSubject` も同様に汚染値を検証対象クレームにしてしまう）。
 *
 * 本経路は SD-JWT VC の Type Metadata 経路とは**別エコシステム**であり、
 * `vct` と `credentialSchema` の claim を混同しない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { FailSafePolicy } from '../../../failsafe-policy/index.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../../prototype-safety/own-property.js';
import type {
  JsonSchema,
  SchemaFailSafeResult,
  SchemaValidationResult,
} from '../../json-schema/index.js';
import {
  assertNoUnverifiableIntegrity,
  CREDENTIAL_SCHEMA_INTEGRITY_KEYS,
  fetchSchemaJson,
  validateAgainstSchema,
} from '../../json-schema/index.js';
import {
  applySchemaViolations,
  clearFailOpenWindow,
  credentialFingerprint,
  isFailClosed,
  schemaFetchFailedResult,
} from '../../schema-validation/fail-safe.js';
import type { CredentialSchemaReference, VerifiableCredential } from '../vc.js';
import { CredentialSchemaCache } from './cache.js';
import type { ValidateCredentialSchemaOptions } from './types.js';
import { JSON_SCHEMA_CREDENTIAL_TYPES } from './types.js';

/** モジュール既定の共有キャッシュ（同一 VC 種別は同じスキーマ URL を繰り返し引くため有効）。 */
const defaultSchemaCache = new CredentialSchemaCache();

/** `credentialSchema` を配列に正規化する（W3C VC Data Model は object | object[] を許容）。 */
function toReferences(
  value: CredentialSchemaReference | readonly CredentialSchemaReference[] | undefined,
): readonly CredentialSchemaReference[] {
  if (value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value : [value as CredentialSchemaReference];
}

/**
 * 検証に使うスキーマ URL を決める。
 *
 * 明示引数 `schema` が最優先。未指定なら `credentialSchema` のうち `type` が JSON Schema 系
 * （{@link JSON_SCHEMA_CREDENTIAL_TYPES}）の**最初の**エントリの `id` を使う。JSON Schema 系の
 * エントリが 1 件も無い場合は「検証できるスキーマが指定されていない」として 3016 とする
 * （未対応の `JsonSchemaCredential` だけを持つ VC もここに落ちる）。
 *
 * `credentialSchema` は own 限定で **1 度だけ**読む。`vc.credentialSchema` と鎖経由で
 * 読むと、宣言していない VC でも `Object.prototype` の汚染値を採用してしまう。
 *
 * @throws URL を解決できない場合（VericertsError、code `3016`）。
 */
export function resolveSchemaUrl(vc: VerifiableCredential, schema?: string): string {
  if (schema !== undefined && schema.length > 0) {
    return schema;
  }
  const credentialSchema = ownProperty<
    CredentialSchemaReference | readonly CredentialSchemaReference[]
  >(vc, 'credentialSchema');
  for (const reference of toReferences(credentialSchema)) {
    if (typeof reference !== 'object' || reference === null) {
      continue;
    }
    // 参照の `id` / `type` も own 限定で読む。`id` を省略した参照が `Object.prototype.id` の汚染値を拾うと、
    // 攻撃者の URL からスキーマを取得し、その全許可スキーマで検証が通る。
    const id = ownProperty<unknown>(reference, 'id');
    const type = ownProperty<unknown>(reference, 'type');
    if (
      typeof id === 'string' &&
      id.length > 0 &&
      typeof type === 'string' &&
      JSON_SCHEMA_CREDENTIAL_TYPES.has(type)
    ) {
      return id;
    }
  }
  throw new VericertsError(ErrorCodes.SCHEMA_NOT_SPECIFIED);
}

/**
 * `credentialSchema` の JSON Schema 系の参照が `digestSRI`（`digestMultibase`）を宣言していれば、取得より前に
 * `3061`（`integrity_unverifiable`）で拒否する。
 *
 * `digestSRI` は Issuer が**スキーマ文書のハッシュを固定**してホスト乗っ取りによる差し替えを防ぐ宣言だが、
 * SDK は取得文書の生バイト列に対するダイジェストを照合しない。宣言を黙って捨てると、差し替えた全許可スキーマで
 * `valid: true` になる。SD-JWT VC の `vct#integrity`と同じ理由・方針・エラーコードで、共通ヘルパ
 * （`json-schema/integrity.ts`）を使う。完全性の失敗は FO-3 / FO-4 の対象外で、
 * fail-open 設定でも通さない。明示引数 `schema` を使う場合も、VC が宣言した固定を黙って捨てないため対象にする。
 * 読み取りは own 限定。
 */
function assertNoUnverifiableSchemaIntegrity(vc: VerifiableCredential): void {
  const credentialSchema = ownProperty<
    CredentialSchemaReference | readonly CredentialSchemaReference[]
  >(vc, 'credentialSchema');
  for (const reference of toReferences(credentialSchema)) {
    if (typeof reference !== 'object' || reference === null) {
      continue;
    }
    const type = ownProperty<unknown>(reference, 'type');
    if (typeof type === 'string' && JSON_SCHEMA_CREDENTIAL_TYPES.has(type)) {
      assertNoUnverifiableIntegrity(reference, CREDENTIAL_SCHEMA_INTEGRITY_KEYS);
    }
  }
}

/** キャッシュ経由でスキーマ文書を取得する。 */
async function loadSchemaDocument(
  url: string,
  options: ValidateCredentialSchemaOptions,
  now: number,
): Promise<JsonSchema> {
  // `schemaCache` は関数値 / クラスインスタンス DI のため `ownProperty` は使えない。`Object.prototype`
  // 由来の汚染値だけを除外する（鎖読みだと汚染した get() が空スキーマを返して検証を素通りする）。
  const cache =
    nonObjectPrototypeProperty<CredentialSchemaCache>(options, 'schemaCache') ?? defaultSchemaCache;
  const cached = cache.get(url, now);
  if (cached !== undefined) {
    return cached;
  }
  const document = await fetchSchemaJson(url, ErrorCodes.SCHEMA_FETCH_FAILED, options);
  cache.set(url, document, now);
  return document;
}

/**
 * VC の `credentialSubject` を VC JSON Schema で検証する。
 *
 * @param vc 検証対象の VC。
 * @param schema JSON Schema の URL。省略時は `vc.credentialSchema` から解決する。
 * @param options `fetchImpl` / キャッシュ / 現在時刻の注入。
 * @returns 検証結果（違反があれば `errors` に JSON Pointer と必須属性フラグを含む）。
 * @throws スキーマ URL を解決できない場合（`3016`）、スキーマ文書の取得に失敗した場合（`3015`）、
 *         `credentialSchema` が `digestSRI` を宣言している場合（`3061`）。
 */
export async function validateCredentialSchema(
  vc: VerifiableCredential,
  schema?: string,
  options: ValidateCredentialSchemaOptions = {},
): Promise<SchemaValidationResult> {
  assertNoUnverifiableSchemaIntegrity(vc);
  const url = resolveSchemaUrl(vc, schema);
  // 検証対象クレームも own 限定で読む。鎖経由だと `credentialSubject` を持たない VC で
  // `Object.prototype` の汚染値をクレームとして検証してしまう。
  const credentialSubject = ownProperty(vc, 'credentialSubject');
  const now = ownProperty<number>(options, 'nowMs') ?? Date.now();
  const document = await loadSchemaDocument(url, options, now);
  return validateAgainstSchema(document, credentialSubject);
}

/**
 * VC の `credentialSubject` を VC JSON Schema で検証する（fail-open 版）。
 *
 * スキーマ参照がないときや取得失敗・属性の違反があるときは、以下の条件で結果を返す。
 *
 * - `credentialSchema` が宣言されていない / JSON Schema 系でない（3016）= 検証対象なしとして
 *   `schemaAvailable: false`（警告なし）。Type Metadata 経路で `vct` が URL でない場合に検証を
 *   スキップするのと同じ扱いで、Fail-open を適用しないため同意・監査記録も要らない。
 * - スキーマ文書の取得失敗（3015）= **FO-3**。fail-open ゲートが許可すれば `valid: true` +
 *   FO-3 の監査キーで警告通過し、許可しなければ 3015 をそのまま伝播する。
 * - `credentialSchema` が `digestSRI`（ハッシュ固定）を宣言している = 検証できないため、FO-3 / FO-4 の対象外として
 *   常に `3061` で拒否する（SD-JWT VC の `vct#integrity` と同じ扱い）。
 * - 検証まで到達した違反 = **FO-4**。任意属性のみの違反でゲートが許可すれば `valid: true` +
 *   FO-4 の監査キー（違反内容は `errors` に残す）、許可しなければ `valid: false`。必須属性違反が
 *   1 件でもあれば FO-4 の対象外として常に `valid: false`（警告なし）。
 *
 * **FO-3 / FO-4 の警告通過には同意コールバック（`requestConsent`）と監査記録先（`onPolicyEvent`）の
 * 双方が要る**。いずれかの未設定・不同意・監査記録の失敗、または同一 URL での 60 秒の上限超過時は
 * Fail-closed に倒れる。`escalate: ['FO-3']` を指定するとスキーマを解決 /
 * 取得できない事象（3015 / 3016）を例外として、`escalate: ['FO-4']` を指定すると任意属性のみの
 * 違反を `valid: false` として扱う。
 *
 * @param vc 検証対象の VC。スキーマ URL は `vc.credentialSchema` から解決する。
 * @param options `fetchImpl` / キャッシュ / 現在時刻 / fail-safe override・同意・監査記録先の注入。
 * @returns 検証結果（適合可否・スキーマ取得可否・違反・監査キー）。
 * @throws `digestSRI` を宣言している場合（`3061`）。スキーマを解決できず `escalate: ['FO-3']` を指定した場合（`3016`）。スキーマを取得できず
 *         fail-open ゲートが通過を許さなかった場合（`3015`）。
 */
export async function validateClaimsAgainstCredentialSchema(
  vc: VerifiableCredential,
  options: ValidateCredentialSchemaOptions = {},
): Promise<SchemaFailSafeResult> {
  // ハッシュ固定の宣言は検証できないため、FO-3 / FO-4 の対象外として常に 3061 で拒否する。
  assertNoUnverifiableSchemaIntegrity(vc);
  // own 限定で読む。鎖経由だと `Object.prototype` の汚染値を
  // 固定の `nowMs` として採用してしまい、`now - start` が常に一定値になって FO-3/FO-4 の
  // 60 秒上限が恒久的に無効化される（fail-open が無期限に継続する）。
  const now = ownProperty<number>(options, 'nowMs') ?? Date.now();
  // fail-open の時間上限はエポック秒で数える（`FailOpenWindow` の契約）。
  const nowSeconds = Math.floor(now / 1000);
  // 検証対象クレームも own 限定で読む（`validateCredentialSchema` と同じ理由）。
  const credentialSubject = ownProperty(vc, 'credentialSubject');

  // 「スキーマ URL を解決できない（3016）」と「解決できた URL の取得に失敗した（3015）」は
  // 別事象なので catch も分ける。前者は Fail-open 許容事象ではなく、後者だけが FO-3 である。
  let url: string;
  try {
    url = resolveSchemaUrl(vc);
  } catch (e) {
    if (!(e instanceof VericertsError && e.code === ErrorCodes.SCHEMA_NOT_SPECIFIED)) {
      throw e;
    }
    // 検証できるスキーマの指定が無い = 構造制約なし（検証していない）。事象ではないため
    // fail-open ゲート（同意 + 監査記録）は通さず、警告も出さない。ただし「スキーマで検証できて
    // いない」点は FO-3 と同じなので、`escalate: ['FO-3']` の格上げ指定にだけは従う。
    // override は own 限定で読む（継承値を拾うと格上げ指定が無効化される）。
    if (isFailClosed('FO-3', ownProperty<FailSafePolicy>(options, 'failSafePolicy'))) {
      throw e;
    }
    return { valid: true, schemaAvailable: false, warnings: [] };
  }

  // Fail-open ウィンドウのキーは経路プレフィックスを付けて資源単位で管理する。
  // SD-JWT VC の Type Metadata 経路も `vct`（HTTPS URL）を資源キーに使うため、
  // プレフィックス無しだと両経路のスキーマ URL が同じ文字列空間で衝突しうる。
  const resourceKey = `w3c:${url}`;

  let document: JsonSchema;
  try {
    document = await loadSchemaDocument(url, options, now);
  } catch (e) {
    // FO-3: スキーマ取得失敗は、同意・監査記録・時間上限を満たしたときだけ警告通過。
    // 資源(スキーマ URL)そのものの到達性なので、クレデンシャル単位ではなく資源単位で計時する。
    if (e instanceof VericertsError && e.code === ErrorCodes.SCHEMA_FETCH_FAILED) {
      const gated = await schemaFetchFailedResult(resourceKey, nowSeconds, options);
      if (gated !== undefined) {
        return gated;
      }
    }
    throw e;
  }

  // 資源（スキーマ URL）の取得に成功した時点で FO-3 の資源キーを破棄する。適合性の検証はその後で行う。
  // `applySchemaViolations` の成功パスは FO-4 の `violationKey` しか破棄しないため、
  // ここで別途 FO-3 の `resourceKey` を破棄しないと、一度取得に成功しても FO-3 側の計時が
  // 巻き戻らず、資源単位の 60 秒予算が古い開始時刻のまま残り続けてしまう。
  clearFailOpenWindow(resourceKey, options);

  // FO-4（任意属性のみの違反 = 警告通過）の適用は Type Metadata 経路と共有する。時間上限は
  // 資源キーに検証対象クレームの指紋を連結してクレデンシャル単位で管理する（
  // 是正）。資源単位のみだと、同じスキーマを参照する無関係な別クレデンシャルの成功で本クレデンシャル
  // の違反予算がリセットされてしまうため。
  const violationKey = `${resourceKey}#${credentialFingerprint(credentialSubject)}`;
  return await applySchemaViolations(
    violationKey,
    nowSeconds,
    validateAgainstSchema(document, credentialSubject),
    options,
  );
}
