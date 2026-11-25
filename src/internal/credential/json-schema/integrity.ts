/**
 * 参照先文書のハッシュ固定（Subresource Integrity）宣言の扱い。共通ヘルパ。
 *
 * W3C VC の `credentialSchema.digestSRI` と、SD-JWT VC の `vct#integrity` /
 * `extends#integrity` / `schema_uri#integrity` を扱う。
 *
 * Issuer が参照先文書のハッシュを宣言するのは、スキーマ / メタデータのホスト乗っ取りによる**差し替え**を
 * 防ぐためである。本 SDK は取得文書の生バイト列に対する SRI / multibase ダイジェストの照合を実装していない
 * （取得層は検証済みのパース後 JSON しか返さず、キャッシュも URL だけをキーにする）。宣言を黙って捨てると、
 * ホストを乗っ取った攻撃者の全許可スキーマで `valid: true` になる。完全性の失敗は Fail-closed が原則で、
 * Fail-open 許容事象（FO-3 / FO-4）にも当たらないため、**宣言があれば取得より前に 3061 で拒否する**。
 * SD-JWT VC 経路と W3C VC 経路で、エラーコード（`3061`）と理由（`reason: "integrity_unverifiable"`）を揃える。
 * 照合を実装したらこの拒否は不要になる。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';

/** `3061` の `context.reason`（検証できない完全性宣言）。 */
export const INTEGRITY_UNVERIFIABLE_REASON = 'integrity_unverifiable';

/** SD-JWT VC のクレーム（検証済みの復元クレーム）に現れる完全性宣言のキー。 */
export const SD_JWT_VC_INTEGRITY_KEYS: readonly string[] = ['vct#integrity'];

/** SD-JWT VC の Type Metadata 文書に現れる完全性宣言のキー。 */
export const TYPE_METADATA_INTEGRITY_KEYS: readonly string[] = [
  'extends#integrity',
  'schema_uri#integrity',
];

/** W3C VC の `credentialSchema` 参照要素に現れる完全性宣言のキー（VC JSON Schema の `digestSRI`、VCDM 2.0 の `digestMultibase`）。 */
export const CREDENTIAL_SCHEMA_INTEGRITY_KEYS: readonly string[] = ['digestSRI', 'digestMultibase'];

/** 比較対象のキーの最大長。これより長いキーは宣言ではないので小文字化せず読み飛ばす。 */
const MAX_DECLARATION_KEY_LENGTH = 32;

/**
 * `holder` が完全性宣言のキー `keys` を**1 つでも持つか**。
 *
 * 宣言の有無は**キーの存在だけ**で判定する。値は読まない — 文字列でない値・`null`・空文字列・空配列・
 * `undefined` でも、宣言があるものとして扱う（値の形で通すと、不正な宣言を黙って捨てる迂回になる）。
 * キーは大文字小文字を区別せず（`digestsri` / `DIGESTSRI` も宣言とみなす）、列挙可能かに関わらず
 * **own** のキーだけを見る（継承値は読まない。`Object.prototype` の汚染で拒否が起きたり外れたりしない）。
 */
function declaresIntegrity(holder: unknown, keys: readonly string[]): boolean {
  if (typeof holder !== 'object' || holder === null) {
    return false;
  }
  const declared = keys.map((key) => key.toLowerCase());
  for (const key of Object.getOwnPropertyNames(holder)) {
    if (key.length <= MAX_DECLARATION_KEY_LENGTH && declared.includes(key.toLowerCase())) {
      return true;
    }
  }
  return false;
}

/**
 * `holder` が完全性宣言を持つなら 3061（`integrity_unverifiable`）で拒否する。
 *
 * @throws `holder` が `keys` のいずれかを own プロパティとして持つ場合（VericertsError、code `3061`）。
 */
export function assertNoUnverifiableIntegrity(holder: unknown, keys: readonly string[]): void {
  if (declaresIntegrity(holder, keys)) {
    throw new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
      context: { reason: INTEGRITY_UNVERIFIABLE_REASON },
    });
  }
}
