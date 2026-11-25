/**
 * SD-JWT VC 発行時の GDPR Art.9 特別カテゴリ属性ガード。
 *
 * SD-JWT VC の発行経路（`createSdJwt` / `createSdJwtAsync`、および `Wallet.issueSdJwt`）は
 * JWT-VC の署名プリミティブ（`vc/issue.ts`）を通らないため、本モジュールが同等の関門を担う。
 * ガードは `buildSdJwtIssuanceParts` の末尾（署名前）で呼ぶため、拒否時に署名鍵は使われない
 * （fail-closed）。送出コードは JWT-VC 側と同じ `10607 GDPR_SPECIAL_CATEGORY_ISSUANCE` を再利用する。
 *
 * ## 走査対象を「payload + 復元した Disclosure」にする理由
 *
 * 1. **payload だけでは足りない。** `disclosureClaims` に指定されたクレームは Disclosure 側へ回り、
 *    payload には `_sd` の digest しか残らない。payload だけを走査すると、まさに隠したい
 *    Art.9 属性（`health` を選択的開示にした発行など）を取り逃す。
 * 2. **Disclosure のエンコード済み文字列をそのまま渡しても検知できない。** Disclosure の実体は
 *    `[salt, claimName, value]` の **JSON 配列**であり、`claimName` は「配列要素の値」の位置に来る。
 *    `findSpecialCategoryAttributes` は配列の添字を属性名として扱わない設計（誤検知回避）なので、
 *    配列表現のままでは属性名として評価されない。そのためデコードして
 *    `{ [claimName]: value }` 形の単一キーオブジェクトへ詰め直し、属性名の位置に戻してから渡す。
 *
 * ## 「走査した値 = 署名・送出されるバイト列」であること
 *
 * payload は呼び出し側が **一度だけ**直列化した文字列を受け取り、その文字列を解析した値を走査する
 * （同じ文字列がそのまま base64url されて署名対象になる）。Disclosure も同様に、`~` 連結されて
 * 送出される **エンコード済み文字列そのもの**から復元する。いずれも「検査してから作り直す」のでは
 * なく「送出される表現から復元して検査する」ため、検査後に内容がずれる余地がない。
 *
 * セキュリティ上の注意:
 * - 例外に属性名・クレーム値・JWT 本文を載せない。既存ガードがコードのみを
 *   返す設計なのでそれに従う。
 */

import { defineDataProperty } from '../../prototype-safety/define-data-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { assertNoSpecialCategoryInIssuedContent } from '../../special-category.js';
import { decodeDisclosure } from './disclosure.js';

/**
 * SD-JWT VC の発行内容（平文 payload + Disclosure）に Art.9 特別カテゴリ属性が無いことを表明する。
 *
 * @param payloadJson Issuer-signed JWT の payload を JSON 直列化した文字列（署名対象そのもの）。
 * @param encodedDisclosures 同梱する Disclosure の base64url 文字列（送出される表現そのもの）。
 * @throws 禁止属性を含む場合（VericertsError、code `10607`）。
 */
export function assertNoSpecialCategoryInSdJwtIssuance(
  payloadJson: string,
  encodedDisclosures: readonly string[],
): void {
  // Disclosure ごとに別オブジェクトを作る（同名クレームの衝突で片方が消えるのを避けるため）。
  // `obj[claimName] = value` は `claimName` が `__proto__` のとき own プロパティを作らず
  // プロトタイプを差し替えるため、走査器（own プロパティを列挙する）から素通りする。
  // `defineDataProperty`（`Object.defineProperty` を記述子ごと `null` プロトタイプで包むヘルパー）
  // なら `__proto__` でも通常の own データプロパティになる（`sdjwt.ts` の
  // 平文クレーム組み立てと同じ理由 —）。
  const disclosureObjects = encodedDisclosures.map((encoded) => {
    const { claimName, value } = decodeDisclosure(encoded);
    // 配列要素の Disclosure（`claimName` なし）は値そのものを走査対象にする。
    if (claimName === undefined) {
      return value;
    }
    const holder: Record<string, unknown> = {};
    defineDataProperty(holder, claimName, value);
    return holder;
  });
  // 配列でまとめて渡してよいのは、走査器が配列の添字を属性名として扱わないためである。
  assertNoSpecialCategoryInIssuedContent([
    parseJsonWithoutPrototype(payloadJson),
    ...disclosureObjects,
  ]);
}
