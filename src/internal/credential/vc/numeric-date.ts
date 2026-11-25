/**
 * ISO 8601 文字列と JWT-VC の NumericDate（エポック秒）の相互変換。
 *
 * 発行（`issue.ts`）と検証（`verify.ts`）の双方が NumericDate 変換を共有することで、
 * envelope↔body の自己整合検証で発行と完全対称な比較を可能にする。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に VC 本文（日付文字列）を含めない。
 */

import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import { ErrorCodes, VericertsError } from '../../errors.js';

/**
 * ISO 8601 文字列を NumericDate（エポック秒）へ変換する。
 *
 * 不正な ISO / 解釈不能な文字列（`Date.parse` が `NaN`）は `Math.floor(NaN / 1000) = NaN` となり、
 * JSON 直列化で `null` に倒れて発行時にはエラーにならず、検証時に 3020 で誤って表面化する
 * （fail-open）。これを避けるため、変換前に妥当性を検証し、不正なら構造不正（3002）として拒否する。
 *
 * **引数の型は実行時には保証されない。** 呼び出し側は非信頼な VC 本文から
 * `ownProperty<string>(vc, 'expirationDate')` のように **cast だけ**で値を取り出しており、
 * `{}` のようなオブジェクトが届き得る。パース境界（`parseJsonWithoutPrototype`）を通った値は
 * `Object.prototype` を継承せず `toString` / `valueOf` を持たないため、`Date.parse` に渡すと
 * 暗黙の `ToPrimitive` が `TypeError: No default value` を送出し、本関数の 3002 の失敗面ごと
 * 迂回して生の例外が呼び出し側の公開 API から漏れる。したがって文字列でない値は
 * 「解釈不能な ISO」と**同じ 3002** へ倒す（`"not-a-date"` を渡した場合と挙動を揃える）。
 *
 * @throws ISO 文字列が解釈不能、または文字列でない場合（VericertsError、code `3002`）。
 */
export function isoToNumericDate(iso: string): number {
  const ms = parseIsoDateTimeMs(iso);
  if (!Number.isFinite(ms)) {
    // 入力（日付文字列）は秘密ではないが、VC 本文の漏えい面を最小化するため値は message に含めない。
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return Math.floor(ms / 1000);
}
