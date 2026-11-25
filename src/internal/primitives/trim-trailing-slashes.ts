/**
 * 識別子 / URL 末尾のスラッシュ除去（横断ヘルパー）。
 *
 * `value.replace(/\/+$/, '')` は `/` の長い連続の**後ろに別の文字が続く**入力で O(n²) になる
 * （各開始位置で `/+` が連続の末尾まで走り、`$` に失敗して次の位置へ進むため）。Offer の
 * `credential_issuer` / `authorization_server` や受領 VC の `iss` は攻撃者が長さを決められる値で、
 * 取得・照合の前段で必ず評価されるため、正規表現ではなく末尾からの線形走査で除く。
 * 照合規則・URL 組み立てが経路ごとにずれないよう、この 1 か所に置く。
 */

/**
 * 末尾の `/` をすべて除く（`https://as.example//` → `https://as.example`）。O(n)。
 *
 * @param value 対象の文字列。
 * @returns 末尾の `/` の連続を取り除いた文字列。
 */
export function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x2f) {
    end -= 1;
  }
  return end === value.length ? value : value.slice(0, end);
}
