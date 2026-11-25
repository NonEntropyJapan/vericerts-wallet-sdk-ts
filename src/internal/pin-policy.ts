/**
 * PIN 形式検証の SSOT。
 *
 * ウォレット復元と拡張の PIN 設定で異なる PIN を受け付けると、復元できても
 * 検証子を設定できなくなる。両方でこのモジュールの文字数と文字種の検査を使う。
 *
 * 検証規則:
 * - 文字列型であること。
 * - 制御文字（C0: U+0000〜U+001F、DEL: U+007F）を含まないこと。
 * - 長さが {@link MIN_PIN_LENGTH} 以上であること。長さは Unicode コードポイント数で数える
 *   （`pin.length`＝UTF-16 コードユニット数だと、サロゲートペア（絵文字など）を含む PIN の
 *   桁数判定が呼び出し側ごとに食い違う）。
 */

/** PIN に必要な最小の Unicode コードポイント数。 */
export const MIN_PIN_LENGTH = 6;

/**
 * 制御文字（C0: U+0000〜U+001F、DEL: U+007F）を含むか。
 *
 * 正規表現に制御文字をリテラルで書くとソースファイル自体に NUL バイトが入り、git / grep が
 * テキストとして扱えなくなるため、コードポイントで判定する。
 */
export function containsControlChar(pin: string): boolean {
  for (const ch of pin) {
    const code = ch.codePointAt(0) ?? 0;
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/**
 * PIN の形式検証。
 *
 * 長さを Unicode コードポイント数で数え（サロゲートペアを 1 文字とする）、制御文字（C0 / DEL）を
 * 禁じる。それ以外の印字可能文字は広く許容する（「英数記号可」）。
 */
export function isValidPinFormat(pin: unknown): pin is string {
  if (typeof pin !== 'string') return false;
  if (containsControlChar(pin)) return false;
  return [...pin].length >= MIN_PIN_LENGTH;
}
