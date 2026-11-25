/**
 * ISO 8601 日時（オフセット必須）の厳格パーサ。期限・有効期間・versionTime 判定の SSOT。
 *
 * `Date.parse` 単独は、オフセット無しの日時（`2026-09-01T00:00:00`）を**実行環境の TZ の
 * ローカル時刻**として解釈し、`'Dec 1 2025'` や `'1'` のような非 ISO 文字列も数値にする。
 * 同じ VC / grant / DID Log の合否が検証環境の TZ で変わるため、正規表現で形式を固定してから
 * `Date.parse` する。
 *
 * V8 / JSC の `Date.parse` は暦として不正な日付（`2026-02-30` / `04-31` / `T24:00:00`）を翌日へ
 * 繰り上げて受理するため、各成分の範囲と月ごとの日数も検査して `NaN` に倒す。
 */

/** 許す ISO 8601 日時形式（`T` 区切り、秒必須、オフセット `Z` / `±hh:mm` 必須）。 */
const ISO_8601_DATE_TIME =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/;

/** 日付のみ（`YYYY-MM-DD`）。ECMAScript は日付のみの形式を UTC 0 時として解釈する（TZ 非依存）。 */
const ISO_8601_DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})$/;

/** 月ごとの日数（非うるう年）。 */
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] as const;

/** 年・月・日が暦として実在するか（グレゴリオ暦のうるう年を考慮）。 */
function isRealCalendarDate(year: number, month: number, day: number): boolean {
  if (month < 1 || month > 12 || day < 1) {
    return false;
  }
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  return day <= (month === 2 && leap ? 29 : (DAYS_IN_MONTH[month - 1] ?? 0));
}

/**
 * ISO 8601 日時（オフセット必須）をエポックミリ秒へ変換する。例外は投げない。
 *
 * **引数の型は実行時には保証されない。** 非信頼な本文から cast だけで取り出した値
 * （`{}` や prototype を持たないオブジェクト）が届き得るため、文字列以外も `NaN` へ倒す
 * （`Date.parse` の暗黙 `ToPrimitive` による `TypeError` を避ける）。
 *
 * @param value 日時文字列（型は保証されない）。
 * @returns エポックミリ秒。形式不正・解釈不能なら `NaN`。
 */
export function parseIsoDateTimeMs(value: unknown): number {
  const m = typeof value === 'string' ? ISO_8601_DATE_TIME.exec(value) : null;
  if (m === null) {
    return Number.NaN;
  }
  const [, year, month, day, hour, minute, second, offsetHour = '0', offsetMinute = '0'] = m;
  if (
    !isRealCalendarDate(Number(year), Number(month), Number(day)) ||
    Number(hour) > 23 ||
    Number(minute) > 59 ||
    Number(second) > 59 ||
    Number(offsetHour) > 23 ||
    Number(offsetMinute) > 59
  ) {
    return Number.NaN;
  }
  return Date.parse(value as string);
}

/**
 * {@link parseIsoDateTimeMs} に加え、日付のみ（`YYYY-MM-DD`、UTC 0 時）も受理する。
 *
 * 日付のみの形式は ECMAScript 仕様上 UTC として解釈されるため TZ に依存しない。JSON Schema の
 * `format: "date"` 検証（`credential/json-schema/internals.ts`）が使う。
 *
 * @param value 日時または日付文字列（型は保証されない）。
 * @returns エポックミリ秒。形式不正・解釈不能なら `NaN`。
 */
export function parseIsoDateOrDateTimeMs(value: unknown): number {
  const m = typeof value === 'string' ? ISO_8601_DATE_ONLY.exec(value) : null;
  if (m === null) {
    return parseIsoDateTimeMs(value);
  }
  return isRealCalendarDate(Number(m[1]), Number(m[2]), Number(m[3]))
    ? Date.parse(value as string)
    : Number.NaN;
}
