/**
 * JSON Schema バリデータの内部ヘルパー（再帰を含まない純粋関数群）。
 */

import { parseIsoDateOrDateTimeMs, parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import {
  compileSafeRegex,
  type RegexBudget,
  type SafeRegex,
  SafeRegexError,
} from '../../primitives/safe-regex/index.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { JsonSchema, SchemaError } from './types.js';

/** 再帰の最大深さ（循環 `$ref` / 深いネストによるスタック枯渇の防止）。 */
export const MAX_DEPTH = 64;

/**
 * 1 回の検証で評価してよいスキーマノードの総数上限。
 *
 * `MAX_DEPTH` は 1 本の再帰経路の長さしか制限しないため、`anyOf` / `oneOf` / `not` の
 * 分岐評価が深さごとに枝分かれする指数爆発を止められない（`{"$defs":{"x":{"anyOf":
 * [{"$ref":"#/$defs/x"},{"$ref":"#/$defs/x"}]}},"$ref":"#/$defs/x"}` は 2^深さ の評価になる）。
 * スキーマは Issuer が配布するリモート文書 = 攻撃者が影響し得る入力なので、分岐の試行を
 * 含む評価ノード数に**総量上限**を課して DoS を防ぐ。実在の VC スキーマの評価量とは
 * 桁違いに大きい値を選び、正当な検証を打ち切らないようにする。
 */
export const MAX_EVALUATIONS = 50_000;

/**
 * 1 回の検証で `pattern` / `patternProperties` の正規表現評価に使ってよいステップ総量。
 *
 * 正規表現は線形時間エンジン（`safe-regex`）で評価するが、スキーマは Issuer 由来で
 * `patternProperties` × キー数のように呼び出し回数を増やせるため、1 回の検証全体で総量を共有する。
 */
export const MAX_REGEX_STEPS = 5_000_000;

/**
 * 1 回の検証で走査（`uniqueItems` の正規化・`enum` / `const` の等価判定・インスタンスのキー列挙・
 * スキーマ側配列 `required` / `type` / `allOf` / `anyOf` / `oneOf` の要素数）に使ってよい走査量の総量。単位はノード数・文字数相当で、1 MiB のインスタンスを 1 回走査すると約 100 万。
 *
 * 要素数基準の計上はサイズを無視するため、巨大な要素を持つインスタンスを `allOf` の多重化で
 * 何度も走査させる DoS を止められなかった。実コストに比例する量を共有予算から差し引く。
 * スキーマ側の配列も長さ × 評価ノード数で無計上のまま増幅できたため、同じ予算へ前払いする。
 * 文字列インスタンス・インスタンスのオブジェクトキー・`required` の欠落キー・`$ref` 文字列は長さに比例する
 * 処理を持つため、`1 + 長さ / 8` 相当を同じ予算へ前払いする。
 */
export const MAX_SCAN_UNITS = 4_000_000;

/**
 * 走査量 1 単位が表す文字数。文字列インスタンス・オブジェクトキー・`$ref` のように長さに比例して
 * 処理される値は `1 + 長さ / この値` を走査量へ前払いする（`deepEqual` の文字列比較と同じ換算）。
 */
export const CHARS_PER_SCAN_UNIT = 8;

/** 長さ `length` の文字列 1 つを処理するための走査量（{@link CHARS_PER_SCAN_UNIT} 換算、最小 1）。 */
export function stringScanUnits(length: number): number {
  return 1 + Math.floor(length / CHARS_PER_SCAN_UNIT);
}

/**
 * 1 回の検証で収集する違反の件数上限。
 *
 * `required` の欠落キーごとの違反を `allOf` / `$ref` / `items` で何度も評価させると、1 MiB 以内の
 * スキーマでも違反オブジェクトが数十億件生成されてヒープを使い切る。上限に達したら以降の違反は
 * 捨て、`exhausted` を立てて検証全体を fail-closed にする（ルートに必須違反が 1 件残る）。
 * 実在のスキーマの違反件数とは桁違いに大きい値で、診断に必要な先頭の違反は保持する。
 */
export const MAX_ERRORS = 1_000;

/** 評価ノード数の残量（分岐の試行も含め、1 回の検証全体で共有する）。 */
export interface EvaluationBudget {
  /** 残り評価可能ノード数。 */
  remaining: number;
  /** 上限に達したか（分岐の試行内で使い切った場合も `true`）。 */
  exhausted: boolean;
  /** 正規表現評価のステップ残量（{@link MAX_REGEX_STEPS}）。コンパイル費用も差し引く。 */
  readonly regex: RegexBudget;
  /** JSON 値の走査量の残量（{@link MAX_SCAN_UNITS}）。 */
  scanRemaining: number;
}

/** `patternProperties` 1 件分をコンパイルした結果。 */
export interface CompiledPatternProperties {
  /** コンパイルできたエントリ（正規表現・一致したキーに適用する部分スキーマ）。 */
  readonly matchers: readonly { readonly regex: SafeRegex; readonly schema: unknown }[];
  /** 評価できない正規表現が 1 つでもあったか。 */
  readonly unusable: boolean;
}

/**
 * 1 回の検証内で共有するコンパイル結果のキャッシュ。分岐の試行・配列の各要素・
 * オブジェクトごとに同じ `pattern` / `patternProperties` を再コンパイルさせないため。
 */
export interface CompileCache {
  /** `pattern` ソース → コンパイル結果（失敗も保持する）。 */
  readonly sources: Map<string, SafeRegex | SafeRegexError>;
  /** `patternProperties` オブジェクト → コンパイル結果。 */
  readonly patternProperties: WeakMap<object, CompiledPatternProperties>;
}

/** 検証中に積み上げる文脈。 */
export interface Context {
  /** 収集した違反。 */
  readonly errors: SchemaError[];
  /** `$ref` 解決の起点となるルートスキーマ。 */
  readonly root: JsonSchema;
  /** 評価ノード数の残量（`anyOf` 等の分岐試行とも共有する）。 */
  readonly budget: EvaluationBudget;
  /** 分岐の試行用（適合したか否かだけを見るため違反は 1 件で打ち切り、上限超過で `exhausted` を立てない）。 */
  readonly probe?: boolean;
  /** 正規表現のコンパイル結果（分岐試行とも共有する）。 */
  readonly compiled: CompileCache;
}

/**
 * 評価ノードを 1 つ消費する。
 *
 * @returns まだ評価してよければ `true`、総量上限に達していれば `false`。
 */
export function consumeEvaluation(budget: EvaluationBudget): boolean {
  if (budget.remaining <= 0) {
    budget.exhausted = true;
    return false;
  }
  budget.remaining -= 1;
  return true;
}

/**
 * JSON 値の走査量を `units` 消費する（インスタンスの大きさに比例する走査の計上用）。
 *
 * @returns 残量が足りれば `true`。足りなければ残量を使い切り `exhausted` を立てて `false`。
 */
export function consumeScan(budget: EvaluationBudget, units: number): boolean {
  if (budget.scanRemaining < units) {
    budget.scanRemaining = 0;
    budget.exhausted = true;
    return false;
  }
  budget.scanRemaining -= units;
  return true;
}

/** 新しい検証 1 回分のコンパイルキャッシュを作る。 */
export function createCompileCache(): CompileCache {
  return { sources: new Map(), patternProperties: new WeakMap() };
}

/**
 * `pattern` ソースをコンパイルする（検証 1 回の内ではソースごとに 1 回だけ）。
 *
 * コンパイル費用はソース長に比例するとみなして正規表現ステップ予算から差し引く。使い切ったら
 * `too-complex`。失敗もキャッシュし、同じ例外を投げ直す。
 *
 * @throws SafeRegexError コンパイルできない・予算超過。
 */
export function compilePattern(ctx: Context, source: string): SafeRegex {
  const cached = ctx.compiled.sources.get(source);
  if (cached instanceof SafeRegexError) {
    throw cached;
  }
  if (cached !== undefined) {
    return cached;
  }
  try {
    const regexBudget = ctx.budget.regex;
    if (regexBudget.remaining < source.length) {
      regexBudget.remaining = 0;
      throw new SafeRegexError('too-complex');
    }
    regexBudget.remaining -= source.length;
    const regex = compileSafeRegex(source);
    ctx.compiled.sources.set(source, regex);
    return regex;
  } catch (error) {
    if (error instanceof SafeRegexError) {
      ctx.compiled.sources.set(source, error);
    }
    throw error;
  }
}

/**
 * 正規表現の失敗を違反メッセージにする。
 *
 * どの種別も検証全体を fail-closed にするため `exhausted` を立てる（`not` / `anyOf` / `oneOf` の
 * 試行内で捨てられる違反を取りこぼさない）。評価不能な `pattern`（先読み・後方参照・構文不正）を
 * 単なる不一致として扱うと、`not` が「禁止条件を満たさなかった」ことになり fail-open になる。
 */
export function patternFailureMessage(ctx: Context, error: unknown): string {
  if (!(error instanceof SafeRegexError)) {
    throw error;
  }
  ctx.budget.exhausted = true;
  switch (error.reason) {
    case 'syntax':
      return 'pattern が正規表現として不正です';
    case 'unsupported':
      return 'pattern が線形時間で評価できない構文（後方参照・先読み・後読み）を含むため評価しません';
    case 'too-complex':
      return 'pattern が長すぎる・複雑すぎる、または評価量が上限に達したため評価しません';
  }
}

/** JSON Pointer の 1 セグメントをエスケープする（RFC 6901 §3）。 */
export function escapePointer(segment: string): string {
  return segment.replace(/~/g, '~0').replace(/\//g, '~1');
}

/**
 * 違反を 1 件記録する。`message` には値を含めない。
 *
 * `path` が空文字列（= インスタンスのルート）の違反は、`required` 引数によらず常に
 * **必須属性の違反**として分類する。ルートの違反は「`credentialSubject` の構造そのものが
 * スキーマと矛盾している」ことを意味し、FO-4（`credentialSchema` の
 * **任意属性**バリデーション違反 = 警告通過）の対象ではないため。ルートを任意扱いにすると
 * 型が丸ごと食い違う VC まで `valid: true` で通過してしまう。
 */
export function addError(ctx: Context, path: string, message: string, required: boolean): void {
  if (ownProperty<boolean>(ctx, 'probe') === true) {
    // 試行の結果は「違反が 1 件でもあるか」しか使わない。
    if (ctx.errors.length === 0) {
      ctx.errors.push({ path, message, required: required || path === '' });
    }
    return;
  }
  if (ctx.errors.length >= MAX_ERRORS) {
    // 捨てた違反の中に必須違反があり得るため、検証全体を fail-closed にする。
    ctx.budget.exhausted = true;
    return;
  }
  ctx.errors.push({ path, message, required: required || path === '' });
}

/** インスタンスの JSON 型名を返す（JSON Schema の `type` 語彙に合わせる）。 */
export function jsonTypeOf(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'array';
  }
  const t = typeof value;
  if (t === 'number') {
    return Number.isInteger(value) ? 'integer' : 'number';
  }
  return t;
}

/** `type` キーワードに適合するか判定する（`integer` は `number` の部分集合）。 */
export function matchesType(value: unknown, expected: string): boolean {
  const actual = jsonTypeOf(value);
  if (expected === 'number') {
    return actual === 'number' || actual === 'integer';
  }
  return actual === expected;
}

/**
 * 正規表現（形状）のあとに暦の妥当性まで検査する `format`（`date` / `date-time`）。
 *
 * 桁数だけの正規表現は `2025-13-45` / `2025-02-30` / `T24:00:00` / `+99:99` を通してしまい、後段の
 * `parseIsoDateTimeMs`（3002 を返す SDK の厳格パーサ）と判定が食い違う。RFC 3339 は
 * `t` / `z` の小文字も許すため、形状は小文字を受理し、暦検査は大文字へ正規化して行う。
 */
function calendarFormat(shape: RegExp, parse: (value: string) => number): (v: string) => boolean {
  return (value) => shape.test(value) && !Number.isNaN(parse(value.toUpperCase()));
}

/**
 * よく使う `format` の検証関数。
 *
 * Draft 2020-12 では `format` は既定で注釈扱いだが、VC のスキーマは日付・URI の形式を
 * `format` で表現することが多いため、既知の値のみ実際に検証する。未知の `format` は無視する。
 * キーはスキーマ由来の任意文字列のため、`constructor` 等の継承プロパティを引かない `Map` を使う。
 */
export const FORMAT_CHECKS: ReadonlyMap<string, (value: string) => boolean> = new Map([
  ['date', calendarFormat(/^\d{4}-\d{2}-\d{2}$/, parseIsoDateOrDateTimeMs)],
  [
    'date-time',
    calendarFormat(
      /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/,
      parseIsoDateTimeMs,
    ),
  ],
  ['email', (value) => /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(value)],
  ['uri', (value) => /^[A-Za-z][A-Za-z0-9+.-]*:/.test(value)],
]);
