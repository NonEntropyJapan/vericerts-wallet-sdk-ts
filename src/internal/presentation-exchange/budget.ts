/**
 * PEx 評価で共有する予算（正規表現ステップ・JSONPath 走査量・`const` / `enum` / `minLength` / `maxLength` の走査量）と、
 * 予算と同じ寿命の `filter.pattern` コンパイル結果のメモ。
 *
 * 予算の単位は「Presentation Request 1 件」。`evaluatePresentationDefinition` は呼び出しごとに新しい予算を
 * 作るが、保持 VC を 1 件ずつ評価する呼び出し側（`matchCredentialsByPresentationDefinition`）は
 * {@link createPexBudget} で作った 1 つの予算を全 VC で共有する。VC の件数に比例して
 * 上限が増えると、Verifier 由来の `path` / `pattern` で同期処理を件数倍だけ占有できてしまうため。
 */

import { type EvaluationBudget, MAX_SCAN_UNITS } from '../credential/json-schema/internals.js';
import type { RegexBudget, SafeRegex, SafeRegexError } from '../primitives/safe-regex/index.js';
import { MAX_PATH_READS, type PathBudget } from './path-budget.js';

/**
 * 1 つの予算で `filter.pattern` の評価に使ってよいステップ総量。
 * Verifier は記述子・フィールド数を自由に増やせるため、予算 1 つ全体で総量を抑える。
 * 超過後の `pattern` は不一致（fail-closed）になる。
 */
export const MAX_PEX_REGEX_STEPS = 10_000_000;

/** 評価で共有する予算。 */
export interface PexBudget {
  readonly regex: RegexBudget;
  readonly paths: PathBudget;
  /** `filter.const` / `filter.enum` の深い等価判定の走査量（`deepEqual` が使う JSON Schema 側の予算型）。 */
  readonly scan: EvaluationBudget;
  /**
   * `filter.pattern` のコンパイル結果（失敗も保持）。同じ `pattern` 文字列をフィールド × 保有 VC の組ごとに
   * 再コンパイルさせないため、予算と同じ寿命（Presentation Request 1 件）でメモする。
   */
  readonly patterns: Map<string, SafeRegex | SafeRegexError>;
  /** `patterns` に積んだコンパイルの回数（決定的に pin するための計数）。 */
  patternCompiles: number;
}

/** 新しい予算を作る。 */
export function createPexBudget(): PexBudget {
  const regex: RegexBudget = { remaining: MAX_PEX_REGEX_STEPS };
  return {
    regex,
    paths: { remaining: MAX_PATH_READS, exhausted: false },
    scan: { remaining: 0, exhausted: false, regex, scanRemaining: MAX_SCAN_UNITS },
    patterns: new Map(),
    patternCompiles: 0,
  };
}
