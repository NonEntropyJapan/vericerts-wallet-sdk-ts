/**
 * ラベルカーディナリティ予算の強制。
 *
 * `WalletOptions.metrics` に注入された `Metrics`（未注入なら既定の in-memory 実装）へ渡る
 * **前に**、ラベル値と系列数に上限を適用する。予算は**設定変更不可の強制ポリシー**で、
 * `Logger` の PII マスキングと同じ位置づけである。呼び出し側がうっかり高カーディナリティ
 * な値（DID 文字列・URL・メッセージ全文など）をラベルに載せても、注入先の時系列データベースは
 * それを series の爆発として受け取らない。
 *
 * 予算違反は例外にしない。テレメトリの都合で業務経路を落とさないためであり、`Logger` 未注入を
 * no-op に落とすのと同じ判断による。代わりに warn ログで観測可能にする。
 */

import type { Logger } from './logger.js';
import type { Counter, Gauge, Histogram, Labels, Metrics } from './metrics.js';
import { createInMemoryMetrics, seriesKey } from './metrics.js';
import { safeEmit } from './safe-emit.js';

/** 許容外の値をまとめる先。 */
const OTHER = 'other';

/** 許容外の値を `other` にまとめるラベル（`method`）の許容値。 */
const METHOD_VALUES: ReadonlySet<string> = new Set([
  'key',
  'ethr',
  'web',
  'ipid',
  'pkh',
  'jwk',
  'peer',
  'webvh',
  'jwt',
]);

/**
 * 許容値以外を拒否するラベルと許容値。
 *
 * `Map` で引くのは、ラベルキーが呼び出し側由来の文字列であり、素のオブジェクトを添字で
 * 引くと `constructor` 等のプロトタイプ由来プロパティに当たってしまうため。
 */
const REJECTED_LABEL_VALUES: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ['format', new Set(['jwt', 'sd-jwt', 'data-integrity', 'cose'])],
  ['result', new Set(['success', 'failure'])],
  ['cache', new Set(['cold', 'warm', 'hot'])],
  ['source', new Set(['etsi', 'federation', 'arf'])],
  ['kind', new Set(['entity-configuration', 'subordinate-statement'])],
]);

/** `reason` はメトリクス名ごとに最初に観測した 20 種まで通し、21 種目以降は `other`。 */
const REASON_BUDGET = 20;

/** 1 メトリクスあたりのラベル組合せ上限（100 を超える組合せを破棄し、警告を記録する）。 */
const COMBINATION_BUDGET = 100;

/** 拒否された観測を捨てるための計器（呼び出し側には成功と区別が付かない形で無視される）。 */
const NOOP_COUNTER: Counter = { inc: () => {} };
const NOOP_HISTOGRAM: Histogram = { observe: () => {} };
const NOOP_GAUGE: Gauge = { set: () => {}, inc: () => {}, dec: () => {} };

/**
 * 注入された Metrics へラベルカーディナリティ予算を挟むラッパ。
 *
 * 正規化は計器を取り出す時点（`counter` / `histogram` / `gauge` の呼び出し）で 1 回だけ行う。
 * 予算の状態（`reason` の既知値・組合せ集合・警告済みメトリクス）は本インスタンスに閉じ、
 * メトリクス名ごとに独立して数える（別メトリクスの多様さが他方の予算を食い潰さないため）。
 */
class BudgetedMetrics implements Metrics {
  /** メトリクス名 → これまで通した `reason` 値。上限 `REASON_BUDGET` 件。 */
  private readonly reasons = new Map<string, Set<string>>();
  /** メトリクス名 → 実際に注入先へ流したラベル組合せの署名。上限 `COMBINATION_BUDGET` 件。 */
  private readonly combinations = new Map<string, Set<string>>();
  /** 切り捨て警告を出し終えたメトリクス名（同じメトリクスで警告を撒き続けない）。 */
  private readonly truncated = new Set<string>();

  constructor(
    private readonly sink: Metrics,
    private readonly logger: Logger,
  ) {}

  counter(name: string, labels?: Labels): Counter {
    const budgeted = this.applyBudget(name, labels);
    return budgeted === undefined ? NOOP_COUNTER : this.sink.counter(name, budgeted);
  }

  histogram(name: string, labels?: Labels, buckets?: readonly number[]): Histogram {
    const budgeted = this.applyBudget(name, labels);
    return budgeted === undefined ? NOOP_HISTOGRAM : this.sink.histogram(name, budgeted, buckets);
  }

  gauge(name: string, labels?: Labels): Gauge {
    const budgeted = this.applyBudget(name, labels);
    return budgeted === undefined ? NOOP_GAUGE : this.sink.gauge(name, budgeted);
  }

  /**
   * 予算を適用したラベルを返す（`undefined` は「この観測ごと捨てる」）。
   *
   * ラベルは own かつ列挙可能なものに限って読む（`Object.entries`）。予算が列挙していない
   * キーは素通しする — 将来追加されるラベルを本表の知らないところで潰さないためである。
   */
  private applyBudget(name: string, labels: Labels | undefined): Labels | undefined {
    const normalized: Labels = {};
    for (const [key, value] of Object.entries(labels ?? {})) {
      const allowed = REJECTED_LABEL_VALUES.get(key);
      if (allowed !== undefined) {
        if (!allowed.has(value)) {
          // 「他は拒否」。例外は投げず観測だけ落とす（テレメトリで呼び出し側を壊さない）。
          safeEmit(() =>
            this.logger.warn('metrics.label_rejected', { metric: name, label: key, value }),
          );
          return undefined;
        }
        normalized[key] = value;
        continue;
      }
      if (key === 'method') {
        // 未知のメソッド（未登録・形式不正・空文字）は 1 系列にまとめる。
        normalized[key] = METHOD_VALUES.has(value) ? value : OTHER;
        continue;
      }
      normalized[key] = key === 'reason' ? this.budgetedReason(name, value) : value;
    }
    return this.capCombinations(name, normalized);
  }

  /** `reason` を初めに観測した 20 種に抑える。21 種目以降は `other` に寄せ、集合は増やさない。 */
  private budgetedReason(name: string, value: string): string {
    const seen = this.reasons.get(name) ?? new Set<string>();
    this.reasons.set(name, seen);
    if (seen.has(value)) {
      return value;
    }
    if (seen.size >= REASON_BUDGET) {
      return OTHER;
    }
    seen.add(value);
    return value;
  }

  /**
   * 1 メトリクスあたりの組合せを 100 に抑える。
   *
   * 上限到達後の**新しい**組合せは全ラベル値を `other` に潰して 1 系列へ畳む（観測自体は
   * 落とさない。総数は保たれ、内訳だけが失われる）。畳んだ署名は集合へ加えない — 加えると
   * 上限が 1 つずつ実質的に緩み、記録済み組合せが 100 で頭打ちにならなくなる。
   */
  private capCombinations(name: string, labels: Labels): Labels {
    const seen = this.combinations.get(name) ?? new Set<string>();
    this.combinations.set(name, seen);
    const signature = seriesKey(name, labels);
    if (seen.has(signature)) {
      return labels;
    }
    if (seen.size < COMBINATION_BUDGET) {
      seen.add(signature);
      return labels;
    }
    if (!this.truncated.has(name)) {
      this.truncated.add(name);
      safeEmit(() => this.logger.warn('metrics.cardinality_truncated', { metric: name }));
    }
    const collapsed: Labels = {};
    for (const key of Object.keys(labels)) {
      collapsed[key] = OTHER;
    }
    return collapsed;
  }
}

/**
 * SDK 内部で使う `Metrics` を組み立てる。
 *
 * @param sink `WalletOptions.metrics`。未注入（`undefined`）なら in-memory 実装に落とす。
 * @param logger 予算違反の警告先。
 * @returns ラベルカーディナリティ予算を強制するラッパ。常に呼び出し可能。
 */
export function createMetrics(sink: Metrics | undefined, logger: Logger): Metrics {
  return new BudgetedMetrics(sink ?? createInMemoryMetrics().metrics, logger);
}
