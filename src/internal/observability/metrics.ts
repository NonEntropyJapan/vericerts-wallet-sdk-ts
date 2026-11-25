/**
 * メトリクスの型定義と既定の in-memory 実装。
 *
 * 公開 API（`WalletOptions.metrics`）が受け取る `Metrics` の型と、未注入時に値をプロセス内に保持する既定実装を提供する。
 * ロガーの no-op と違って値を捨てないのは、メトリクスは「注入しなくても手元で読めること」
 * 自体が既定の価値だからである（外部送信は伴わないので Opt-in テレメトリの原則にも反しない）。
 *
 * SDK 内部が実際に使う計器は、本モジュールの実装をそのまま使うのではなく、ラベル
 * カーディナリティ予算を挟む `metrics-budget.ts` の `createMetrics` から受け取る。
 * 型は本モジュール（横断）に置き、`wallet/options.ts` が公開 API として再エクスポートする
 * （内部モジュールから公開 API 層への依存を避けるため）。
 */

/** メトリクスのラベル。 */
export type Labels = Record<string, string>;

/** 単調増加カウンタ。 */
export interface Counter {
  inc(value?: number): void;
}

/** 値の分布を記録するヒストグラム。 */
export interface Histogram {
  observe(value: number): void;
}

/** 増減する現在値。 */
export interface Gauge {
  set(value: number): void;
  inc(delta?: number): void;
  dec(delta?: number): void;
}

/** メトリクス出力先。Prometheus / OpenTelemetry Meter をアダプタで差し替える。 */
export interface Metrics {
  counter(name: string, labels?: Labels): Counter;
  histogram(name: string, labels?: Labels, buckets?: readonly number[]): Histogram;
  gauge(name: string, labels?: Labels): Gauge;
}

/**
 * 本 SDK が配線済みの必須メトリクス名（全 15 種）。
 *
 * 命名規約（小文字スネークケース・`vericerts_` 接頭辞・単位サフィックス）は
 * 呼び出し側が本定数を使うことで静的に担保する。実行時の名前検証は行わない（規約違反は
 * 実行するまでもなくレビューとこの定数で止まる。動的な名前検証は複雑さに見合わない）。
 *
 * DID 解決・VC 検証の 4 種、残り 11 種を配線した。うち
 * `BUNDLER_USEROP_TOTAL` / `FEDERATION_STATEMENT_FETCH_DURATION_SECONDS` /
 * `TRUST_CHAIN_BUILD_DURATION_SECONDS`（`source: 'federation'` のみ、`etsi` / `arf` は
 * follow-up）は、Wallet ファサードへ配線されていない独立した公開 seam のため `metrics` を
 * 任意引数としている（未注入時は記録しない）。
 */
export const MetricNames = {
  /** DID 解決の成功・失敗回数（labels: `method` / `result`）。 */
  DID_RESOLVE_TOTAL: 'vericerts_did_resolve_total',
  /** DID 解決レイテンシ（labels: `method` / `cache`）。 */
  DID_RESOLVE_DURATION_SECONDS: 'vericerts_did_resolve_duration_seconds',
  /** VC 検証回数（labels: `format` / `result` / `reason`）。 */
  VC_VERIFY_TOTAL: 'vericerts_vc_verify_total',
  /** VC 検証レイテンシ（labels: `format`）。 */
  VC_VERIFY_DURATION_SECONDS: 'vericerts_vc_verify_duration_seconds',
  /** Status List Token 取得レイテンシ（labels: `cache`）。 */
  STATUS_LIST_FETCH_DURATION_SECONDS: 'vericerts_status_list_fetch_duration_seconds',
  /** Status List 判定回数（失効確認、labels: `result`）。 */
  STATUS_LIST_CHECK_TOTAL: 'vericerts_status_list_check_total',
  /** ストレージ暗号化（`Wallet.encrypt`）のレイテンシ（labels: `algorithm`）。 */
  STORAGE_ENCRYPT_DURATION_SECONDS: 'vericerts_storage_encrypt_duration_seconds',
  /** Replay 検知回数（labels: `context`）。セキュリティ指標。 */
  NONCE_REPLAY_DETECTED_TOTAL: 'vericerts_nonce_replay_detected_total',
  /** UserOperation 送信結果（labels: `result`）。 */
  BUNDLER_USEROP_TOTAL: 'vericerts_bundler_userop_total',
  /** Federation Entity Statement 取得レイテンシ（labels: `kind` / `cache`）。 */
  FEDERATION_STATEMENT_FETCH_DURATION_SECONDS:
    'vericerts_federation_statement_fetch_duration_seconds',
  /** Trust Chain 構築レイテンシ（labels: `source`）。 */
  TRUST_CHAIN_BUILD_DURATION_SECONDS: 'vericerts_trust_chain_build_duration_seconds',
  /** PID 受領回数（labels: `result`）。 */
  PID_ISSUANCE_TOTAL: 'vericerts_pid_issuance_total',
  /** OID4VP 応答生成レイテンシ（labels: `format`）。 */
  OID4VP_RESPONSE_DURATION_SECONDS: 'vericerts_oid4vp_response_duration_seconds',
  /**
   * WUA 取得回数（labels: `result`）。
   *
   * spec 名は「リフレッシュ回数」だが、本 SDK の WUA 取得 API は `obtainWalletAttestation`
   * のみ（`internal/eudi/wua/wua.ts` の `refreshWalletAttestation` はどこからも呼ばれない未配線の
   * 純関数）。取得の都度そのときの有効な WUA に置き換わるため、実質的な更新（refresh）はこの
   * 1 経路がすべてで、本メトリクスもここで記録する。
   */
  WUA_REFRESH_TOTAL: 'vericerts_wua_refresh_total',
  /** OID4VCI Token Endpoint レイテンシ（labels: `flow`）。 */
  OID4VCI_TOKEN_DURATION_SECONDS: 'vericerts_oid4vci_token_duration_seconds',
} as const;

/** カウンタ・ゲージの観測値 1 系列（`createInMemoryMetrics` のスナップショット要素）。 */
export interface MetricSample {
  readonly name: string;
  readonly labels: Labels;
  readonly value: number;
}

/** ヒストグラムの観測値 1 系列（件数と合計。バケットは既定実装では保持しない）。 */
export interface HistogramSample {
  readonly name: string;
  readonly labels: Labels;
  readonly count: number;
  readonly sum: number;
}

/** in-memory 実装が保持している全系列の写し（テスト・Dashboard 表示用）。 */
export interface MetricsSnapshot {
  readonly counters: readonly MetricSample[];
  readonly histograms: readonly HistogramSample[];
  readonly gauges: readonly MetricSample[];
}

/** in-memory 実装と、その蓄積値を読み出す口。 */
export interface InMemoryMetrics {
  readonly metrics: Metrics;
  snapshot(): MetricsSnapshot;
}

/**
 * `name` とラベルから系列キーを作る。
 *
 * ラベルはキー昇順に並べ替えてから直列化する。宣言順が違うだけの同じラベル集合を別系列に
 * 割ってしまうと、蓄積値が分裂し、組合せ計数も過大になるためである。既定実装の系列
 * 同定と `metrics-budget.ts` の組合せ計数は**同じ同定規則**でなければならないため共有する。
 */
export function seriesKey(name: string, labels: Labels): string {
  const entries = Object.entries(labels).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return JSON.stringify([name, entries]);
}

/** in-memory 実装が系列ごとに持つ可変の蓄積値（カウンタ・ゲージ・ヒストグラムで共用）。 */
interface SeriesState {
  readonly name: string;
  readonly labels: Labels;
  value: number;
  count: number;
  sum: number;
}

/**
 * 既定の in-memory 実装を組み立てる。
 *
 * 同じ `name` + ラベルで何度呼んでも同一の系列へ積み上がる（呼び出しごとに新しい計器を
 * 作ると値が分裂して集計にならない）。ヒストグラムのバケットは保持しない — バケット境界の
 * 管理は Prometheus 等の注入先の責務で、既定実装が担うのは件数と合計の提示までである。
 */
export function createInMemoryMetrics(): InMemoryMetrics {
  const counters = new Map<string, SeriesState>();
  const histograms = new Map<string, SeriesState>();
  const gauges = new Map<string, SeriesState>();

  /** 系列を取り出す（無ければ 0 で作る）。ラベルは呼び出し側の参照を持ち越さないよう複製する。 */
  const series = (store: Map<string, SeriesState>, name: string, labels: Labels): SeriesState => {
    const key = seriesKey(name, labels);
    const found = store.get(key);
    if (found !== undefined) {
      return found;
    }
    const created: SeriesState = { name, labels: { ...labels }, value: 0, count: 0, sum: 0 };
    store.set(key, created);
    return created;
  };

  const metrics: Metrics = {
    counter(name, labels = {}) {
      const state = series(counters, name, labels);
      // 既定の増分は 1（Prometheus の `Counter.inc()` と同じ）。
      return {
        inc: (value = 1) => {
          state.value += value;
        },
      };
    },
    histogram(name, labels = {}) {
      const state = series(histograms, name, labels);
      return {
        observe: (value) => {
          state.count += 1;
          state.sum += value;
        },
      };
    },
    gauge(name, labels = {}) {
      const state = series(gauges, name, labels);
      return {
        set: (value) => {
          state.value = value;
        },
        // ゲージも既定の増減幅は 1（`Counter.inc()` と揃える）。
        inc: (delta = 1) => {
          state.value += delta;
        },
        dec: (delta = 1) => {
          state.value -= delta;
        },
      };
    },
  };

  return {
    metrics,
    snapshot: () => ({
      counters: [...counters.values()].map(({ name, labels, value }) => ({ name, labels, value })),
      histograms: [...histograms.values()].map(({ name, labels, count, sum }) => ({
        name,
        labels,
        count,
        sum,
      })),
      gauges: [...gauges.values()].map(({ name, labels, value }) => ({ name, labels, value })),
    }),
  };
}
