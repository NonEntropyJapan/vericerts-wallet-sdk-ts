/**
 * Federation Entity Statement のキャッシュ層（Entity Configuration / Subordinate Statement 共通）。
 *
 * TTL の決め方（did:web / Token Status List とはここが異なる）:
 *
 * - Entity Statement は**自分自身の `iat` / `exp` を署名対象として持つ**。したがって TTL の上界は
 *   Statement 自身の `exp`（`exp - now`）だけで決まり、SDK は独自のヒューリスティックを一切足さない。
 * - HTTP `Cache-Control` は**権威ではない**。署名されていない配信側ヘッダが、署名された有効期間を
 *   延ばすことも縮めることもあってはならないため、本モジュールは `max-age` を参照しない
 *   （did:web / Status List が `Cache-Control` を尊重するのは、対象自体が有効期間を持たないため）。
 * - そのうえでエントリは **600 秒**（`FEDERATION_CACHE_MAX_TTL_SECONDS`）で頭打ちにする。これは
 *   SDK が勝手に TTL を短縮しているのではなく、**鍵無効化宣言（`revoked_keys`）の伝播 SLA という
 *   仕様上の要求**である。`exp` が 1 年先の
 *   Statement をそのまま 1 年キャッシュすると、上位が公開した無効化宣言が 1 年間 Verifier に届かない。
 *
 * すなわち採用 TTL は `min(exp - now, 600)` である。
 *
 * キャッシュする値は**生の compact JWT 文字列**であり、検証済みオブジェクトではない。命中時も
 * 毎回デコード・署名検証・`iss` / `sub` 一致・有効期間検証をやり直すため、「キャッシュに入った時点で
 * 検証を済ませたことにする」経路が構造的に存在しない。`resolveCachedStatement` が検証関数
 * （`verify`）をキャッシュ命中・ミスの双方で必ず呼ぶのはこのためである。
 *
 * negative cache は**取得（`fetchJwt`）の内側で起きた失敗だけ**を 30 秒記憶する。デコード・署名・
 * 構造・有効期間の検証はキャッシュ領域の外で行うため、「取得は成功したが Statement が不正」
 * （`TRUST_CHAIN_INVALID`、5010）は決して記憶されない。両者は別の条件であり、前者は「取得先が今は
 * 応答しない」という短時間持続しやすい状態、後者は配信側の差し替えで即座に直り得る内容の問題である
 * （did:web の 2003 / 2010 の切り分けと同じ規律）。
 *
 * セキュリティ上の注意:
 * - キャッシュキーは well-known URL / fetch endpoint URL であり、ログ・例外メッセージ・`context`・
 *   観測イベントには載せない。観測イベントに渡すのは種別と状態ラベルのみ。
 */

import {
  type CacheState,
  createTtlCache,
  resolveMaxTtlSeconds,
  STRING_CACHE_MAX_TOTAL_LENGTH,
  systemNowSeconds,
  type TtlCache,
} from '../../../cache/index.js';
import type { Metrics } from '../../../observability/metrics.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../../prototype-safety/own-property.js';
import { failOrSubstitute, type StatementFetchFailureHook } from '../fail-open/fetch-failure.js';
import { KEY_REVOCATION_PROPAGATION_MAX_SECONDS } from '../revocation/key-revocation.js';

/**
 * Federation Entity Statement のキャッシュ TTL 上限（秒）。
 *
 * 値は `KEY_REVOCATION_PROPAGATION_MAX_SECONDS`（600）そのものであり、独立した定数として
 * 数値を再宣言しない。上限の意味は「鍵無効化宣言が公開されてから Verifier に届くまでの上界」で
 * あって性能上の調整値ではないため、片方だけ動かせる形にしてはならない。
 */
export const FEDERATION_CACHE_MAX_TTL_SECONDS = KEY_REVOCATION_PROPAGATION_MAX_SECONDS;

/** キャッシュ対象の Entity Statement の種別（`kind` ラベル）。 */
export type FederationStatementKind = 'entity-configuration' | 'subordinate-statement';

/**
 * キャッシュ観測イベント（`kind`、`cache` ラベルに対応）。
 *
 * entity_id / URL / JWT は**含めない**。この値はメトリクスラベルやログへ渡る前提であり、
 * 高カーディナリティかつ追跡可能な識別子を載せてはならない。
 */
export interface FederationCacheEvent {
  /** Statement の種別。 */
  readonly kind: FederationStatementKind;
  /** キャッシュ状態（`cold` / `warm` / `hot`）。 */
  readonly state: CacheState;
}

/** Federation の取得系に注入するキャッシュ依存（すべて任意。未指定なら毎回取得する）。 */
export interface FederationCacheDeps {
  /** Entity Statement（生 JWT）のキャッシュ。未指定ならキャッシュしない（従来動作）。 */
  readonly statementCache?: TtlCache<string>;
  /** TTL 上限（秒）。`FEDERATION_CACHE_MAX_TTL_SECONDS` 以下のみ許可（緩和は 3002 で拒否）。 */
  readonly maxTtlSeconds?: number;
  /** キャッシュ状態の観測フック（メトリクス / span 属性の記録点）。 */
  readonly onCacheEvent?: (event: FederationCacheEvent) => void;
  /**
   * `vericerts_federation_statement_fetch_duration_seconds`の記録先。
   * 未指定なら記録しない。`statement-observability.ts` の `instrumentFederationStatementFetch`
   * が本フィールドを読んで計装する（`resolveCachedStatement` 自体は計装を持たない）。
   */
  readonly metrics?: Metrics;
}

/**
 * Federation Entity Statement 用の TTL キャッシュを生成する。
 *
 * TTL 上限は `FEDERATION_CACHE_MAX_TTL_SECONDS`（600 秒）で固定する。ここを緩める設定は
 * `resolveMaxTtlSeconds` が拒否するため、生成側では受け付けない。
 *
 * @param nowSeconds 時計（エポック秒）。未指定なら実時計。
 * @param maxEntries 保持する最大エントリ数（省略時はキャッシュ層の既定）。
 * @returns Entity Statement（生 JWT）用 TTL キャッシュ。
 */
export function createFederationStatementCache(
  nowSeconds: () => number = systemNowSeconds,
  maxEntries?: number,
): TtlCache<string> {
  const maxTtlSeconds = FEDERATION_CACHE_MAX_TTL_SECONDS;
  return createTtlCache<string>(
    maxEntries === undefined
      ? { maxTtlSeconds, nowSeconds, maxTotalWeight: STRING_CACHE_MAX_TOTAL_LENGTH }
      : { maxTtlSeconds, nowSeconds, maxEntries, maxTotalWeight: STRING_CACHE_MAX_TOTAL_LENGTH },
  );
}

/**
 * Entity Statement をキャッシュしてよい秒数を求める。
 *
 * `min(exp - now, maxTtlSeconds)` を 0 で下限クリップした値。既に `exp` を過ぎている
 * （`exp <= now`）Statement は 0 を返し、格納しない。
 *
 * `iat` を引数に取るのは TTL の起点が Statement 自身の有効期間であることを型で示すためで、
 * 上界を決めるのは `exp` だけである（`iat` に基づく有効性判定は `assertStatementTimeValid` の責務）。
 * SDK 側の独自短縮は行わない。`maxTtlSeconds` による頭打ちは SDK の判断ではなく、鍵無効化宣言の
 * 伝播 SLA という仕様上の要求である（`FEDERATION_CACHE_MAX_TTL_SECONDS`）。
 *
 * @param statement Statement の有効期間クレーム（`iat` / `exp`、いずれもエポック秒）。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @param maxTtlSeconds 採用する TTL 上限（秒）。
 * @returns キャッシュしてよい秒数。0 ならキャッシュしない。
 */
export function statementCacheTtlSeconds(
  statement: { readonly iat: number; readonly exp: number },
  nowSeconds: number,
  maxTtlSeconds: number,
): number {
  return Math.max(0, Math.min(statement.exp - nowSeconds, maxTtlSeconds));
}

/** `resolveCachedStatement` の `verify` が返す検証結果（値と TTL 根拠の有効期間クレーム）。 */
export interface CachedStatementVerification<T> {
  /** 呼び出し側へ返す検証済みの値。 */
  readonly value: T;
  /** TTL を決める有効期間クレーム（署名検証済みの Statement 由来であること）。 */
  readonly statement: { readonly iat: number; readonly exp: number };
}

/** `resolveCachedStatement` の入力。 */
export interface CachedStatementRequest<T> {
  /** キャッシュキー（well-known URL / `sub` を含む fetch endpoint URL）。 */
  readonly key: string;
  /** Statement の種別（観測イベント用）。 */
  readonly kind: FederationStatementKind;
  /** キャッシュ依存（未注入ならキャッシュせず毎回取得する）。 */
  readonly deps: FederationCacheDeps;
  /** 現在時刻（エポック秒）。 */
  readonly nowSeconds: number;
  /** compact JWT を取得する関数。キャッシュ命中時は呼ばれない。 */
  readonly fetchJwt: () => Promise<string>;
  /** JWT を検証する関数。**キャッシュ命中時も必ず呼ばれる**（再検証の担保）。 */
  readonly verify: (jwt: string) => CachedStatementVerification<T>;
  /**
   * 取得失敗時に代替 JWT を問い合わせるフック（FO-6）。設定するのは
   * `entity-configuration.ts` だけで、`subordinate.ts` は設定しない。Subordinate Statement の
   * 取得失敗は本フィールドの存在に関わらず fail-closed のままである（鍵無効化宣言の伝播を
   * 止めないため。FC-11）。返された JWT も他の経路と同じく `verify` を必ず通す。
   * `undefined` を返した場合・未設定の場合は、元の失敗を従来どおりそのまま送出する。
   */
  readonly onFetchFailure?: StatementFetchFailureHook;
}

/** 観測フックへ状態を通知する（フック未設定なら何もしない）。 */
function emitCacheEvent<T>(request: CachedStatementRequest<T>, state: CacheState): void {
  // 鎖を辿らない（`Object.prototype` 汚染で観測フックが差し替わるのを防ぐ）。
  const emit = nonObjectPrototypeProperty<FederationCacheDeps['onCacheEvent']>(
    request.deps,
    'onCacheEvent',
  );
  emit?.({ kind: request.kind, state });
}

/**
 * Entity Statement をキャッシュ経由で取得・検証する。
 *
 * 状態遷移（`cache` ラベル）:
 * - エントリ無し → `cold`（ネットワーク取得）
 * - エントリ有り・TTL 切れ → `warm`（再取得。staleness の観測点）
 * - エントリ有り・TTL 内 → `hot`（ネットワーク I/O 無し。ただし検証はやり直す）
 * - 記憶済みの取得失敗に命中 → `hot`（ネットワークに出ず同じ失敗を再送出する）
 *
 * TTL 上限の検証はキャッシュの有無に依らず先に行う。キャッシュ未注入でも、緩める指定
 * （601 秒以上）は黙って無視せず `3002` で拒否する（設定ミスを運用に持ち込ませない）。
 *
 * 取得失敗（negative cache 命中を含む）は `request.onFetchFailure` が代替 JWT を返した場合に限り
 * 救済する（FO-6）。フック未設定なら従来どおり失敗をそのまま送出する。
 *
 * @param request キー・種別・依存・時刻・取得関数・検証関数。
 * @returns 検証済みの値。
 * @throws TTL 上限設定が不正な場合（VericertsError、code `3002`）、
 *         および `fetchJwt` / `verify` が投げた例外をそのまま。
 */
export async function resolveCachedStatement<T>(request: CachedStatementRequest<T>): Promise<T> {
  const maxTtlSeconds = resolveMaxTtlSeconds(
    ownProperty<number>(request.deps, 'maxTtlSeconds'),
    FEDERATION_CACHE_MAX_TTL_SECONDS,
  );
  const cache = nonObjectPrototypeProperty<TtlCache<string>>(request.deps, 'statementCache');
  if (cache === undefined) {
    emitCacheEvent(request, 'cold');
    return request.verify(await request.fetchJwt()).value;
  }

  const { key, nowSeconds } = request;
  // エントリ参照は副作用の無い読み取りなので negative cache の判定より前に置く。記憶済みの取得失敗に
  // 命中した経路でも stale な JWT を FO-6 の代替候補として提示するため。後置きにすると
  // negative が生きている 30 秒だけ FO-6 が発動せず、継続的な障害中に通過と拒否が周期的に入れ替わる。
  const entry = cache.get(key, nowSeconds);
  // FO-6 の代替候補（`staleJwt`）に差し出してよいのは **TTL 切れのエントリだけ**。
  // 時計の巻き戻りで negative cache が生きたまま `entry.expired` が `false` に
  // 戻ると、新鮮なエントリが「stale な代替」として FO-6 の判定に誤って回ってしまうため。
  const staleEntryJwt = entry?.expired === true ? entry.value : undefined;
  const remembered = cache.getNegative(key, nowSeconds);
  if (remembered !== undefined) {
    emitCacheEvent(request, 'hot');
    return failOrSubstitute(request, remembered, staleEntryJwt);
  }
  if (entry !== undefined && !entry.expired) {
    emitCacheEvent(request, 'hot');
    // キャッシュ命中でも検証は必ずやり直す（署名・`iss`/`sub`・有効期間を素通りさせない）。
    return request.verify(entry.value).value;
  }
  emitCacheEvent(request, entry === undefined ? 'cold' : 'warm');

  let jwt: string;
  try {
    jwt = await request.fetchJwt();
  } catch (error) {
    // 取得の内側で起きた失敗（HTTP / ネットワーク / DNS）のみ 30 秒記憶する。
    // 検証由来の失敗はこの try の外で起きるため、決して記憶されない。
    cache.setNegative(key, error, nowSeconds);
    return failOrSubstitute(request, error, staleEntryJwt);
  }
  const verified = request.verify(jwt);
  // 取得と検証に成功したので格納する（同キーの negative エントリは `set` が破棄する）。
  cache.set(
    key,
    jwt,
    statementCacheTtlSeconds(verified.statement, nowSeconds, maxTtlSeconds),
    nowSeconds,
    jwt.length, // 総保持量の上限に本文長を計上する。
  );
  return verified.value;
}
