/**
 * Token Status List のキャッシュ層（`status-list-resolver.ts` 専用の判断をまとめたもの）。
 *
 * - HTTP `Cache-Control: max-age` を尊重し、TTL 上限 60 秒でキャップする。
 * - negative cache（404 / DNS 失敗などの取得失敗）は 30 秒固定。
 * - Status List Token 自身の `exp` でさらに切り詰める。
 *
 * キャッシュ本体は対象非依存の `internal/cache/ttl-cache.ts`を、TTL 評価は
 * `status-list-verifier.ts` の `evaluateCacheFreshness` をそのまま使う。本モジュールが持つのは
 * Status List 固有の判断（キーの取り方・観測イベント・`fetchToken` の戻り値の正規化）だけである。
 *
 * キャッシュする値は**生の Status List Token（JWT 文字列）**にする。展開済みビット列ではなく
 * Token を持つことで、キャッシュ命中時も署名検証・`sub` 一致確認をやり直せる（キャッシュに
 * 入った時点で検証を済ませたことにしない）。
 *
 * セキュリティ上の注意:
 * - キャッシュキーは Status List URI であり、ログ・例外メッセージ・`context` には載せない。
 * 観測イベントに渡すのは状態ラベルのみ。
 */

import {
  type CacheState,
  createTtlCache,
  parseMaxAgeSeconds,
  STRING_CACHE_MAX_TOTAL_LENGTH,
  systemNowSeconds,
  type TtlCache,
} from '../cache/index.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';
import {
  DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS,
  evaluateCacheFreshness,
} from './status-list-verifier.js';

/**
 * `fetchToken` の戻り値（Token と、TTL 決定に使う `Cache-Control`）。
 *
 * `fetchToken` は素の `string` も返せる（後方互換）。その場合 `Cache-Control` は得られないため、
 * TTL は設定された上限（既定 60 秒）をそのまま採用する。
 */
export interface StatusListTokenResponse {
  /** Status List Token（コンパクト JWT 文字列）。 */
  readonly token: string;
  /** レスポンスの `Cache-Control` ヘッダ値（未取得なら undefined）。 */
  readonly cacheControl?: string | null;
}

/** キャッシュ観測イベント（`cache` ラベルに対応）。 */
export interface StatusListCacheEvent {
  /** キャッシュ状態（`cold` / `warm` / `hot`）。 */
  readonly state: CacheState;
}

/** キャッシュ参照に必要な依存（いずれも任意。未指定ならキャッシュしない）。 */
export interface StatusListCacheDeps {
  /** Status List Token のキャッシュ。未指定なら毎回取得する。 */
  readonly cache?: TtlCache<string>;
  /** キャッシュ状態の観測フック（メトリクス / span 属性の記録点）。 */
  readonly onCacheEvent?: (event: StatusListCacheEvent) => void;
}

/** キャッシュ参照の結果（3 つは排他ではなく、`stale` と `remembered` は同時に立ち得る）。 */
export interface StatusListCacheLookup {
  /** TTL 内のエントリ。そのまま使ってよい（ネットワーク I/O 不要）。 */
  readonly fresh?: string;
  /** TTL 切れのエントリ。再取得に失敗したときだけ FO-2 の材料として使う。 */
  readonly stale?: string;
  /** 記憶済みの取得失敗。ある間はネットワークに出ず、この失敗をそのまま評価に回す。 */
  readonly remembered?: unknown;
}

/**
 * Token Status List 用の TTL キャッシュを生成する。
 *
 * TTL 上限は `DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS`（60 秒）で固定する。ここを緩める設定は
 * `createStatusListResolver` の `maxTtlSeconds` が拒否するため、生成側では受け付けない。
 *
 * @param nowSeconds 時計（エポック秒）。未指定なら実時計。
 * @param maxEntries 保持する最大エントリ数（省略時はキャッシュ層の既定）。
 * @returns Status List Token 用 TTL キャッシュ。
 */
export function createStatusListCache(
  nowSeconds: () => number = systemNowSeconds,
  maxEntries?: number,
): TtlCache<string> {
  const maxTtlSeconds = DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS;
  return createTtlCache<string>(
    maxEntries === undefined
      ? { maxTtlSeconds, nowSeconds, maxTotalWeight: STRING_CACHE_MAX_TOTAL_LENGTH }
      : { maxTtlSeconds, nowSeconds, maxEntries, maxTotalWeight: STRING_CACHE_MAX_TOTAL_LENGTH },
  );
}

/**
 * `fetchToken` の戻り値を `StatusListTokenResponse` に正規化する。
 *
 * @param result Token 文字列、または Token と `Cache-Control` の組。
 * @returns 正規化した取得結果。
 */
export function normalizeTokenResponse(
  result: string | StatusListTokenResponse,
): StatusListTokenResponse {
  if (typeof result === 'string') {
    return { token: result };
  }
  // 戻り値は呼び出し側（`fetchToken`）が構築したオブジェクトであり、SDK の管理下にない。
  // そのまま素通しすると、`cacheControl` を持たない応答でもプロトタイプ鎖の汚染値が下流で
  // 拾われ、実効キャッシュ TTL に効いてしまう。境界で own 限定に読み直して**自身のプロパティ
  // だけを持つ**オブジェクトへ正規化する。
  // `token` は own 限定では読めない。`fetchToken` が `class Resp { get token() {...} }` のように
  // プロトタイプ上のアクセサで公開する**正当な実装**を弾いてしまい、`token` が undefined の
  // まま「取得失敗」として扱われる。そうなると fail-safe 設定時に FO-1 へ落ちて
  // `{ valid: true }` が返り、**取得に成功しているのに失効検査がバイパスされる**。
  // したがって `Object.prototype` 由来だけを弾く `nonObjectPrototypeProperty` を使い、
  // 文字列でなければ取得失敗として明示的に送出する（キャストで嘘をつかない）。
  const token = nonObjectPrototypeProperty<string>(result, 'token');
  if (typeof token !== 'string') {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const cacheControl = nonObjectPrototypeProperty<string | null>(result, 'cacheControl');
  return {
    token,
    ...(cacheControl === undefined ? {} : { cacheControl }),
  };
}

/**
 * キャッシュを参照し、取得経路を観測フックへ通知する。
 *
 * 状態遷移（`cache` ラベル）:
 * - TTL 内のエントリ有り → `hot`（ネットワーク I/O 無し）
 * - 記憶済みの取得失敗有り → `hot`（同じくネットワーク I/O 無し）
 * - エントリ無し → `cold`（これから取得する）
 * - エントリ有り・TTL 切れ → `warm`（これから再取得する。staleness の観測点）
 *
 * @param uri Status List URI（キャッシュキー）。
 * @param deps キャッシュ・観測フック。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @returns 有効エントリ / stale エントリ / 記憶済み失敗の有無。
 */
export function lookupCachedToken(
  uri: string,
  deps: StatusListCacheDeps,
  nowSeconds: number,
): StatusListCacheLookup {
  const cache = nonObjectPrototypeProperty<StatusListCacheDeps['cache']>(deps, 'cache');
  const onCacheEvent = nonObjectPrototypeProperty<StatusListCacheDeps['onCacheEvent']>(
    deps,
    'onCacheEvent',
  );
  if (cache === undefined) {
    onCacheEvent?.({ state: 'cold' });
    return {};
  }
  const entry = cache.get(uri, nowSeconds);
  if (entry !== undefined && !entry.expired) {
    onCacheEvent?.({ state: 'hot' });
    return { fresh: entry.value };
  }
  const remembered = cache.getNegative(uri, nowSeconds);
  if (remembered !== undefined) {
    onCacheEvent?.({ state: 'hot' });
    return { ...(entry === undefined ? {} : { stale: entry.value }), remembered };
  }
  onCacheEvent?.({ state: entry === undefined ? 'cold' : 'warm' });
  return entry === undefined ? {} : { stale: entry.value };
}

/** `cacheFetchedToken` の入力。 */
export interface CacheFetchedTokenParams {
  /** 格納先のキャッシュ。 */
  readonly cache: TtlCache<string>;
  /** Status List URI（キャッシュキー）。 */
  readonly uri: string;
  /** 署名検証済みの Status List Token。 */
  readonly token: string;
  /** レスポンスの `Cache-Control` ヘッダ値（未取得なら undefined）。 */
  readonly cacheControl?: string | null;
  /** Token の `exp`（エポック秒。妥当な整数でなければ undefined）。 */
  readonly expSeconds?: number;
  /** 採用する TTL 上限（秒）。 */
  readonly maxTtlSeconds: number;
  /** 取得時刻＝現在時刻（エポック秒）。 */
  readonly nowSeconds: number;
}

/**
 * 取得した Status List Token をキャッシュへ格納する。
 *
 * 採用 TTL は `min(Cache-Control の max-age ?? 上限, 上限)` を Token の `exp` で切り詰めた値
 * （評価は `evaluateCacheFreshness` に委ねる）。**配信側が返す過大な `max-age` はキャップする**
 * のに対し、**SDK 利用者が上限そのものを緩めようとした場合は拒否する**（`resolveMaxTtlSeconds`）。
 * 前者は制御できない他者の設定、後者は制御できる自分の設定であり、扱いを分ける。
 *
 * `no-store` / `no-cache` および `exp` 経過済みの Token は TTL 0 となり格納しない。いずれの場合も
 * 取得に成功した事実は確定しているため、同キーの negative エントリは破棄される。
 *
 * @param params キャッシュ・キー・Token・`Cache-Control`・`exp`・TTL 上限・現在時刻。
 */
export function cacheFetchedToken(params: CacheFetchedTokenParams): void {
  // 任意プロパティは自身のプロパティに限って読む。ここで継承値を新しい
  // オブジェクトリテラルへ詰め直すと own プロパティに化け、`evaluateCacheFreshness` 側の
  // own 限定読み取りが無効化される（キャッシュ TTL の実効値が汚染値に左右される）。
  const maxAgeSeconds = parseMaxAgeSeconds(ownProperty<string>(params, 'cacheControl'));
  const expSeconds = ownProperty<number>(params, 'expSeconds');
  const freshness = evaluateCacheFreshness({
    fetchedAtSeconds: params.nowSeconds,
    nowSeconds: params.nowSeconds,
    maxTtlSeconds: params.maxTtlSeconds,
    ...(maxAgeSeconds === undefined ? {} : { maxAgeSeconds }),
    ...(expSeconds === undefined ? {} : { expSeconds }),
  });
  // 本文長を重みに計上し、件数上限だけでは抑えられない総保持量を `STRING_CACHE_MAX_TOTAL_LENGTH` で抑える。
  params.cache.set(
    params.uri,
    params.token,
    freshness.remainingSeconds,
    params.nowSeconds,
    params.token.length,
  );
}
