/**
 * 汎用 TTL キャッシュ（トランスポート非依存・インメモリ・永続化なし）。
 *
 * キャッシュの基本動作（`Cache-Control` 尊重 + 上限キャップ +
 * negative cache 30 秒固定）を、対象リソースに依存しないプリミティブとして提供する。
 * DID Document（did:web）・Token Status List・Federation Entity
 * Statementはいずれも「TTL 上限が異なるだけの同じ戦略」であるため、上限秒数と
 * 時計を注入で受け取り、対象固有の判断（どのエラーを negative cache するか等）は呼び出し側に残す。
 *
 * 永続化しないのは意図的である。プロセス再起動でキャッシュが消えれば必ず再取得が走るため、
 * 失効・鍵無効化の反映が遅れる方向には倒れない（fail-closed 側）。
 *
 * セキュリティ上の注意:
 * - キーは URL や DID 文字列になり得るため、本モジュールはキーをログ出力せず、
 *   例外メッセージや `context` にも含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { assertFiniteClock } from './system-clock.js';

/**
 * negative cache（404 / DNS 失敗などの取得失敗）の TTL（秒）。
 *
 * 404 / DNS 失敗の negative cache は 30 秒固定。
 * 固定値であり設定で変更できない。短すぎれば障害中の再取得が濫発し、長すぎれば復旧後も
 * 失敗を返し続けるため、上流仕様が単一の値に固定している。
 */
export const NEGATIVE_CACHE_TTL_SECONDS = 30;

/**
 * キャッシュ観測用の状態ラベル（`cache` ラベル許容値）。
 *
 * - `cold`: エントリ無し → ネットワーク取得した（ネットワークレイテンシを含む）。
 * - `warm`: エントリはあったが TTL 切れ（stale）→ 再取得した（staleness の観測点）。
 * - `hot`: TTL 内のエントリをそのまま返した（ネットワーク I/O 無し）。
 *
 * 「キャッシュ無し」「キャッシュ失効」「キャッシュ命中」を 3 分割するのは、
 * `vericerts_did_resolve_duration_seconds` のようなレイテンシヒストグラムを意味のあるものに
 * するためである。cold と warm を混ぜるとネットワーク往復の分布が読めず、warm と hot を混ぜると
 * staleness（どれだけの割合が TTL 切れで再取得しているか）が観測できなくなる。
 * span `did.resolve` の `did.cache_hit` は状態が `hot` のときに限り true になる。
 */
export type CacheState = 'cold' | 'warm' | 'hot';

/**
 * キャッシュ経由で得た値と、その取得経路の組。
 *
 * 「値」と「どう得たか」を分離して持ち回ると観測点で取り違えるため、対にして返すための型。
 * did:webは観測を `onCacheEvent` フックで行うためこの型を使わないが、
 * 値と状態を同時に呼び出し側へ返す利用側が共有する。
 */
export interface CacheHit<T> {
  /** 取得できた値。 */
  readonly value: T;
  /** 値の取得経路（`cold` / `warm` は再取得済み、`hot` はキャッシュそのまま）。 */
  readonly state: CacheState;
}

/**
 * `Cache-Control` ヘッダから `max-age` の秒数を取り出す。
 *
 * `no-store` / `no-cache` はキャッシュ不可を意味するため 0 を返す（呼び出しごとに再取得）。
 * `max-age` が無い / 数値でない場合は `undefined`（呼び出し側の既定 TTL に委ねる）。
 *
 * @param header `Cache-Control` ヘッダ値（未設定なら null / undefined）。
 * @returns `max-age` 秒数、キャッシュ不可なら 0、判定不能なら undefined。
 */
export function parseMaxAgeSeconds(header: string | null | undefined): number | undefined {
  if (header === null || header === undefined) {
    return undefined;
  }
  const directives = header.toLowerCase().split(',');
  const normalized = directives.map((d) => d.trim());
  if (normalized.includes('no-store') || normalized.includes('no-cache')) {
    return 0;
  }
  for (const directive of normalized) {
    // 開き引用符と閉じ引用符は対で受理する（一方だけの不整合は不正値として弾く）。
    const match = /^max-age\s*=\s*(?:"(\d+)"|(\d+))$/.exec(directive);
    const value = match?.[1] ?? match?.[2];
    if (value !== undefined) {
      return Number.parseInt(value, 10);
    }
  }
  return undefined;
}

/** 値が TTL（秒）として妥当（有限の非負整数）かを検証する。 */
function assertTtlSeconds(value: number): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
}

/**
 * SDK 利用者が指定した TTL 上限を、ハードキャップに照らして採用可否判定する。
 *
 * 「上限値を緩める設定を拒否し、厳しくする設定のみ許可する」という要件の実装点である。
 * 上限超過を黙って切り詰める（clamp）のではなく**拒否する**のが要点で、キャップを緩めたつもりの
 * 呼び出し側が「効いているつもりの設定が無視されている」状態で運用に入るのを防ぐ。
 *
 * なお、これは**SDK 利用者の設定**に対する規律である。**配信側（サーバ）が返す `Cache-Control:
 * max-age`** が上限を超える場合は拒否ではなくキャップする（呼び出し側は配信側の設定ミスを
 * 制御できないため、解決自体を失敗させない）。両者は別物として扱う。
 *
 * @param requested 呼び出し側が指定した TTL 上限（秒）。未指定なら `hardCapSeconds` を採用。
 * @param hardCapSeconds 仕様が定めるハードキャップ（秒）。
 * @returns 採用する TTL 上限（秒）。常に `hardCapSeconds` 以下。
 * @throws 上限超過・非負整数でない場合（VericertsError、code `3002`）。
 */
export function resolveMaxTtlSeconds(
  requested: number | undefined,
  hardCapSeconds: number,
): number {
  assertTtlSeconds(hardCapSeconds);
  if (requested === undefined) {
    return hardCapSeconds;
  }
  assertTtlSeconds(requested);
  if (requested > hardCapSeconds) {
    // 緩和方向の上書きは拒否する（要件: 厳しくする設定のみ許可）。
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return requested;
}

/** `createTtlCache` の設定。 */
export interface TtlCacheOptions {
  /** このキャッシュが保持を許す TTL の上限（秒）。`set` の TTL はこの値で切り詰める。 */
  readonly maxTtlSeconds: number;
  /** 既定の時計（エポック秒）。`get` / `set` で明示指定が無い場合に使う。 */
  readonly nowSeconds: () => number;
  /** 保持する最大エントリ数（既定 `DEFAULT_CACHE_MAX_ENTRIES`）。超過分は古い順に捨てる。 */
  readonly maxEntries?: number;
  /**
   * 正エントリの重み（`set` の `weight`）の合計上限（既定: 無制限）。値のサイズが攻撃者制御で、
   * 件数だけでは保持メモリを抑えられないキャッシュ向け。超過分は古い順に捨て、
   * 単独で上限を超える値は格納しない。
   */
  readonly maxTotalWeight?: number;
}

/** `maxEntries` の既定値（メモリ上界を与えるためのもので、仕様値ではない）。 */
export const DEFAULT_CACHE_MAX_ENTRIES = 256;

/**
 * 文字列本文（Status List Token / Entity Statement JWT / TSL XML）を保持する TTL キャッシュの総量上限（文字数）。
 * 件数 256 だけでは 1 MiB × 256 件を保持できてしまうため、`set` の `weight` に本文長を渡して総量でも抑える。
 */
export const STRING_CACHE_MAX_TOTAL_LENGTH = 32 * 1024 * 1024;

/** TTL キャッシュ本体のインターフェース。 */
export interface TtlCache<T> {
  /**
   * 正エントリを引く。TTL 切れでもエントリがあれば `expired: true` で返す
   * （呼び出し側が `warm` を観測できるようにするため、失効時に握り潰さない）。
   */
  get(key: string, nowSeconds?: number): { value: T; expired: boolean } | undefined;
  /**
   * 正エントリを格納する。`ttlSeconds <= 0` の場合は格納しない
   * （`no-store` / `no-cache` を尊重する）。いずれの場合も同キーの negative エントリは消す。
   * `weight`（既定 0）は `maxTotalWeight` の計上値で、単独で上限を超える値も格納しない。
   */
  set(key: string, value: T, ttlSeconds: number, nowSeconds?: number, weight?: number): void;
  /** 取得失敗を `NEGATIVE_CACHE_TTL_SECONDS`（30 秒固定）だけ記憶する。 */
  setNegative(key: string, error: unknown, nowSeconds?: number): void;
  /** 記憶済みの取得失敗を引く。TTL 切れなら破棄して `undefined` を返す。 */
  getNegative(key: string, nowSeconds?: number): unknown | undefined;
  /** 指定キーの正・negative 両エントリを削除する。 */
  delete(key: string): void;
  /** 全エントリを削除する。 */
  clear(): void;
  /** 保持中の正エントリ数（negative エントリは含まない）。 */
  readonly size: number;
}

/** 内部エントリ（値と失効時刻）。 */
interface Entry<T> {
  readonly value: T;
  readonly expiresAtSeconds: number;
  /** `set` に渡された重み（総量上限の計上用。negative は 0）。 */
  readonly weight: number;
}

/** `map` を `maxEntries` 以下に保つ（挿入順＝古い順に捨てる FIFO）。 */
function evictOldest(map: Map<string, unknown>, maxEntries: number): void {
  while (map.size > maxEntries) {
    const oldest = map.keys().next();
    if (oldest.done === true) {
      return;
    }
    map.delete(oldest.value);
  }
}

/**
 * TTL キャッシュを生成する。
 *
 * 正エントリと negative エントリは別々の Map に保持する。分離しておくことで、取得成功時に
 * 「値を格納する」と「記憶していた失敗を消す」を取り違えずに両立できる（成功したのに
 * negative が残って以後 30 秒失敗し続ける、という事故を構造的に防ぐ）。
 *
 * @param opts TTL 上限・時計・最大エントリ数。
 * @returns TTL キャッシュ。
 * @throws TTL 上限が非負整数でない場合（VericertsError、code `3002`）。
 */
export function createTtlCache<T>(opts: TtlCacheOptions): TtlCache<T> {
  assertTtlSeconds(opts.maxTtlSeconds);
  // 上限は own 限定（`Object.prototype.maxEntries` / `maxTotalWeight` の汚染で容量上限が差し替わらない）。
  const maxEntries = ownProperty<number>(opts, 'maxEntries') ?? DEFAULT_CACHE_MAX_ENTRIES;
  assertTtlSeconds(maxEntries);
  const ownMaxTotalWeight = ownProperty<number>(opts, 'maxTotalWeight');
  const maxTotalWeight = ownMaxTotalWeight ?? Number.POSITIVE_INFINITY;
  if (ownMaxTotalWeight !== undefined) {
    assertTtlSeconds(ownMaxTotalWeight);
  }
  const positive = new Map<string, Entry<T>>();
  const negative = new Map<string, Entry<unknown>>();
  /** 正エントリの重みの合計（`maxTotalWeight` の判定用）。 */
  let positiveWeight = 0;
  const removePositive = (key: string): void => {
    const removed = positive.get(key);
    if (removed !== undefined) {
      positiveWeight -= removed.weight;
      positive.delete(key);
    }
  };
  // NaN の時刻は `now >= expiresAt` を常に false にして期限切れエントリを「新鮮」として返し、
  // `set` では `NaN` の期限（= 永久に期限切れにならない）を格納してしまう。非有限は 4015 で拒否する。
  const now = (explicit: number | undefined): number =>
    assertFiniteClock(explicit ?? opts.nowSeconds());

  return {
    get(key: string, nowSeconds?: number): { value: T; expired: boolean } | undefined {
      const entry = positive.get(key);
      if (entry === undefined) {
        return undefined;
      }
      // 失効判定は境界を含む: `now === expiresAtSeconds` は失効済みとして扱う。
      return { value: entry.value, expired: now(nowSeconds) >= entry.expiresAtSeconds };
    },

    set(key: string, value: T, ttlSeconds: number, nowSeconds?: number, weight = 0): void {
      assertTtlSeconds(ttlSeconds);
      // 取得に成功した事実が確定しているため、格納可否に関わらず記憶した失敗は破棄する。
      negative.delete(key);
      // 挿入順を最新に揃えるため、既存キーはいったん削除してから入れ直す。
      removePositive(key);
      if (ttlSeconds === 0 || weight > maxTotalWeight) {
        // `no-store` / `no-cache` 相当。古い値を残すと失効指示の反映が遅れるため消す。
        // 重みが総量上限を超える値も（他を全て追い出しても入らないので）格納しない。
        return;
      }
      const effectiveTtl = Math.min(ttlSeconds, opts.maxTtlSeconds);
      positive.set(key, { value, expiresAtSeconds: now(nowSeconds) + effectiveTtl, weight });
      positiveWeight += weight;
      // 件数・総量の上限内に戻るまで古い順に捨てる。直前に入れた値は上限内なので残る。
      for (const oldest of positive.keys()) {
        if (positive.size <= maxEntries && positiveWeight <= maxTotalWeight) {
          break;
        }
        removePositive(oldest);
      }
    },

    setNegative(key: string, error: unknown, nowSeconds?: number): void {
      negative.delete(key);
      negative.set(key, {
        weight: 0,
        value: error,
        expiresAtSeconds: now(nowSeconds) + NEGATIVE_CACHE_TTL_SECONDS,
      });
      evictOldest(negative, maxEntries);
    },

    getNegative(key: string, nowSeconds?: number): unknown | undefined {
      const entry = negative.get(key);
      if (entry === undefined) {
        return undefined;
      }
      if (now(nowSeconds) >= entry.expiresAtSeconds) {
        // negative は `warm` を持たない（失敗をもう一度返す意味が無い）ため破棄する。
        negative.delete(key);
        return undefined;
      }
      return entry.value;
    },

    delete(key: string): void {
      removePositive(key);
      negative.delete(key);
    },

    clear(): void {
      positive.clear();
      positiveWeight = 0;
      negative.clear();
    },

    get size(): number {
      return positive.size;
    },
  };
}
