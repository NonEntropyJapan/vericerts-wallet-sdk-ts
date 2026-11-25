/**
 * seen-nonces cache による replay 検知ロジック。
 *
 * 検知ロジックは 1 実装のみを持ち、永続化は `NonceStoreAdapter` として差し替える。
 * ライフサイクルは `put`（発行記録）→ `checkAndUse`（使用記録）の 2 段構成。
 * `bloomFilter` 有効時は `adapter.get` の前段に Bloom Filter を挟む。
 */

import { assertFiniteClock } from '../../cache/system-clock.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { KeyLock } from '../../primitives/key-lock.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { BloomFilter } from './bloom-filter.js';
import { NonceCapacityManager } from './capacity/capacity.js';
import { assertBindingMatches, defaultTtlMsFor, resolveBinding } from './context.js';
import { entryKeyFrom, entryKeyPrefixFrom } from './context-keys.js';
import { assertWellFormedNonce, generateNonce } from './generate.js';
import { MemoryNonceStoreAdapter } from './memory-adapter.js';
import {
  assertValidTtl,
  DEFAULT_MAX_ENTRIES,
  DEFAULT_SWEEP_INTERVAL_MS,
  resolveBloomFilter,
} from './store-options.js';
import type {
  CheckAndUseOptions,
  NonceContext,
  NonceStore,
  NonceStoreAdapter,
  NonceStoreOptions,
  SeenNonceEntry,
} from './types.js';

/** 検知ロジック本体。`NonceStoreAdapter` を差し替えることで永続化方式を選べる。 */
class AdapterNonceStore implements NonceStore {
  readonly #adapter: NonceStoreAdapter;
  readonly #sweepIntervalMs: number;
  readonly #now: () => number;
  readonly #capacity: NonceCapacityManager;
  #lastSweepAt: number;
  /** キーごとの直列化ロック（同一 nonce の並行処理による二重消費を防ぐ）。 */
  readonly #lock = new KeyLock();
  /** `adapter.get` の前段プリフィルタ。未設定時は常に `adapter.get` へ問い合わせる。 */
  readonly #bloom: BloomFilter | undefined;
  /** `#bloom` の復元（アダプタの既存キー投入）の進行中 / 完了 Promise。未着手・失敗時は `undefined`。 */
  #bloomHydration: Promise<void> | undefined;

  constructor(adapter: NonceStoreAdapter, opts: NonceStoreOptions) {
    this.#adapter = adapter;
    // opts は own 限定で読む。`Object.prototype.now` / `adapter` / `maxEntries` の汚染で
    // 注入クロック・永続化先・容量上限（= リプレイ保護の前提）が差し替わらないようにする。
    this.#sweepIntervalMs =
      ownProperty<number>(opts, 'sweepIntervalMs') ?? DEFAULT_SWEEP_INTERVAL_MS;
    // 注入クロックが NaN を返すと `existing.expiresAt > now` が常に false になり、
    // 既知 nonce を「初見」として再受理する（リプレイ fail-open）。非有限な時刻は fail-closed で拒否する。
    const injectedNow = nonObjectPrototypeProperty<() => number>(opts, 'now');
    this.#now =
      injectedNow === undefined ? () => Date.now() : () => assertFiniteClock(injectedNow());
    this.#capacity = new NonceCapacityManager(
      this.#adapter,
      ownProperty<number>(opts, 'maxEntries') ?? DEFAULT_MAX_ENTRIES,
      this.#now,
      nonObjectPrototypeProperty<NonceStoreOptions['onEvict']>(opts, 'onEvict'),
      this.#lock,
    );
    this.#lastSweepAt = this.#now();
    this.#bloom = resolveBloomFilter(opts);
  }

  /**
   * 永続アダプタの既存キーでプリフィルタを 1 度だけ復元する。
   *
   * フィルタはメモリ上の空から始まるため、復元しないとプロセス再起動後に永続ストア上の消費済み
   * nonce が「絶対に無い」と判定され、`checkAndUse` が初見扱いで受理してしまう（リプレイ許可）。
   * 失敗（`entries()` の reject）はキャッシュせず、次回アクセスで再試行する（fail-closed）。
   */
  #hydrateBloom(bloom: BloomFilter): Promise<void> {
    if (this.#bloomHydration === undefined) {
      this.#bloomHydration = this.#adapter.entries().then(
        (all) => {
          for (const [key] of all) bloom.add(key);
        },
        (error: unknown) => {
          this.#bloomHydration = undefined;
          throw error;
        },
      );
    }
    return this.#bloomHydration;
  }

  /**
   * `adapter.get` の前段プリフィルタ。
   *
   * Bloom Filter が「絶対に無い」と判定できる場合に限りアダプタ問い合わせを省く。フィルタは
   * 初回アクセス時にアダプタの既存キーから復元し（`#hydrateBloom`）、以降は追加のみで削除しないため、
   * 退避済みキーを誤って「あるかもしれない」と判定することはあっても、実在するキーを「無い」と誤判定
   * すること（偽陰性）は起こらない。前提: バックエンドへ書き込むのはこのストアだけ（他プロセスの
   * 書き込みはフィルタに反映されない）。無効時は常にアダプタへ問い合わせる。
   */
  async #getExisting(key: string): Promise<SeenNonceEntry | undefined> {
    if (this.#bloom !== undefined) {
      await this.#hydrateBloom(this.#bloom);
      if (!this.#bloom.mightContain(key)) {
        return undefined;
      }
    }
    return await this.#adapter.get(key);
  }

  /**
   * CSPRNG で nonce を生成する。
   *
   * @param byteLength 生成するバイト数。既定 16（= 128 bit）。
   * @returns base64url（パディング無し）の nonce。
   */
  generate(byteLength: 16 | 32 = 16): string {
    return generateNonce(byteLength);
  }

  /**
   * 発行した nonce を TTL 付きで記録する。
   *
   * 未失効の同一エントリが既に存在する場合は nonce 一意性の破れとして 4010 を投げる。
   * 上書きを許すと消費済みフラグが消え、リプレイ検知を回避できてしまうため。
   *
   * @param nonce 発行した nonce。
   * @param ctx 発行コンテキスト。
   * @param ttlMs 保持期間（ms）。
   * @throws `NONCE_MALFORMED`（4013）/ `REPLAY_DETECTED`（4010）/ `RangeError`。
   */
  async put(nonce: string, ctx: NonceContext, ttlMs: number): Promise<void> {
    assertWellFormedNonce(nonce);
    assertValidTtl(ttlMs);
    // `flow` と束縛値は 1 パスで 1 度だけ読み、キーはその読み取り結果から組み立てる（詳細は `checkAndUse`）。
    const { flow, value: binding } = resolveBinding(ctx);
    // エントリキーは容量スコープの接頭辞 ＋ nonce（この不変条件が `NonceCapacityManager` の
    // `enforceCapacity` の `startsWith` によるスコープ判定と一致していることが LRU 退避の前提）。
    const prefix = entryKeyPrefixFrom(flow, binding);
    const key = `${prefix}${nonce}`;

    await this.#lock.run(key, async () => {
      // 遅延 sweep より先に対象エントリを読む。順序を逆にすると、判定対象そのものを
      // sweep が消してしまい「期限切れ（4011）」が「初見」に化ける。
      const now = this.#now();
      const existing = await this.#getExisting(key);
      if (existing !== undefined && existing.expiresAt > now) {
        throw new VericertsError(ErrorCodes.REPLAY_DETECTED);
      }

      await this.#capacity.enforceCapacity(prefix, key);
      await this.#adapter.set(key, {
        nonce,
        context: ctx,
        firstSeenAt: now,
        expiresAt: now + ttlMs,
      });
      this.#bloom?.add(key);
      await this.#maybeSweep();
    });
  }

  /**
   * nonce を消費する。
   *
   * 未発行の nonce は初見として受理し、消費済みとして記録する。有効期間内に同じコンテキストで再度消費すると 4010 になる。
   *
   * @param nonce 消費する nonce。
   * @param ctx 発行コンテキスト。
   * @param opts バインディング実測値と初見時 TTL。
   * @throws 4013 形式不正 / 4012 バインディング不一致 / 4011 期限切れ / 4010 消費済み。
   */
  async checkAndUse(
    nonce: string,
    ctx: NonceContext,
    opts: CheckAndUseOptions = {},
  ): Promise<void> {
    assertWellFormedNonce(nonce);
    // `flow` と束縛値は `resolveBinding` で 1 パス・1 度だけ読み、照合もキー組み立ても**その読み取り
    // 結果**だけで行う。照合の後に読み直すと、束縛メンバを own のアクセサとして持つ `NonceContext`
    // では読み取りごとに別値が返り得るため、束縛照合を通っていない値からキーが決まり、**照合済みの
    // 束縛値とは別のキー空間**へ消費記録が書かれる（＝拒否リストに載らず、同じ nonce をリプレイできる）。
    // replay ガード経由の `ctx` は入口でスナップショット化されている（`context-snapshot.ts`）ため
    // guard 層と値が分裂しない。本メソッドを直に呼ぶ経路では、この 1 パスが唯一の読みになる。
    const { flow, value: binding } = resolveBinding(ctx);
    // `opts` の任意プロパティも own 限定で読む。鎖読みだと `binding` を意図的に省略した
    // 正当な呼び出しが `Object.prototype.binding` の汚染値を照合対象として拾い、一律 4012 で拒否される。
    assertBindingMatches(binding, ownProperty<string>(opts, 'binding'));
    // エントリキーは容量スコープの接頭辞 ＋ nonce（不変条件は `put` のコメント）。
    const prefix = entryKeyPrefixFrom(flow, binding);
    const key = `${prefix}${nonce}`;

    // get → set を排他区間に入れる。直列化しないと同一 nonce の並行呼び出しが
    // 双方とも「未消費」を観測して二重消費できる（リプレイ検知の回避）。
    await this.#lock.run(key, async () => {
      const now = this.#now();
      const existing = await this.#getExisting(key);

      if (existing !== undefined) {
        if (existing.expiresAt <= now) {
          // ここでエントリを削除してはならない。判定対象が消えると、直後の再提示が
          // 「初見」として受理されリプレイが通る。削除は prune に任せる。
          throw new VericertsError(ErrorCodes.NONCE_EXPIRED);
        }
        if (ownProperty<number>(existing, 'usedAt') !== undefined) {
          throw new VericertsError(ErrorCodes.REPLAY_DETECTED);
        }
        await this.#adapter.set(key, { ...existing, usedAt: now });
        await this.#maybeSweep();
        return;
      }

      // `one-time-credential` は既定 TTL を持たず、未指定なら `RangeError`。
      // `ttlMs` も own 限定で読む。鎖読みだとその fail-closed が素通りし、`Object.prototype.ttlMs` の
      // 汚染値（例 `1`）で初見 nonce が即時失効して、prune 後の再消費が受理される（検知のバイパス）。
      const ttlMs = ownProperty<number>(opts, 'ttlMs') ?? defaultTtlMsFor(flow);
      assertValidTtl(ttlMs);
      await this.#capacity.enforceCapacity(prefix, key);
      await this.#adapter.set(key, {
        nonce,
        context: ctx,
        firstSeenAt: now,
        expiresAt: now + ttlMs,
        usedAt: now,
      });
      this.#bloom?.add(key);
      await this.#maybeSweep();
    });
  }

  /**
   * 該当 nonce が消費済みとして記録されているかを返す。
   *
   * @param nonce 判定対象。
   * @param ctx 発行コンテキスト。
   * @returns 未失効かつ消費済みなら `true`。
   */
  async has(nonce: string, ctx: NonceContext): Promise<boolean> {
    // キーの組み立ては `checkAndUse` と同一の 1 回読みで行う（読み方が違うと、消費記録を書いた
    // キー空間と問い合わせるキー空間がずれて「消費済み」を取りこぼす）。接頭辞は不要なので `*From` を直に使う。
    const { flow, value: binding } = resolveBinding(ctx);
    const entry = await this.#getExisting(entryKeyFrom(nonce, flow, binding));
    if (entry === undefined || ownProperty<number>(entry, 'usedAt') === undefined) {
      return false;
    }
    return entry.expiresAt > this.#now();
  }

  /**
   * 期限切れエントリを削除する。
   *
   * アダプタが `pruneExpired` を持つならそちらへ委譲し、全件をアプリケーションプロセスへ
   * 引き上げない（redis は native TTL に任せ、sqlite は条件付き DELETE 1 発で済む）。
   *
   * @returns 削除した件数（`pruneExpired` に委譲した場合はアダプタの申告値）。
   */
  async prune(): Promise<number> {
    const now = this.#now();
    this.#lastSweepAt = now;
    if (this.#capacity.canSkipEntryFetch() && this.#adapter.pruneExpired !== undefined) {
      return await this.#adapter.pruneExpired(now);
    }
    let removed = 0;
    for (const [key, entry] of await this.#adapter.entries()) {
      // スナップショットの `expiresAt` は候補選びにだけ使い、削除はキーロック下の再読込で決める。
      if (entry.expiresAt <= now && (await this.#capacity.evictExpired(key))) {
        removed += 1;
      }
    }
    return removed;
  }

  /** 前回 sweep から `sweepIntervalMs` 以上経過していれば prune する（遅延 sweep）。 */
  async #maybeSweep(): Promise<void> {
    if (this.#now() - this.#lastSweepAt >= this.#sweepIntervalMs) {
      await this.prune();
    }
  }
}

/**
 * `NonceStore` を生成するモジュールレベル関数。
 *
 * `backend: 'memory'` は SDK 内蔵のインメモリ実装を使う。`indexeddb` / `redis` / `sqlite` は
 * ステートフルな永続実装を SDK が持たない方針のため、`adapter` の注入が必須。
 *
 * @param opts バックエンド種別・上限・sweep 間隔・注入アダプタ。
 * @returns 検知ロジックを備えた `NonceStore`。
 * @throws `TypeError` `memory` 以外のバックエンドで `adapter` が未指定の場合。
 */
export function createNonceStore(opts: NonceStoreOptions): NonceStore {
  const adapter = nonObjectPrototypeProperty<NonceStoreAdapter>(opts, 'adapter');
  if (opts.backend === 'memory') {
    return new AdapterNonceStore(adapter ?? new MemoryNonceStoreAdapter(), opts);
  }
  if (adapter === undefined) {
    throw new TypeError(
      `backend "${opts.backend}" には NonceStoreAdapter の注入が必要です（SDK は永続実装を持ちません）`,
    );
  }
  return new AdapterNonceStore(adapter, opts);
}
