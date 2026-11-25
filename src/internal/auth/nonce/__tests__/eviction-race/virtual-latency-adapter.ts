/**
 * 仮想時間で動くレイテンシ付き `NonceStoreAdapter`（退避 / sweep と `checkAndUse` の並行競合テスト用）。
 *
 * 実時間（`setTimeout`）には一切依存しない。各アダプタ操作は `VirtualClock#sleep` で「1 往復分」の
 * 仮想 ms を待ち、テスト側が `advance` / `runAll` で時刻を手動で進める。await ポイントの並び順が
 * 仮想時刻だけで決まるため、並行タイミング（位相）を 0〜8 ms ずらしても完全に決定的に再現できる。
 */

import { MemoryNonceStoreAdapter } from '../../memory-adapter.js';
import type { NonceStoreAdapter, SeenNonceEntry } from '../../types.js';

/** マイクロタスクを十分に流し切る（仮想タイマーの発火間で Promise 連鎖を進める）。 */
async function settle(): Promise<void> {
  for (let i = 0; i < 200; i += 1) {
    await Promise.resolve();
  }
}

interface Timer {
  readonly at: number;
  readonly resolve: () => void;
}

/** 手動で進める仮想クロック。同時刻のタイマーは登録順に発火する。 */
export class VirtualClock {
  #now = 0;
  #timers: Timer[] = [];

  /** 仮想 `ms` 経過後に解決する Promise。 */
  sleep(ms: number): Promise<void> {
    const { promise, resolve } = Promise.withResolvers<void>();
    this.#timers.push({ at: this.#now + ms, resolve });
    return promise;
  }

  /** 仮想時刻を `ms` 進め、その間に満期となったタイマーを順に発火する。 */
  async advance(ms: number): Promise<void> {
    const target = this.#now + ms;
    await settle();
    for (;;) {
      const due = this.#timers.filter((t) => t.at <= target);
      if (due.length === 0) {
        break;
      }
      const next = Math.min(...due.map((t) => t.at));
      this.#now = next;
      const firing = this.#timers.filter((t) => t.at <= next);
      this.#timers = this.#timers.filter((t) => t.at > next);
      for (const timer of firing) {
        timer.resolve();
        await settle();
      }
    }
    this.#now = target;
    await settle();
  }

  /** 待機中のタイマーが無くなるまで進める。 */
  async runAll(): Promise<void> {
    await settle();
    while (this.#timers.length > 0) {
      await this.advance(Math.min(...this.#timers.map((t) => t.at)) - this.#now);
    }
  }
}

/**
 * 全操作が `latencyMs`（仮想）の往復を要するアダプタ。効果は待機後に適用される。`delete` だけ
 * `deleteLatencyMs` に伸ばせる（「古いスナップショットに基づく削除が遅れて着弾する」窓を広げる）。
 */
export class VirtualLatencyAdapter implements NonceStoreAdapter {
  readonly inner = new MemoryNonceStoreAdapter();
  readonly #clock: VirtualClock;
  readonly #latencyMs: number;
  readonly #deleteLatencyMs: number;

  constructor(clock: VirtualClock, latencyMs: number, deleteLatencyMs = latencyMs) {
    this.#clock = clock;
    this.#latencyMs = latencyMs;
    this.#deleteLatencyMs = deleteLatencyMs;
  }

  async get(key: string): Promise<SeenNonceEntry | undefined> {
    await this.#clock.sleep(this.#latencyMs);
    return await this.inner.get(key);
  }
  async set(key: string, entry: SeenNonceEntry): Promise<void> {
    await this.#clock.sleep(this.#latencyMs);
    await this.inner.set(key, entry);
  }
  async delete(key: string): Promise<void> {
    await this.#clock.sleep(this.#deleteLatencyMs);
    await this.inner.delete(key);
  }
  async entries(): Promise<readonly (readonly [string, SeenNonceEntry])[]> {
    await this.#clock.sleep(this.#latencyMs);
    return await this.inner.entries();
  }
  async entriesByPrefix(prefix: string): Promise<readonly (readonly [string, SeenNonceEntry])[]> {
    await this.#clock.sleep(this.#latencyMs);
    return await this.inner.entriesByPrefix(prefix);
  }
}
