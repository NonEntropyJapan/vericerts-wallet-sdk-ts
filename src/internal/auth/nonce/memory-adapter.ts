/**
 * インメモリの `NonceStoreAdapter` 実装。
 *
 * 単体テストと単一プロセス用途の既定実装。プロセスをまたぐ永続化はしないため、
 * 水平スケールする Verifier / Issuer では Redis 等の実装を注入すること。
 * `storage.ts` の `MemoryStorage` と同じく `Map` ベースで、挿入順を保つ。
 */

import type { NonceStoreAdapter, SeenNonceEntry } from './types.js';

/**
 * `Map` ベースの `NonceStoreAdapter`。
 *
 * `Map` は挿入順を保持するため、`entries()` は LRU 退避が前提とする順序を満たす。
 * 既存キーの `set` は挿入順を変えない（`Map` の仕様）ので、`put` → `checkAndUse` の
 * 更新でエントリが「新しい」側へ移動することはない。
 */
export class MemoryNonceStoreAdapter implements NonceStoreAdapter {
  readonly #entries = new Map<string, SeenNonceEntry>();

  /**
   * キーに対応するエントリを返す。
   *
   * @param key エントリキー。
   * @returns エントリ。無ければ `undefined`。
   */
  get(key: string): Promise<SeenNonceEntry | undefined> {
    return Promise.resolve(this.#entries.get(key));
  }

  /**
   * エントリを保存する（既存キーは上書き）。
   *
   * @param key エントリキー。
   * @param entry 保存するエントリ。
   */
  set(key: string, entry: SeenNonceEntry): Promise<void> {
    this.#entries.set(key, entry);
    return Promise.resolve();
  }

  /**
   * エントリを削除する。
   *
   * @param key エントリキー。
   */
  delete(key: string): Promise<void> {
    this.#entries.delete(key);
    return Promise.resolve();
  }

  /**
   * 保持中の全エントリを挿入順で返す。
   *
   * @returns `[key, entry]` の配列。
   */
  entries(): Promise<readonly (readonly [string, SeenNonceEntry])[]> {
    return Promise.resolve([...this.#entries.entries()]);
  }

  /**
   * 指定プレフィックスのエントリだけを挿入順で返す。
   *
   * 未実装だと `NonceStore` の容量管理が `entries()` にフォールバックし、挿入のたびに
   * キャッシュ全体を配列へコピーする。`Map` は挿入順に反復するため、
   * 前方一致するエントリを抽出しても LRU 退避の順序を保てる。
   *
   * @param prefix キーの前方一致プレフィックス。
   * @returns 一致した `[key, entry]` の配列（挿入順）。
   */
  entriesByPrefix(prefix: string): Promise<readonly (readonly [string, SeenNonceEntry])[]> {
    const matched: (readonly [string, SeenNonceEntry])[] = [];
    for (const pair of this.#entries) {
      if (pair[0].startsWith(prefix)) {
        matched.push(pair);
      }
    }
    return Promise.resolve(matched);
  }

  /**
   * 期限切れ（`expiresAt <= now`）のエントリを削除し、件数を返す。
   *
   * `Map` は反復中の `delete` が安全（削除済みキーは再訪されない）なので、`entries()` の
   * ように保持中の全エントリを配列へコピーせずに sweep できる。判定の基準時刻は
   * `NonceStore` が注入したクロックの値であり、ここで `Date.now()` を読み直さない。
   *
   * @param now 判定の基準時刻（UNIX ms）。
   * @returns 削除したエントリ数。
   */
  pruneExpired(now: number): Promise<number> {
    let removed = 0;
    for (const [key, entry] of this.#entries) {
      if (entry.expiresAt <= now) {
        this.#entries.delete(key);
        removed += 1;
      }
    }
    return Promise.resolve(removed);
  }

  /**
   * 保持中のエントリ数を返す。
   *
   * 前方一致の判定は `entriesByPrefix` と同一にすること（数え方がずれると容量管理が狂う）。
   * 期限切れエントリも数に含む（上限判定は上振れ側に倒れるだけで超過を見逃さない）。
   *
   * @param prefix キーの前方一致プレフィックス。未指定なら全件。
   * @returns 一致したエントリ数。
   */
  count(prefix?: string): Promise<number> {
    if (prefix === undefined) {
      return Promise.resolve(this.#entries.size);
    }
    let matched = 0;
    for (const key of this.#entries.keys()) {
      if (key.startsWith(prefix)) {
        matched += 1;
      }
    }
    return Promise.resolve(matched);
  }

  /** 保持中のエントリ数（テスト・診断用）。 */
  get size(): number {
    return this.#entries.size;
  }
}
