/**
 * キー単位の直列化ロック。
 *
 * `checkAndUse` / `put` は `adapter.get()` と `adapter.set()` の間で await を挟むため、
 * ロック無しでは同一 nonce の並行呼び出しが双方とも「未消費」を観測して二重消費できる
 * （リプレイ検知の完全な回避）。本モジュールは同一キーの処理を Promise チェーンで直列化する。
 *
 * **本ロックは単一プロセス内でのみ有効。** 複数プロセス / 複数インスタンスで同じバックエンドを
 * 共有する場合は、アダプタ側で `get` → `set` の原子性を保証する必要がある。
 */

/** 待ち行列を繋ぐためだけの no-op（失敗を握りつぶして後続をブロックしない）。 */
function noop(): void {
  // 直列化チェーンの継続専用。値も例外も伝播させない。
}

/** キーごとに処理を直列化するロック。 */
export class KeyLock {
  readonly #chains = new Map<string, Promise<void>>();

  /**
   * 同一キーの処理を直列化して実行する。
   *
   * 異なるキーは互いにブロックしない。待ち行列が空になったキーは Map から除去するため、
   * キーが増え続けてもリークしない。
   *
   * @param key 直列化の単位。
   * @param fn 排他区間で実行する処理。
   * @returns `fn` の戻り値（`fn` が投げた例外はそのまま伝播する）。
   */
  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.#chains.get(key) ?? Promise.resolve();
    // 前段の成否に関わらず、順番が来たら実行する。
    const current = previous.then(fn, fn);
    const chained = current.then(noop, noop);
    this.#chains.set(key, chained);
    try {
      return await current;
    } finally {
      // 自分が待ち行列の最後尾なら削除する。
      if (this.#chains.get(key) === chained) {
        this.#chains.delete(key);
      }
    }
  }

  /**
   * 同一キーの処理が進行中・待機中でなければ実行し、そうでなければ待たずに `{ ran: false }` を返す。
   *
   * 排他区間の中から**別キー**のロックを取る用途専用。`run` で待つと、2 つの排他区間が互いの
   * キーを待ち合って（A が B を、B が A を待つ）デッドロックし得る。待たない取得ならその循環が
   * 起きない。実行できた場合の直列化・解放は `run` と同じ。
   *
   * @param key 直列化の単位。
   * @param fn 排他区間で実行する処理。
   * @returns 実行した場合は `{ ran: true, value }`、キーが使用中なら `{ ran: false }`。
   */
  async tryRun<T>(
    key: string,
    fn: () => Promise<T>,
  ): Promise<{ readonly ran: true; readonly value: T } | { readonly ran: false }> {
    if (this.#chains.has(key)) {
      return { ran: false };
    }
    return { ran: true, value: await this.run(key, fn) };
  }

  /** 待機中のキー数（テスト・診断用。リーク検知に使う）。 */
  get pendingKeys(): number {
    return this.#chains.size;
  }
}
