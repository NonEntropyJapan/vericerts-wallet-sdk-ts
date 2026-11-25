/**
 * 環境非依存のストレージ抽象とテスト用 in-memory 実装。
 *
 * 本モジュールは、永続化バックエンド（将来的な IndexedDB 等）の差異を隠蔽する `Storage`
 * インターフェースと、その最小実装である `MemoryStorage` を提供する。
 *
 * 責務分担:
 * - `Storage` は鍵=文字列・値=バイト列の単純な KV ストアを抽象化する。実装は環境ごとに差し替える。
 * - `MemoryStorage` は永続化を伴わない揮発的な `Map` ベース実装で、主にテスト用途を想定する。
 *   in-memory のため I/O 例外は発生せず、VericertsError は送出しない
 *   （6xxx の永続化エラーは IndexedDB 実装向けで本実装には不要）。
 */

// `Storage` の契約は横断ヘルパー `internal/storage-port.ts` が SSOT（`keymanager` が公開 API を
// import しないようにするための依存性逆転）。公開 API から見た
// import 元と型は変えないため、ここでそのまま再エクスポートする。
export type { Storage } from '../internal/storage-port.js';

import type { Storage } from '../internal/storage-port.js';

/**
 * `Map` ベースの揮発的 `Storage` 実装（テスト用）。
 *
 * 値は格納・取得の両端で防御的にコピーするため、呼び出し側が元配列や戻り値を後で
 * 変更しても内部状態は不変に保たれる。
 */
export class MemoryStorage implements Storage {
  /** キー → 格納値（防御的コピー済み）のレジストリ。 */
  private readonly store = new Map<string, Uint8Array>();

  /**
   * キーに対応する値の複製を返す。未存在の場合は `null`。
   *
   * 内部値を `slice()` した複製を返すため、戻り値を変更しても内部状態には影響しない。
   * 空のバイト列（`Uint8Array(0)`）は非 null で保持され、未存在の `null` とは区別される。
   *
   * @param key 取得するキー。
   * @returns 格納値の複製、または未存在時 `null`。
   */
  async get(key: string): Promise<Uint8Array | null> {
    const value = this.store.get(key);
    if (value === undefined) {
      return null;
    }
    // 戻り値の変更が内部状態へ波及しないよう複製を返す（ビュー共有を避けるため subarray は使わない）。
    return value.slice();
  }

  /**
   * キーに値を格納する。既存の同一キーは上書きする。
   *
   * 渡されたバイト列を `slice()` で複製して格納するため、呼び出し側が元配列を後で
   * 変更しても内部状態は不変に保たれる。
   *
   * @param key 格納先キー。
   * @param value 格納するバイト列。
   */
  async set(key: string, value: Uint8Array): Promise<void> {
    // 元配列の後続変更が内部状態へ波及しないよう複製を格納する。
    this.store.set(key, value.slice());
  }

  /**
   * キーに対応する値を削除する。未存在でも例外を投げず no-op となる（冪等）。
   *
   * @param key 削除するキー。
   */
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  /**
   * 指定 prefix に前方一致するキーの一覧を返す。
   *
   * 結果はキー昇順（`.sort()`）で返す。spec は順序未規定だが、本実装は決定的な順序を保証する。
   *
   * @param prefix 前方一致させる prefix。空文字列は全件にマッチする。
   * @returns 一致したキーの昇順配列（該当なしは空配列）。
   */
  async list(prefix: string): Promise<string[]> {
    const matched: string[] = [];
    for (const key of this.store.keys()) {
      if (key.startsWith(prefix)) {
        matched.push(key);
      }
    }
    return matched.sort();
  }
}
