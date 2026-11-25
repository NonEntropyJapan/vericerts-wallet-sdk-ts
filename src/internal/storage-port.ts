/**
 * 永続化バックエンドのポート（`Storage` インターフェース）。
 *
 * **配置**: `src/internal` 直下の横断ヘルパー。
 * `keymanager`（Foundation）の `keymanager.ts` / `vault/mnemonic-vault.ts` が受け取る鍵素材の
 * 保管先としてこの契約を必要とするが、実体を公開 API の `src/storage` に置くと
 * Foundation → 公開API の逆方向依存になる。
 * 依存性逆転の原則どおり、**契約は利用側の下位レイヤーが持ち、実装が上位から満たす**形にする。
 *
 * 公開 API `src/storage/storage.ts` は本インターフェースをそのまま再エクスポートするため、
 * 利用者から見た `Storage` の import 元と型は変わらない。実装（`MemoryStorage`）は
 * 引き続き `src/storage` にある。
 */

/**
 * バイト列を格納する環境非依存の KV ストレージ抽象。
 *
 * 注: モジュール export 宣言が優先されるため、DOM global の `Storage` とは衝突しない。
 */
export interface Storage {
  /**
   * キーに対応する値を返す。未存在の場合は `null`。
   *
   * @param key 取得するキー。
   * @returns 格納されているバイト列、または未存在時 `null`。
   */
  get(key: string): Promise<Uint8Array | null>;
  /**
   * キーに値を格納する。既存の同一キーは上書きする。
   *
   * @param key 格納先キー。
   * @param value 格納するバイト列。
   */
  set(key: string, value: Uint8Array): Promise<void>;
  /**
   * キーに対応する値を削除する。未存在でも例外を投げない（冪等）。
   *
   * @param key 削除するキー。
   */
  delete(key: string): Promise<void>;
  /**
   * 指定 prefix に前方一致するキーの一覧を返す。
   *
   * @param prefix 前方一致させる prefix。空文字列は全件にマッチする。
   * @returns 一致したキーの配列（該当なしは空配列）。
   */
  list(prefix: string): Promise<string[]>;
}
