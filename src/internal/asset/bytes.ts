/**
 * `Uint8Array` 系の依存ゼロ純粋関数の SSOT。
 *
 * `concatBytes`: `rlp.ts` / `eth-signing.ts` / `auth/jwe/ecdh.ts` / `didcomm/jwe-primitives.ts` /
 * `keymanager/shamir/cipher.ts` に、「合計長を計算 → `new Uint8Array(total)` → `set` しながら
 * offset を進める」という同一アルゴリズムがほぼ同一のまま重複実装されていたため、ここへ集約した
 * （`hex-codec.ts`。依存ゼロの純粋関数のため、他ドメインのモジュールからの
 * import も問題ない。`eth-signing.ts` が `keymanager/address.ts` の `keccak256` を
 * cross-import しているのと同じ扱い）。
 *
 * `toBufferSource` は `didcomm`・`keymanager`・`auth/jwe` から使えるよう、
 * いずれにも依存しない共通関数としてここに置く。
 *
 * `src/internal/` 直下ではなく `asset/` に置くのは、linterly の 1 ディレクトリ行数上限
 * （`.linterly.yml` の `max_lines_per_directory`）を `src/internal/` 直下がすでに
 * warning_threshold 間際まで消費しているため（新規ファイル追加で誤って error 化させないための
 * 配置。`hex-codec.ts` と同じ場所を再利用するだけで新規ディレクトリは作らない）。
 */

/** 複数の `Uint8Array` を連結する。 */
export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * 公開 API の `Uint8Array`（`ArrayBufferLike` バッキング）を、Web Crypto の `BufferSource`
 * が要求する `ArrayBuffer` バッキングのビューへ正規化する。
 *
 * 既に `ArrayBuffer` 上のビューならゼロコピーでそのまま返し、`SharedArrayBuffer` 等の場合のみ
 * 連続領域へコピーする。これにより DOM 型（`BufferSource`）との整合と SAB 非対応を両立する。
 *
 * @param bytes 任意の `Uint8Array`。
 * @returns `ArrayBuffer` バッキングの `Uint8Array`。
 */
export function toBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes.buffer instanceof ArrayBuffer
    ? (bytes as Uint8Array<ArrayBuffer>)
    : Uint8Array.from(bytes);
}
