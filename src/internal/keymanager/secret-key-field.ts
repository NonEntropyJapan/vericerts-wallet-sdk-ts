/**
 * `KeyManager` が返す鍵ペア（`KeyPair` / `P256KeyPair`）の `privateKey` を「うっかり出力」から守る封。
 *
 * JSON やログ出力から秘密鍵を除外するため、公開型の形
 * （`interface KeyPair` / `P256KeyPair`）は変えず、生成点で `privateKey` を**列挙不可・書き換え不可・再定義不可の
 * own データプロパティ**にして次の経路で出ないようにする。
 *
 * - `JSON.stringify` / `Object.keys` / `Object.entries` / スプレッド / `for…in` / `Object.assign`
 * - `structuredClone` / `postMessage`（構造化複製は列挙可能な own プロパティだけを複製する）
 * - Node / Bun の `util.inspect`（`showHidden: true` を含む。下記の inspect.custom が優先される）
 *
 * ブラウザの DevTools（`console.log`）は非列挙の own プロパティも展開しうるので、上の経路では防げない（鍵ペアをそのまま
 * ログへ渡さない）。
 *
 * `toJSON` は定義しない。列挙不可で足り、`toJSON` は `structuredClone` に効かないので「対策済み」に見せるだけになる。
 * `keyPair.privateKey` の**明示的な**参照は従来どおり同一の `Uint8Array` を返す（署名・`zeroize`・拡張の
 * `withPseudonymMasterSeed` が使う）。`Reflect.ownKeys` / `Object.getOwnPropertyNames` からは隠さない
 * （明示的な参照まで隠すことは目的ではない）。
 */

import { defineDataProperty } from '../prototype-safety/define-data-property.js';
import type { RegisteredKeyPair } from './types.js';

/** Node / Bun の `util.inspect` が参照する、グローバル Symbol レジストリ上のカスタム検査フック。 */
const INSPECT_CUSTOM = Symbol.for('nodejs.util.inspect.custom');

/**
 * 鍵ペアの `privateKey` を封じ、inspect 表示を `id`（と `address`）だけにして返す。
 *
 * `privateKey` の配列は複製せず同一参照のまま残す（レジストリの同一性・`zeroize` の `fill(0)` を保つ）。
 * 凍結はしない（`writable: false` / `configurable: false` は `privateKey` の参照にだけ掛かり、配列の中身は
 * `zeroize` が消去できる）。属性の定義は `defineDataProperty`（プロトタイプ汚染に強い記述子の組み立て）を使う。
 *
 * @param keyPair `privateKey` を含む、組み立て直後の鍵ペア（呼び出し元が所有する新規オブジェクト）。
 * @returns 渡した `keyPair` そのもの。
 */
export function sealPrivateKey<T extends RegisteredKeyPair>(keyPair: T): T {
  const privateKey = keyPair.privateKey;
  defineDataProperty(keyPair, 'privateKey', privateKey, {
    enumerable: false,
    writable: false,
    configurable: false,
  });
  const label =
    keyPair.algorithm === 'secp256k1'
      ? `[KeyPair id=${keyPair.id} address=${keyPair.address}]`
      : `[P256KeyPair id=${keyPair.id}]`;
  defineDataProperty(keyPair, INSPECT_CUSTOM, () => label, {
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return keyPair;
}
