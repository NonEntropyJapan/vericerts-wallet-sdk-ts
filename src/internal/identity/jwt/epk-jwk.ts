/**
 * ECDH-ES のエフェメラル公開鍵（epk）を SEC1 非圧縮バイト列から JWK へ変換するヘルパ。
 *
 * `jwk-key.ts` の行数上限（300 行）を守るため、署名検証用の鍵変換（`jwk-key.ts`）から分離した。
 */

import { base64urlnopad } from '@scure/base';
import { EC_COORDINATE_LENGTH, SUPPORTED_EC_CRV } from './jwk-key.js';

/**
 * `toEpkJwk` が返す EC 公開鍵 JWK（epk）の最小形。索引シグネチャを持たせることで、呼び出し側の
 * `JWK`（値型 `unknown`）・`Record<string, string>` 双方の索引シグネチャ制約に構造的に適合する
 * （名前付き型はリテラルと異なり、割り当て先が索引シグネチャを持つ場合は自身も索引シグネチャを
 * 持たない限り代入不可のため）。
 */
export interface EcPublicKeyJwk {
  readonly kty: 'EC';
  readonly crv: string;
  readonly x: string;
  readonly y: string;
  readonly [key: string]: string;
}

/**
 * SEC1 非圧縮 EC 公開鍵バイト列（`0x04 || x(32) || y(32)`）を JWK（`{kty:'EC', crv, x, y}`）へ
 * 変換する（`jwkToUncompressedPublicKey` の逆）。
 *
 * ECDH-ES のエフェメラル公開鍵（`epk`）を JWE protected header / バックアップの `kdfParams.epk`
 * へ載せる際に、`didcomm/jwe.ts` / `auth/jwe/ecdh.ts` / `wallet-migration/kdf/backup-ecdh.ts`
 * の 3 箇所が共有する（従来は 3 箇所とも一字一句同一の実装を独立に持っていた）。
 *
 * @param uncompressed 65 バイトの非圧縮公開鍵（`0x04` プレフィックス + x(32) + y(32)）。
 * @returns `{kty: 'EC', crv: SUPPORTED_EC_CRV, x, y}`（`x` / `y` は base64url パディングなし）。
 */
export function toEpkJwk(uncompressed: Uint8Array): EcPublicKeyJwk {
  return {
    kty: 'EC',
    crv: SUPPORTED_EC_CRV,
    x: base64urlnopad.encode(uncompressed.slice(1, 1 + EC_COORDINATE_LENGTH)),
    y: base64urlnopad.encode(uncompressed.slice(1 + EC_COORDINATE_LENGTH)),
  };
}
