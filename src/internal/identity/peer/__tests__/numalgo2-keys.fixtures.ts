/**
 * did:peer numalgo 2 の `V` / `E` 鍵エレメント用テストフィクスチャ（鍵検証の通る multibase 鍵）。
 *
 * 長さと multicodec のみを検証する実装に合わせ、固定バイトから決定的に組み立てる。
 */

import { getP256PublicKey } from '../../../keymanager/signer.js';
import { encodeMulticodecVarint, multibaseBase58Encode } from '../../multibase.js';
import { encodePublicKeyMultibase } from '../method-peer.js';

/** `multicodec(code) || raw` を multibase(base58btc) へ符号化する（未対応 codec・不正長の鍵も作れる）。 */
export function multikey(code: number, raw: Uint8Array): string {
  const prefix = encodeMulticodecVarint(code);
  const payload = new Uint8Array(prefix.length + raw.length);
  payload.set(prefix, 0);
  payload.set(raw, prefix.length);
  return multibaseBase58Encode(payload);
}

/** P-256 圧縮 33B 鍵（`E` / `V` の双方で有効）。 */
export function p256Key(fill: number): string {
  return encodePublicKeyMultibase('P-256', getP256PublicKey(new Uint8Array(32).fill(fill), true));
}

/** X25519 32B 鍵（`E` のみ有効。multicodec `0xec`）。 */
export function x25519Key(fill: number): string {
  return multikey(0xec, new Uint8Array(32).fill(fill));
}
