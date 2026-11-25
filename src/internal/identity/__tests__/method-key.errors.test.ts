/**
 * MethodKey / createDidKey / resolveDidKey のエラー検証。
 *
 * 不正な did:key 入力（非 z multibase / 不正 base58 / 未知 multicodec / 公開鍵長不一致 /
 * identifier 空）は 2001、update / deactivate は 2002 を投げることを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { base58 } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DidKeyType } from '../did.js';
import { createDidKey, MethodKey, resolveDidKey } from '../method-key.js';

const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);
const METHOD_NOT_SUPPORTED = new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);

describe('resolveDidKey errors', () => {
  it('did:key: プレフィックスがない場合は 2001', () => {
    expect(() => resolveDidKey('did:web:example.com')).toThrow(INVALID_DID);
  });

  it('identifier が空（did:key:）は 2001', () => {
    expect(() => resolveDidKey('did:key:')).toThrow(INVALID_DID);
  });

  it('非 z multibase は 2001', () => {
    expect(() => resolveDidKey('did:key:x6Mk')).toThrow(INVALID_DID);
  });

  it('不正な base58 文字列は 2001', () => {
    expect(() => resolveDidKey('did:key:z0OIl')).toThrow(INVALID_DID);
  });

  it('未知の multicodec プレフィックスは 2001', () => {
    // 未使用 codec 0x9999 (varint [0x99,0xb3,0x02]) + 32B では既知 3 種に一致しない。
    // 簡潔に 2 バイト未知 prefix [0x00,0x00] + 32B を符号化する。
    const payload = new Uint8Array(2 + 32);
    payload[0] = 0x00;
    payload[1] = 0x00;
    const did = `did:key:z${base58.encode(payload)}`;
    expect(() => resolveDidKey(did)).toThrow(INVALID_DID);
  });

  it('非 canonical varint prefix（Ed25519 codec の継続ビット誤用）は 2001', () => {
    // Ed25519 canonical prefix は [0xed, 0x01]。2 バイト目に継続ビット(0x80)を立てた
    // [0xed, 0x81] は同じ codec(0xed) を非 canonical に符号化したもの。継続ビットを
    // マスクするだけの実装だと Ed25519 として誤受理されるが、canonical 照合では弾く。
    const payload = new Uint8Array(2 + 32);
    payload[0] = 0xed;
    payload[1] = 0x81;
    const did = `did:key:z${base58.encode(payload)}`;
    expect(() => resolveDidKey(did)).toThrow(INVALID_DID);
  });

  it('公開鍵長が不一致（Ed25519 prefix + 31B）は 2001', () => {
    // Ed25519 prefix(0xed01) + 31 バイト（32 でない）。
    const payload = new Uint8Array(2 + 31);
    payload[0] = 0xed;
    payload[1] = 0x01;
    const did = `did:key:z${base58.encode(payload)}`;
    expect(() => resolveDidKey(did)).toThrow(INVALID_DID);
  });
});

describe('createDidKey errors', () => {
  it('未対応の keyType は 2001', () => {
    expect(() => createDidKey('unknown' as DidKeyType, new Uint8Array(32))).toThrow(INVALID_DID);
  });

  it('Ed25519 で公開鍵長が 32B でない場合は 2001', () => {
    expect(() => createDidKey('Ed25519', new Uint8Array(31))).toThrow(INVALID_DID);
  });

  it('secp256k1 で公開鍵長が 33B でない場合は 2001', () => {
    expect(() => createDidKey('secp256k1', new Uint8Array(32))).toThrow(INVALID_DID);
  });
});

describe('MethodKey update/deactivate', () => {
  it('update は 2002 を投げる', async () => {
    const method = new MethodKey();
    await expect(method.update('did:key:z6Mk', {})).rejects.toThrow(METHOD_NOT_SUPPORTED);
  });

  it('deactivate は 2002 を投げる', async () => {
    const method = new MethodKey();
    await expect(method.deactivate('did:key:z6Mk')).rejects.toThrow(METHOD_NOT_SUPPORTED);
  });

  it('method() は key を返す', () => {
    expect(new MethodKey().method()).toBe('key');
  });
});
