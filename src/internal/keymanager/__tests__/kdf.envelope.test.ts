/**
 * vault/envelope-format.ts のエンベロープ組み立て不変条件の検証。
 *
 * packEnvelopeV2 の 2 バイト BE 長ヘッダ上限（65535）ガードを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { packEnvelopeV2 } from '../vault/envelope-format.js';

describe('packEnvelopeV2 length guard', () => {
  const salt = new Uint8Array(32);
  const iv = new Uint8Array(12);
  const ct = new Uint8Array(0);

  it('throws ENCRYPT_FAILED when kdfJson exceeds the 2-byte BE header limit', () => {
    // 65535 を 1 バイト超える kdfJson は 2 バイト長ヘッダで表現できない。
    const oversized = new Uint8Array(0x10000);
    try {
      packEnvelopeV2(oversized, salt, iv, ct);
      throw new Error('expected packEnvelopeV2 to throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.ENCRYPT_FAILED);
    }
  });

  it('accepts kdfJson at the 65535-byte boundary', () => {
    const atLimit = new Uint8Array(0xffff);
    const env = packEnvelopeV2(atLimit, salt, iv, ct);
    // version(1) + len(2) + kdfJson + salt(32) + iv(12) + ct(0)
    expect(env.length).toBe(3 + 0xffff + 32 + 12);
    // 長ヘッダは BE で 0xffff を保持する。
    expect(env[1]).toBe(0xff);
    expect(env[2]).toBe(0xff);
  });
});
