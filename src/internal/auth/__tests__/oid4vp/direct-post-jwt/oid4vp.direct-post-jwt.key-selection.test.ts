/**
 * `direct_post.jwt` の受信者鍵選択が、使えない EC 鍵（P-384・座標欠落・曲線外点）を読み飛ばして
 * 同一 JWKS 内の有効な P-256 鍵を採用することの回帰テスト。
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import {
  capture,
  clientMetadata,
  decryptJwe,
  headerOf,
  installFetchCapture,
  RECIPIENT_PUBLIC,
  RECIPIENT_SECRET,
  restoreFetch,
  sampleRequest,
  submitAndCaptureJwe,
  toEcJwk,
} from './direct-post-jwt.fixtures.js';

beforeEach(() => {
  installFetchCapture();
});

afterEach(() => {
  restoreFetch();
});

const coordinate = base64urlnopad.encode(new Uint8Array(32).fill(1));
const P384_KEY = { kty: 'EC', crv: 'P-384', x: coordinate, y: coordinate, use: 'enc', kid: 'p384' };
const VALID_P256 = toEcJwk(RECIPIENT_PUBLIC, { use: 'enc', kid: 'p256' });

/** 不適格鍵を先頭に置いても、有効な P-256 鍵（kid: p256）で暗号化され復号できる。 */
async function expectEncryptedToP256(keys: readonly Record<string, unknown>[]): Promise<void> {
  for (const alg of ['ECDH-ES', 'ECDH-ES+A256KW']) {
    capture.calls = 0;
    const jwe = await submitAndCaptureJwe(
      sampleRequest({ clientMetadata: clientMetadata(alg, keys) }),
    );
    expect(headerOf(jwe).kid).toBe('p256');
    expect(JSON.parse(await decryptJwe(jwe, RECIPIENT_SECRET)).vp_token).toBe('vp-token-string');
  }
}

describe('direct_post.jwt の鍵選択: 不適格な EC 鍵を読み飛ばす', () => {
  it('[P-384(use:enc), P-256(use:enc)] は P-256 を使う', async () => {
    await expectEncryptedToP256([P384_KEY, VALID_P256]);
  });

  it('[crv/x/y 欠落の EC 鍵, 有効 P-256] は P-256 を使う', async () => {
    await expectEncryptedToP256([{ kty: 'EC', use: 'enc', kid: 'broken' }, VALID_P256]);
  });

  it('[座標が曲線外の鍵, 有効 P-256] は P-256 を使う', async () => {
    const offCurve = { kty: 'EC', crv: 'P-256', x: coordinate, y: coordinate, kid: 'off' };
    await expectEncryptedToP256([offCurve, VALID_P256]);
  });

  it('[座標長不正の P-256 鍵, 有効 P-256] は P-256 を使う', async () => {
    const shortCoordinate = base64urlnopad.encode(new Uint8Array(31).fill(1));
    const shortKey = { kty: 'EC', crv: 'P-256', x: shortCoordinate, y: shortCoordinate };
    await expectEncryptedToP256([shortKey, VALID_P256]);
  });
});
