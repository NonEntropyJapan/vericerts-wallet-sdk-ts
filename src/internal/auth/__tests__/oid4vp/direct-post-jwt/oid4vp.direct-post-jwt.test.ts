/**
 * OID4VP `response_mode=direct_post.jwt`（JWE 応答）のラウンドトリップ / JOSE ヘッダテスト
 * （実鍵・モック禁止）。
 *
 * JAR 署名を検証し、direct_post.jwt の応答を復号して確認する。
 * 失敗系（8036）と response_mode 切替は `oid4vp.direct-post-jwt.errors.test.ts` に分離する。
 *
 * 検証内容:
 * - `ECDH-ES`（direct）で暗号化した `response` を受信者秘密鍵で復号でき、平文が
 *   `{ vp_token, state }` に一致する（ラウンドトリップ）。
 * - `ECDH-ES+A256KW`（鍵ラップ）でも同じ平文へ復号できる。
 * - 複数 VP Token は JSON 配列として JWE ペイロードに載る。
 * - `presentation_submission` を指定すると JWE ペイロードに含まれる。
 * - フォーム本文は `response` のみで、平文 `vp_token` / `state` が本文に現れない。
 * - `apv` = base64url(SHA-256(nonce))、`apu` = base64url(SHA-256(wallet_nonce))（手順 17）。
 * - エフェメラル鍵は送信ごとに異なる（`epk` の再利用が無い）。
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import {
  capture,
  clientMetadata,
  headerOf,
  installFetchCapture,
  NONCE,
  restoreFetch,
  STATE,
  sampleRequest,
  submitAndCaptureJwe,
  submitAndDecrypt,
  WALLET_NONCE,
} from './direct-post-jwt.fixtures.js';

beforeEach(() => {
  installFetchCapture();
});

afterEach(() => {
  restoreFetch();
});

describe('submitPresentation — direct_post.jwt ラウンドトリップ', () => {
  it('ECDH-ES（direct）で暗号化した response を復号すると vp_token / state が一致する', async () => {
    expect(await submitAndDecrypt(sampleRequest())).toEqual({
      vp_token: 'vp-token-string',
      state: STATE,
    });
  });

  it('ECDH-ES+A256KW（鍵ラップ）でも同じ平文へ復号できる', async () => {
    const request = sampleRequest({ clientMetadata: clientMetadata('ECDH-ES+A256KW') });
    const jwe = await submitAndCaptureJwe(request);
    expect(headerOf(jwe).alg).toBe('ECDH-ES+A256KW');
    // direct と異なり encrypted_key セグメントが空でないこと（ラップ済み CEK）。
    expect(jwe.split('.')[1]).not.toBe('');
    expect(await submitAndDecrypt(request)).toEqual({
      vp_token: 'vp-token-string',
      state: STATE,
    });
  });

  it('複数 VP Token は JSON 配列として JWE ペイロードに載る', async () => {
    const payload = await submitAndDecrypt(sampleRequest(), ['tok-a', 'tok-b']);
    expect(payload.vp_token).toEqual(['tok-a', 'tok-b']);
  });

  it('presentation_submission を指定すると JWE ペイロードに含まれる', async () => {
    const submission = { id: 'sub-1', definition_id: 'def-1', descriptor_map: [] };
    const payload = await submitAndDecrypt(sampleRequest(), 'tok', {
      presentationSubmission: submission,
    });
    expect(payload.presentation_submission).toEqual(submission);
  });

  it('フォーム本文は response のみで、平文の vp_token / state を含まない', async () => {
    await submitAndCaptureJwe(sampleRequest(), 'super-secret-vp-token');
    const params = new URLSearchParams(capture.body);
    expect([...params.keys()]).toEqual(['response']);
    expect(capture.body).not.toContain('super-secret-vp-token');
    expect(capture.body).not.toContain(STATE);
  });
});

describe('submitPresentation — direct_post.jwt JOSE ヘッダ', () => {
  it('apv = base64url(SHA-256(nonce))、apu = base64url(SHA-256(wallet_nonce))', async () => {
    const header = headerOf(
      await submitAndCaptureJwe(sampleRequest(), 'tok', { walletNonce: WALLET_NONCE }),
    );
    expect(header.apv).toBe(base64urlnopad.encode(sha256(new TextEncoder().encode(NONCE))));
    expect(header.apu).toBe(base64urlnopad.encode(sha256(new TextEncoder().encode(WALLET_NONCE))));
  });

  it('wallet_nonce 未指定なら apu を省略する', async () => {
    const header = headerOf(await submitAndCaptureJwe(sampleRequest()));
    expect(header.apu).toBeUndefined();
    expect(header.apv).toBeDefined();
  });

  it('選択した鍵の kid と enc をヘッダに載せる', async () => {
    const header = headerOf(await submitAndCaptureJwe(sampleRequest()));
    expect(header.kid).toBe('k1');
    expect(header.enc).toBe('A256GCM');
  });

  it('エフェメラル鍵は送信ごとに新規生成する（epk を再利用しない）', async () => {
    const first = headerOf(await submitAndCaptureJwe(sampleRequest()));
    const second = headerOf(await submitAndCaptureJwe(sampleRequest()));
    expect(first.epk).not.toEqual(second.epk);
  });
});
