/**
 * `direct_post.jwt`（JWE 応答）テストの共有フィクスチャ（実鍵・モック禁止）。
 *
 * ここには実装側とは**独立に**組み立てた JWE 復号器（Verifier 役）を置く。実装の
 * `encryptJweCompact` と同じ手順を再実装せず、RFC 7518 §4.6.2 / RFC 7516 §7.1 の定義から
 * 直接組み立てることで、ラウンドトリップテストが実装のバグを検出できるようにする。
 */

import { expect } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import {
  RESPONSE_MODE_DIRECT_POST_JWT,
  type SubmitPresentationOptions,
  submitPresentation,
} from '../../../oid4vp/oid4vp-submit.js';
import type { PresentationRequest } from '../../../request.js';

export const CLIENT_ID = 'https://verifier.example.com';
export const NONCE = 'nonce-abcdefghijklmnopqrstuvwxyz012345';
export const STATE = 'state-0123456789';
export const WALLET_NONCE = 'wallet-nonce-9876543210';

/** 受信者（Verifier）の固定秘密鍵。テストの決定性のため定数とする。 */
export const RECIPIENT_SECRET = new Uint8Array(32).fill(23);
export const RECIPIENT_PUBLIC = p256.getPublicKey(RECIPIENT_SECRET, false);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
export function toEcJwk(
  pub: Uint8Array,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    kty: 'EC',
    crv: 'P-256',
    x: base64urlnopad.encode(pub.subarray(1, 33)),
    y: base64urlnopad.encode(pub.subarray(33, 65)),
    ...extra,
  };
}

/** `client_metadata` を組み立てる。 */
export function clientMetadata(
  alg: string,
  keys: readonly Record<string, unknown>[] = [toEcJwk(RECIPIENT_PUBLIC, { use: 'enc', kid: 'k1' })],
  enc?: string,
): Record<string, unknown> {
  return {
    authorization_encrypted_response_alg: alg,
    ...(enc !== undefined ? { authorization_encrypted_response_enc: enc } : {}),
    jwks: { keys },
  };
}

/** テスト用 `PresentationRequest`（既定は `direct_post.jwt` + ECDH-ES）。 */
export function sampleRequest(overrides: Partial<PresentationRequest> = {}): PresentationRequest {
  return {
    responseType: 'vp_token',
    clientId: CLIENT_ID,
    responseMode: RESPONSE_MODE_DIRECT_POST_JWT,
    responseUri: `${CLIENT_ID}/callback`,
    nonce: NONCE,
    state: STATE,
    clientMetadata: clientMetadata('ECDH-ES'),
    ...overrides,
  };
}

/** 直近の POST 本文と fetch 呼び出し回数を記録する捕捉器。 */
export const capture = { body: '', calls: 0 };

const originalFetch = globalThis.fetch;

/** `globalThis.fetch` を捕捉器に差し替える（`beforeEach` から呼ぶ）。 */
export function installFetchCapture(status = 200): void {
  capture.body = '';
  capture.calls = 0;
  globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
    capture.calls += 1;
    capture.body = String(init?.body ?? '');
    return new Response(null, { status });
  }) as unknown as typeof fetch;
}

/** `globalThis.fetch` を元に戻す（`afterEach` から呼ぶ）。 */
export function restoreFetch(): void {
  globalThis.fetch = originalFetch;
}

/** 32bit ビッグエンディアン。 */
function uint32BE(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

/** バイト列連結。Web Crypto に渡すため `ArrayBuffer` バッキングで返す。 */
function concat(...parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(parts.reduce((n, p) => n + p.length, 0)));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** `Uint8Array` を Web Crypto の `BufferSource` が要求する `ArrayBuffer` バッキングへ正規化する。 */
function buf(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes.buffer instanceof ArrayBuffer
    ? (bytes as Uint8Array<ArrayBuffer>)
    : Uint8Array.from(bytes);
}

/** Concat KDF（RFC 7518 §4.6.2）。実装側とは独立にテスト側で組み立てる。 */
function concatKdf(z: Uint8Array, algId: string, apu: Uint8Array, apv: Uint8Array): Uint8Array {
  const lp = (b: Uint8Array): Uint8Array => concat(uint32BE(b.length), b);
  return sha256(
    concat(uint32BE(1), z, lp(new TextEncoder().encode(algId)), lp(apu), lp(apv), uint32BE(256)),
  );
}

/** JWE の protected header（第 1 セグメント）を復元する。 */
export function headerOf(jwe: string): Record<string, unknown> {
  return JSON.parse(
    new TextDecoder().decode(base64urlnopad.decode(jwe.split('.')[0] as string)),
  ) as Record<string, unknown>;
}

/** JWE Compact を受信者秘密鍵で復号する（Verifier 側の処理を模した検証用）。 */
export async function decryptJwe(jwe: string, recipientSecret: Uint8Array): Promise<string> {
  const [protectedHeader, encryptedKey, iv, ciphertext, tag] = jwe.split('.');
  const header = headerOf(jwe) as Record<string, string>;

  const epk = header.epk as unknown as Record<string, string>;
  const epkPublic = concat(
    Uint8Array.of(0x04),
    base64urlnopad.decode(epk.x as string),
    base64urlnopad.decode(epk.y as string),
  );
  const z = p256.getSharedSecret(recipientSecret, epkPublic).slice(1);
  const isDirect = header.alg === 'ECDH-ES';
  const derived = concatKdf(
    z,
    isDirect ? (header.enc as string) : (header.alg as string),
    header.apu !== undefined ? base64urlnopad.decode(header.apu) : new Uint8Array(0),
    header.apv !== undefined ? base64urlnopad.decode(header.apv) : new Uint8Array(0),
  );

  let cek = derived;
  if (!isDirect) {
    const kek = await crypto.subtle.importKey('raw', buf(derived), { name: 'AES-KW' }, false, [
      'unwrapKey',
    ]);
    const unwrapped = await crypto.subtle.unwrapKey(
      'raw',
      buf(base64urlnopad.decode(encryptedKey as string)),
      kek,
      'AES-KW',
      { name: 'AES-GCM' },
      true,
      ['decrypt'],
    );
    cek = new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped));
  }

  const key = await crypto.subtle.importKey('raw', buf(cek), { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: buf(base64urlnopad.decode(iv as string)),
      tagLength: 128,
      additionalData: new TextEncoder().encode(protectedHeader as string),
    },
    key,
    concat(base64urlnopad.decode(ciphertext as string), base64urlnopad.decode(tag as string)),
  );
  return new TextDecoder().decode(plaintext);
}

/** `submitPresentation` を実行し、送信された `response`（JWE）を取り出す。 */
export async function submitAndCaptureJwe(
  request: PresentationRequest,
  vpToken: string | string[] = 'vp-token-string',
  options?: SubmitPresentationOptions,
): Promise<string> {
  await submitPresentation(request, vpToken, options);
  const response = new URLSearchParams(capture.body).get('response');
  expect(response).not.toBeNull();
  return response as string;
}

/** 送信された `response` を復号し、JSON ペイロードを返す。 */
export async function submitAndDecrypt(
  request: PresentationRequest,
  vpToken: string | string[] = 'vp-token-string',
  options?: SubmitPresentationOptions,
): Promise<Record<string, unknown>> {
  const jwe = await submitAndCaptureJwe(request, vpToken, options);
  return JSON.parse(await decryptJwe(jwe, RECIPIENT_SECRET)) as Record<string, unknown>;
}
