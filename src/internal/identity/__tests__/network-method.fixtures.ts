/**
 * did:ebsi / did:ion / did:cheqd の単体テスト共通フィクスチャ。
 *
 * 取得は `fetchFn` 注入のモックで行い、実ネットワークには触れない。
 */

import { expect } from 'bun:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64urlnopad } from '@scure/base';
import { type ErrorCode, VericertsError } from '../../errors.js';

/** モックの `fetchFn` が受けた呼び出し。 */
export interface RecordedCall {
  readonly url: string;
  readonly accept: string | null;
}

/** モック応答の指定。 */
export interface MockReply {
  readonly status?: number;
  readonly contentType?: string | null;
  readonly body: string;
}

/** 呼び出しを記録し、URL ごとに応答を返す `fetchFn`。`reply` が例外を投げるとネットワークエラーになる。 */
export function recordingFetch(reply: (url: string, call: number) => MockReply): {
  readonly fetchFn: typeof fetch;
  readonly calls: RecordedCall[];
} {
  const calls: RecordedCall[] = [];
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const headers = new Headers(init?.headers);
    calls.push({ url, accept: headers.get('accept') });
    const mock = reply(url, calls.length);
    const responseHeaders = new Headers();
    if (mock.contentType !== null) {
      responseHeaders.set('content-type', mock.contentType ?? 'application/json');
    }
    return new Response(mock.body, { status: mock.status ?? 200, headers: responseHeaders });
  }) as unknown as typeof fetch;
  return { fetchFn, calls };
}

/** 本文を JSON にして 200 で返す指定。 */
export function jsonReply(value: unknown, contentType = 'application/json'): MockReply {
  return { contentType, body: JSON.stringify(value) };
}

/** reject が指定コード（と任意の `context.reason`）の `VericertsError` であることを検証する。 */
export async function expectRejects(
  promise: Promise<unknown>,
  code: ErrorCode,
  reason?: string,
): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
  if (reason !== undefined) {
    expect((caught as VericertsError).context?.reason).toBe(reason);
  }
}

/** 同期関数が指定コードの `VericertsError` を投げることを検証する。 */
export function expectThrows(fn: () => unknown, code: ErrorCode, reason?: string): void {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
  if (reason !== undefined) {
    expect((caught as VericertsError).context?.reason).toBe(reason);
  }
}

/** 決定的な秘密鍵（seed を 1 バイト目に入れた 32 バイト）。 */
function seeded(seed: number): Uint8Array {
  const bytes = new Uint8Array(32);
  bytes[31] = seed;
  return bytes;
}

/** 非圧縮点（`0x04 || x || y`）から EC 公開鍵 JWK を作る。 */
function ecJwk(crv: 'P-256' | 'secp256k1', point: Uint8Array): Record<string, string> {
  return {
    kty: 'EC',
    crv,
    x: base64urlnopad.encode(point.slice(1, 33)),
    y: base64urlnopad.encode(point.slice(33, 65)),
  };
}

/** P-256 の公開鍵 JWK。 */
export function p256Jwk(seed = 1): Record<string, string> {
  return ecJwk('P-256', p256.getPublicKey(seeded(seed), false));
}

/** secp256k1 の公開鍵 JWK。 */
export function secp256k1Jwk(seed = 1): Record<string, string> {
  return ecJwk('secp256k1', secp256k1.getPublicKey(seeded(seed), false));
}

/** Ed25519 の公開鍵 JWK（OKP）。 */
export function ed25519Jwk(seed = 1): Record<string, string> {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: base64urlnopad.encode(ed25519.getPublicKey(seeded(seed))),
  };
}
