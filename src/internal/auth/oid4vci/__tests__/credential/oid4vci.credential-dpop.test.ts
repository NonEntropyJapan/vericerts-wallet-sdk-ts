/**
 * Credential Endpoint へ DPoP アクセストークンと proof を送る際のヘッダーを検証する（RFC 9449 §7.1）。
 *
 * 回帰観点:
 * - `dpop` 指定時に `Authorization: DPoP <access_token>` と `DPoP: <proof>` が載ること
 * - `dpop` 未指定の既存呼び出しは従来どおり `Authorization: Bearer` のままであること（下位互換）
 * - `tokenType: "DPoP"` で proof 未指定なら HTTP を 1 度も発生させずに fail-closed で落ちること
 * - `dpop` / `tokenType` を `Object.prototype` 経由で汚染しても拾わないこと
 */

import { afterEach, describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FetchLike } from '../../../../fetch-di.js';
import { type RequestCredentialOptions, requestCredential } from '../../oid4vci.js';

const CREDENTIAL_URL = 'https://issuer.example.com/credential';
const ACCESS_TOKEN = 'access-token-value';
const DPOP_PROOF = 'eyJ0eXAiOiJkcG9wK2p3dCJ9.eyJodHUiOiJ4In0.sig';

interface Recorded {
  readonly url: string;
  readonly headers: Record<string, string>;
}

function stub(): { fetchImpl: FetchLike; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    calls.push({ url, headers: init.headers });
    return new Response(JSON.stringify({ credential: 'vc-value' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  return { fetchImpl, calls };
}

function options(overrides: Partial<RequestCredentialOptions> = {}): RequestCredentialOptions {
  return {
    credentialEndpoint: CREDENTIAL_URL,
    accessToken: ACCESS_TOKEN,
    format: 'dc+sd-jwt',
    credentialDefinition: { type: ['UniversityDegree'] },
    proofJwt: 'header.payload.sig',
    ...overrides,
  };
}

describe('requestCredential の DPoP proof 送出', () => {
  test('dpop 指定時は Authorization: DPoP と DPoP ヘッダを送る', async () => {
    const { fetchImpl, calls } = stub();
    const result = await requestCredential(options({ fetchImpl, dpop: DPOP_PROOF }));
    expect(result.status).toBe('issued');
    expect(calls).toHaveLength(1);
    expect(calls[0]?.headers.Authorization).toBe(`DPoP ${ACCESS_TOKEN}`);
    expect(calls[0]?.headers.DPoP).toBe(DPOP_PROOF);
    // proof は送信先（htu）に束縛されるため、送信先が Credential Endpoint であることも確認する。
    expect(calls[0]?.url).toBe(CREDENTIAL_URL);
  });

  test('dpop 未指定の既存呼び出しは Authorization: Bearer のまま（下位互換）', async () => {
    const { fetchImpl, calls } = stub();
    await requestCredential(options({ fetchImpl }));
    expect(calls[0]?.headers.Authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
    expect(calls[0]?.headers.DPoP).toBeUndefined();
  });

  test('tokenType が Bearer なら proof 無しでも従来どおり送る', async () => {
    const { fetchImpl, calls } = stub();
    await requestCredential(options({ fetchImpl, tokenType: 'Bearer' }));
    expect(calls[0]?.headers.Authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  });

  test('tokenType が DPoP で proof 未指定なら fetch を発生させずに 8020 で落ちる', async () => {
    const { fetchImpl, calls } = stub();
    const promise = requestCredential(options({ fetchImpl, tokenType: 'DPoP' }));
    await expect(promise).rejects.toThrow(VericertsError);
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.CREDENTIAL_REQUEST_FAILED,
      context: { reason: 'dpop_proof_required' },
    });
    expect(calls).toHaveLength(0);
  });

  test('token_type の大文字小文字は区別しない（RFC 6749 §5.1）', async () => {
    const { fetchImpl, calls } = stub();
    await expect(requestCredential(options({ fetchImpl, tokenType: 'dpop' }))).rejects.toThrow(
      VericertsError,
    );
    expect(calls).toHaveLength(0);
  });

  test('tokenType が DPoP でも proof があれば送れる', async () => {
    const { fetchImpl, calls } = stub();
    await requestCredential(options({ fetchImpl, tokenType: 'DPoP', dpop: DPOP_PROOF }));
    expect(calls[0]?.headers.Authorization).toBe(`DPoP ${ACCESS_TOKEN}`);
    expect(calls[0]?.headers.DPoP).toBe(DPOP_PROOF);
  });

  test('空白のみの dpop は fetch を発生させずに拒否する', async () => {
    const { fetchImpl, calls } = stub();
    await expect(requestCredential(options({ fetchImpl, dpop: '   ' }))).rejects.toMatchObject({
      code: ErrorCodes.CREDENTIAL_REQUEST_FAILED,
      context: { reason: 'invalid_dpop_proof' },
    });
    expect(calls).toHaveLength(0);
  });
});

describe('requestCredential の dpop / tokenType は own 限定で読む', () => {
  afterEach(() => {
    for (const key of ['dpop', 'tokenType']) {
      delete (Object.prototype as unknown as Record<string, unknown>)[key];
    }
  });

  test('継承した dpop は DPoP ヘッダに載らない', async () => {
    const { fetchImpl, calls } = stub();
    (Object.prototype as unknown as Record<string, unknown>).dpop = 'attacker-proof';
    await requestCredential(options({ fetchImpl }));
    // 汚染値を拾うと Authorization が DPoP に切り替わり攻撃者の proof で送出される。
    expect(calls[0]?.headers.Authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
    expect(calls[0]?.headers.DPoP).toBeUndefined();
  });

  test('継承した tokenType は fail-closed 判定を誤らせない', async () => {
    const { fetchImpl, calls } = stub();
    (Object.prototype as unknown as Record<string, unknown>).tokenType = 'DPoP';
    // 汚染値を拾うと proof 未指定の正当な呼び出しが 8020 で拒否され DoS になる。
    await requestCredential(options({ fetchImpl }));
    expect(calls).toHaveLength(1);
    expect(calls[0]?.headers.Authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  });
});
