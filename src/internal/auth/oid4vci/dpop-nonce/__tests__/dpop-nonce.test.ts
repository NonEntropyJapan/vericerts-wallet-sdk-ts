/**
 * DPoP nonce チャレンジ（`use_dpop_nonce` + `DPoP-Nonce`）への 1 回再送（RFC 9449 §8 / §9）。
 *
 * nonce を要求する AS / RS への DPoP 受領が成立すること、再送が**ちょうど 1 回**であること、
 * proof を持たない（Bearer）要求や別種の 400/401 では再送しないことを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { VALID_PAR_BODY } from '../../__tests__/par/par-fixtures.js';
import { VALID_TOKEN_BODY } from '../../__tests__/token/token-fixtures.js';
import type { FetchLike } from '../../oid4vci.js';
import { requestCredential } from '../../oid4vci.js';
import { pushAuthorizationRequest } from '../../par/par.js';
import { requestTokenPreAuthorized } from '../../token/oid4vci-token.js';

const TOKEN_ENDPOINT = 'https://issuer.example.com/token';
const CREDENTIAL_ENDPOINT = 'https://issuer.example.com/credential';
const PAR_ENDPOINT = 'https://issuer.example.com/par';
const NONCE = 'server-nonce-1';
const VC_JWT = 'eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6e319.vc-sig';

/** 1 回分の要求記録。 */
interface Seen {
  readonly dpop: string | undefined;
}

/** 応答を順に返し、各要求の `DPoP` ヘッダを記録する fetch。 */
function sequence(responses: readonly (() => Response)[], seen: Seen[]): FetchLike {
  let i = 0;
  return async (_url, init) => {
    seen.push({ dpop: init.headers.DPoP });
    const next = responses[Math.min(i, responses.length - 1)];
    i += 1;
    return (next as () => Response)();
  };
}

const json = (body: unknown, status: number, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });

/** AS の nonce チャレンジ（RFC 9449 §8）。 */
const asChallenge = (): Response => json({ error: 'use_dpop_nonce' }, 400, { 'DPoP-Nonce': NONCE });

/** RS の nonce チャレンジ（RFC 9449 §9）。 */
const rsChallenge = (): Response =>
  new Response('', {
    status: 401,
    headers: { 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"', 'DPoP-Nonce': NONCE },
  });

/** nonce を受け取ると proof へ載せる再生成関数（呼び出された nonce を記録する）。 */
function rebuilder(nonces: string[]): (nonce: string) => string {
  return (nonce) => {
    nonces.push(nonce);
    return `proof-with-${nonce}`;
  };
}

describe('Token Endpoint（RFC 9449 §8）', () => {
  it('400 use_dpop_nonce を受けたら nonce 付き proof で 1 回だけ再送して成功する', async () => {
    const seen: Seen[] = [];
    const nonces: string[] = [];
    const fetchImpl = sequence([asChallenge, () => json(VALID_TOKEN_BODY, 200)], seen);
    const token = await requestTokenPreAuthorized(TOKEN_ENDPOINT, {
      preAuthorizedCode: 'code',
      dpop: 'proof-initial',
      rebuildDpop: rebuilder(nonces),
      fetchImpl,
    });
    expect(token.accessToken).toBe(VALID_TOKEN_BODY.access_token);
    expect(seen.map((s) => s.dpop)).toEqual(['proof-initial', `proof-with-${NONCE}`]);
    expect(nonces).toEqual([NONCE]);
  });

  it('再送後もチャレンジなら再々送せず 8010 で落ちる（上限 1 回）', async () => {
    const seen: Seen[] = [];
    const fetchImpl = sequence([asChallenge], seen);
    await expect(
      requestTokenPreAuthorized(TOKEN_ENDPOINT, {
        preAuthorizedCode: 'code',
        dpop: 'proof-initial',
        rebuildDpop: rebuilder([]),
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(seen).toHaveLength(2);
  });

  it('use_dpop_nonce 以外の 400（invalid_grant）は再送せず、通常どおり本文を読んで 8010', async () => {
    const seen: Seen[] = [];
    const fetchImpl = sequence(
      [() => json({ error: 'invalid_grant' }, 400, { 'DPoP-Nonce': NONCE })],
      seen,
    );
    await expect(
      requestTokenPreAuthorized(TOKEN_ENDPOINT, {
        preAuthorizedCode: 'code',
        dpop: 'proof-initial',
        rebuildDpop: rebuilder([]),
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(seen).toHaveLength(1);
  });

  it('DPoP-Nonce ヘッダが無い / 不正な形なら再送しない', async () => {
    for (const nonce of [undefined, '', 'has space', 'a'.repeat(513)]) {
      const seen: Seen[] = [];
      const fetchImpl = sequence(
        [
          () =>
            json(
              { error: 'use_dpop_nonce' },
              400,
              nonce === undefined ? {} : { 'DPoP-Nonce': nonce },
            ),
        ],
        seen,
      );
      await expect(
        requestTokenPreAuthorized(TOKEN_ENDPOINT, {
          preAuthorizedCode: 'code',
          dpop: 'proof-initial',
          rebuildDpop: rebuilder([]),
          fetchImpl,
        }),
      ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
      expect(seen).toHaveLength(1);
    }
  });

  it('proof（dpop）を送っていない要求は再送しない（Bearer 経路の挙動は変えない）', async () => {
    const seen: Seen[] = [];
    const fetchImpl = sequence([asChallenge], seen);
    await expect(
      requestTokenPreAuthorized(TOKEN_ENDPOINT, {
        preAuthorizedCode: 'code',
        rebuildDpop: rebuilder([]),
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(seen).toEqual([{ dpop: undefined }]);
  });

  it('rebuildDpop が無ければ再送しない', async () => {
    const seen: Seen[] = [];
    const fetchImpl = sequence([asChallenge], seen);
    await expect(
      requestTokenPreAuthorized(TOKEN_ENDPOINT, {
        preAuthorizedCode: 'code',
        dpop: 'proof-initial',
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(seen).toHaveLength(1);
  });
});

describe('Credential Endpoint（RFC 9449 §9）', () => {
  const base = {
    credentialEndpoint: CREDENTIAL_ENDPOINT,
    accessToken: 'at',
    format: 'jwt_vc_json',
    credentialDefinition: { type: ['VerifiableCredential'] },
    proofJwt: 'eyJ.proof.jwt',
    tokenType: 'DPoP',
  } as const;

  it('401 + WWW-Authenticate use_dpop_nonce を受けたら nonce 付き proof で 1 回だけ再送して受領する', async () => {
    const seen: Seen[] = [];
    const nonces: string[] = [];
    const fetchImpl = sequence([rsChallenge, () => json({ credential: VC_JWT }, 200)], seen);
    const result = await requestCredential({
      ...base,
      dpop: 'proof-initial',
      rebuildDpop: rebuilder(nonces),
      fetchImpl,
    });
    expect(result.status).toBe('issued');
    expect(seen.map((s) => s.dpop)).toEqual(['proof-initial', `proof-with-${NONCE}`]);
    expect(nonces).toEqual([NONCE]);
  });

  it('再送後もチャレンジなら再々送せず 8020 で落ちる（上限 1 回）', async () => {
    const seen: Seen[] = [];
    const fetchImpl = sequence([rsChallenge], seen);
    await expect(
      requestCredential({
        ...base,
        dpop: 'proof-initial',
        rebuildDpop: rebuilder([]),
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.CREDENTIAL_REQUEST_FAILED });
    expect(seen).toHaveLength(2);
  });

  it('error が use_dpop_nonce でない 401（invalid_token）は再送しない', async () => {
    const seen: Seen[] = [];
    const fetchImpl = sequence(
      [
        () =>
          new Response('', {
            status: 401,
            headers: { 'WWW-Authenticate': 'DPoP error="invalid_token"', 'DPoP-Nonce': NONCE },
          }),
      ],
      seen,
    );
    await expect(
      requestCredential({ ...base, dpop: 'proof-initial', rebuildDpop: rebuilder([]), fetchImpl }),
    ).rejects.toMatchObject({ code: ErrorCodes.CREDENTIAL_REQUEST_FAILED });
    expect(seen).toHaveLength(1);
  });

  it('Bearer 要求（dpop 無し）は 401 use_dpop_nonce でも再送しない', async () => {
    const seen: Seen[] = [];
    const fetchImpl = sequence([rsChallenge], seen);
    await expect(
      requestCredential({
        ...base,
        tokenType: 'Bearer',
        rebuildDpop: rebuilder([]),
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.CREDENTIAL_REQUEST_FAILED });
    expect(seen).toEqual([{ dpop: undefined }]);
  });
});

describe('PAR（RFC 9449 §8）', () => {
  const request = (fetchImpl: FetchLike, withRebuild: boolean) => ({
    par_endpoint: PAR_ENDPOINT,
    client_id: 'wallet-client',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    redirect_uri: 'com.example.wallet://cb',
    state: 'Zm9vYmFyLXN0YXRlLTEyOGJpdA',
    dpop: 'proof-initial',
    ...(withRebuild ? { rebuildDpop: rebuilder([]) } : {}),
    fetchImpl,
  });

  it('400 use_dpop_nonce を受けたら nonce 付き proof で 1 回だけ再送する', async () => {
    const seen: Seen[] = [];
    const fetchImpl = sequence([asChallenge, () => json(VALID_PAR_BODY, 201)], seen);
    await pushAuthorizationRequest(request(fetchImpl, true));
    expect(seen.map((s) => s.dpop)).toEqual(['proof-initial', `proof-with-${NONCE}`]);
  });

  it('rebuildDpop が無ければ再送しない', async () => {
    const seen: Seen[] = [];
    const fetchImpl = sequence([asChallenge], seen);
    await expect(pushAuthorizationRequest(request(fetchImpl, false))).rejects.toBeDefined();
    expect(seen).toHaveLength(1);
  });
});
