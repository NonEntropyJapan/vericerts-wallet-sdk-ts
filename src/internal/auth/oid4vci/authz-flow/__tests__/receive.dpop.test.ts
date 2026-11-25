/**
 * Authorization Code Flow の DPoP proof 配線。
 *
 * 手順 12（Credential Endpoint）まで proof が載ることと、`htu` が 3 経路で送信先ごとに違うことを
 * 実際の HTTP 記録から確認する。RFC 9449 §4.3 の `htu` 束縛により 1 つの proof を共用できない。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { receiveCredentialViaAuthorizationCode } from '../receive.js';
import {
  ACCESS_TOKEN,
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  dpopTokenResponse,
  flowDeps,
  flowOptions,
  PAR_URL,
  parResponse,
  TOKEN_URL,
  tokenResponse,
} from './flow-fixtures.js';

/** `htu` ごとに区別できる proof を返す生成関数。 */
const proofFor = (htu: string): string => `proof-for:${htu}`;

describe('receiveCredentialViaAuthorizationCode の DPoP proof', () => {
  test('createDpopProof 指定時は Credential Request にも DPoP proof が載る', async () => {
    const stub = createStubFetch({
      [PAR_URL]: parResponse,
      [TOKEN_URL]: dpopTokenResponse,
      [CREDENTIAL_URL]: credentialResponse,
    });
    const result = await receiveCredentialViaAuthorizationCode(
      flowOptions(),
      flowDeps(stub, { createDpopProof: proofFor }),
    );
    expect(result.status).toBe('issued');

    const credentialCall = stub.callTo(CREDENTIAL_URL);
    expect(credentialCall?.headers.Authorization).toBe(`DPoP ${ACCESS_TOKEN}`);
    // htu は Credential Endpoint。PAR / Token の proof を再利用すると Issuer が束縛検証で落とす。
    expect(credentialCall?.headers.DPoP).toBe(proofFor(CREDENTIAL_URL));
  });

  test('3 経路の proof は送信先ごとに別（htu 束縛。RFC 9449 §4.3）', async () => {
    const stub = createStubFetch({
      [PAR_URL]: parResponse,
      [TOKEN_URL]: dpopTokenResponse,
      [CREDENTIAL_URL]: credentialResponse,
    });
    await receiveCredentialViaAuthorizationCode(
      flowOptions(),
      flowDeps(stub, { createDpopProof: proofFor }),
    );
    expect(stub.callTo(PAR_URL)?.headers.DPoP).toBe(proofFor(PAR_URL));
    expect(stub.callTo(TOKEN_URL)?.headers.DPoP).toBe(proofFor(TOKEN_URL));
    expect(stub.callTo(CREDENTIAL_URL)?.headers.DPoP).toBe(proofFor(CREDENTIAL_URL));
  });

  test('createDpopProof 未指定なら手順 12 は従来どおり Bearer（下位互換）', async () => {
    const stub = createStubFetch({
      [PAR_URL]: parResponse,
      [TOKEN_URL]: tokenResponse,
      [CREDENTIAL_URL]: credentialResponse,
    });
    const result = await receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(stub));
    expect(result.status).toBe('issued');
    const credentialCall = stub.callTo(CREDENTIAL_URL);
    expect(credentialCall?.headers.Authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
    expect(credentialCall?.headers.DPoP).toBeUndefined();
  });

  test('DPoP 束縛トークンなのに proof 生成関数が無い場合は Credential Request を出さず fail-closed', async () => {
    const stub = createStubFetch({
      [PAR_URL]: parResponse,
      [TOKEN_URL]: dpopTokenResponse,
      [CREDENTIAL_URL]: credentialResponse,
    });
    const promise = receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(stub));
    await expect(promise).rejects.toThrow(VericertsError);
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.CREDENTIAL_REQUEST_FAILED,
      context: { reason: 'dpop_proof_required' },
    });
    // access_token を平文で 1 度も送らない（Credential Endpoint への呼び出しが 0 件）。
    expect(stub.callTo(CREDENTIAL_URL)).toBeUndefined();
  });
});

describe('receiveCredentialViaAuthorizationCode の token_type 分岐と ath', () => {
  test('Bearer 応答なら createDpopProof を渡しても Credential Request は Bearer・DPoP ヘッダなし', async () => {
    const stub = createStubFetch({
      [PAR_URL]: parResponse,
      [TOKEN_URL]: tokenResponse,
      [CREDENTIAL_URL]: credentialResponse,
    });
    const htus: string[] = [];
    await receiveCredentialViaAuthorizationCode(
      flowOptions(),
      flowDeps(stub, {
        createDpopProof: (htu) => {
          htus.push(htu);
          return proofFor(htu);
        },
      }),
    );
    const credentialCall = stub.callTo(CREDENTIAL_URL);
    expect(credentialCall?.headers.Authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
    expect(credentialCall?.headers.DPoP).toBeUndefined();
    // Credential Endpoint 用の proof は生成しない（PAR / Token 用だけ）。
    expect(htus).toEqual([PAR_URL, TOKEN_URL]);
  });

  test('Credential Endpoint 用の呼び出しにだけ access_token が渡る（ath 用）', async () => {
    const stub = createStubFetch({
      [PAR_URL]: parResponse,
      [TOKEN_URL]: dpopTokenResponse,
      [CREDENTIAL_URL]: credentialResponse,
    });
    const seen: Array<[string, string | undefined]> = [];
    await receiveCredentialViaAuthorizationCode(
      flowOptions(),
      flowDeps(stub, {
        createDpopProof: (htu, ctx) => {
          seen.push([htu, ctx?.accessToken]);
          return proofFor(htu);
        },
      }),
    );
    expect(seen).toEqual([
      [PAR_URL, undefined],
      [TOKEN_URL, undefined],
      [CREDENTIAL_URL, ACCESS_TOKEN],
    ]);
  });
});
