/**
 * ファサード `receiveCredential`（pre-authorized_code）の DPoP nonce 往復（RFC 9449 §8 / §9）。
 *
 * `createDpopProof` へ nonce が渡り、Token / Credential の各 Endpoint で `use_dpop_nonce` を受けたときに
 * 1 回だけ nonce 付き proof で再送されることを、受領フロー全体で固定する。
 */

import { describe, expect, test } from 'bun:test';
import type { DpopProofContext } from '../../../oid4vci-credential-dpop.js';
import { receiveCredential } from '../../receive.js';
import {
  ACCESS_TOKEN,
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  type FetchCall,
  facadeDeps,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  preAuthorizedOfferURI,
  TOKEN_URL,
  tokenResponse,
} from '../facade-fixtures.js';

const TOKEN_NONCE = 'as-nonce';
const CREDENTIAL_NONCE = 'rs-nonce';

/** 初回だけチャレンジを返し、2 回目以降は `ok` を返すルート。 */
function challengeOnce(challenge: () => Response, ok: () => Response): () => Response {
  let first = true;
  return () => {
    if (first) {
      first = false;
      return challenge();
    }
    return ok();
  };
}

describe('receiveCredential: DPoP nonce チャレンジ', () => {
  test('Token は AS の、Credential は RS の nonce で 1 回ずつ再送し、受領できる', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: challengeOnce(
        () =>
          new Response(JSON.stringify({ error: 'use_dpop_nonce' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', 'DPoP-Nonce': TOKEN_NONCE },
          }),
        tokenResponse('DPoP'),
      ),
      [CREDENTIAL_URL]: challengeOnce(
        () =>
          new Response('', {
            status: 401,
            headers: {
              'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
              'DPoP-Nonce': CREDENTIAL_NONCE,
            },
          }),
        credentialResponse,
      ),
    });
    const proofRequests: { htu: string; ctx: DpopProofContext | undefined }[] = [];
    const received = await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, {
        createDpopProof: (htu, ctx) => {
          proofRequests.push({ htu, ctx });
          return `proof(${htu},${ctx?.nonce ?? '-'})`;
        },
      }),
    );
    expect(received.raw).toBeString();

    const dpopHeaders = (url: string): (string | undefined)[] =>
      stub.calls.filter((c: FetchCall) => c.url === url).map((c) => c.headers.DPoP);
    expect(dpopHeaders(TOKEN_URL)).toEqual([
      `proof(${TOKEN_URL},-)`,
      `proof(${TOKEN_URL},${TOKEN_NONCE})`,
    ]);
    expect(dpopHeaders(CREDENTIAL_URL)).toEqual([
      `proof(${CREDENTIAL_URL},-)`,
      `proof(${CREDENTIAL_URL},${CREDENTIAL_NONCE})`,
    ]);
    // Credential の proof は再送でも access_token（`ath`）を引き継ぐ。nonce は宛先ごとで持ち越さない。
    const credentialCtxs = proofRequests.filter((r) => r.htu === CREDENTIAL_URL).map((r) => r.ctx);
    expect(credentialCtxs).toEqual([
      { accessToken: ACCESS_TOKEN },
      { accessToken: ACCESS_TOKEN, nonce: CREDENTIAL_NONCE },
    ]);
  });
});
