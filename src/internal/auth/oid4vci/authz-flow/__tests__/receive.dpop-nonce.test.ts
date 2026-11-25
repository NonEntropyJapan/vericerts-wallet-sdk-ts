/**
 * Authorization Code Flow の DPoP nonce 再送の配線（RFC 9449 §8 / §9）。
 *
 * PAR・Token・Credential の各 Endpoint が `use_dpop_nonce` を返したとき、`createDpopProof` に
 * 渡る `(htu, ctx)` が「宛先ごとの `htu`・宛先ごとの nonce・Credential だけ `accessToken`（`ath`）」に
 * なることを固定する。配線（`dpopProofRebuilder`）の削除・`htu` の取り違え・`accessToken` 欠落は
 * `facade/__tests__/receive-dpop-nonce.test.ts`（pre-authorized_code 経路のみ）では検知できない。
 */

import { describe, expect, test } from 'bun:test';
import type { DpopProofContext } from '../../oid4vci-credential-dpop.js';
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
} from './flow-fixtures.js';

const PAR_NONCE = 'par-nonce';
const TOKEN_NONCE = 'token-nonce';
const CREDENTIAL_NONCE = 'credential-nonce';

/** AS（PAR / Token）の `400 use_dpop_nonce` チャレンジ（RFC 9449 §8）。 */
const asChallenge = (nonce: string) => (): Response =>
  new Response(JSON.stringify({ error: 'use_dpop_nonce' }), {
    status: 400,
    headers: { 'Content-Type': 'application/json', 'DPoP-Nonce': nonce },
  });

/** RS（Credential）の `401 WWW-Authenticate: DPoP error="use_dpop_nonce"` チャレンジ（§9）。 */
const rsChallenge = (nonce: string) => (): Response =>
  new Response('', {
    status: 401,
    headers: { 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"', 'DPoP-Nonce': nonce },
  });

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

describe('receiveCredentialViaAuthorizationCode: DPoP nonce 再送の配線', () => {
  test('PAR / Token / Credential が各自の nonce で 1 回ずつ再送され、htu と accessToken が宛先ごとに正しい', async () => {
    const stub = createStubFetch({
      [PAR_URL]: challengeOnce(asChallenge(PAR_NONCE), parResponse),
      [TOKEN_URL]: challengeOnce(asChallenge(TOKEN_NONCE), dpopTokenResponse),
      [CREDENTIAL_URL]: challengeOnce(rsChallenge(CREDENTIAL_NONCE), credentialResponse),
    });
    const proofRequests: { htu: string; ctx: DpopProofContext | undefined }[] = [];
    const result = await receiveCredentialViaAuthorizationCode(
      flowOptions(),
      flowDeps(stub, {
        createDpopProof: (htu, ctx) => {
          proofRequests.push({ htu, ctx });
          return `proof(${htu},${ctx?.nonce ?? '-'})`;
        },
      }),
    );
    expect(result.status).toBe('issued');

    // 各宛先へ「初回（nonce なし）→ 再送（その宛先の nonce）」の 2 回だけ。htu は宛先自身。
    const dpopHeaders = (url: string): (string | undefined)[] =>
      stub.calls.filter((c) => c.url === url).map((c) => c.headers.DPoP);
    expect(dpopHeaders(PAR_URL)).toEqual([`proof(${PAR_URL},-)`, `proof(${PAR_URL},${PAR_NONCE})`]);
    expect(dpopHeaders(TOKEN_URL)).toEqual([
      `proof(${TOKEN_URL},-)`,
      `proof(${TOKEN_URL},${TOKEN_NONCE})`,
    ]);
    expect(dpopHeaders(CREDENTIAL_URL)).toEqual([
      `proof(${CREDENTIAL_URL},-)`,
      `proof(${CREDENTIAL_URL},${CREDENTIAL_NONCE})`,
    ]);

    // `createDpopProof` に渡る文脈。PAR / Token は access_token を持たず、Credential だけが再送でも
    // `accessToken`（`ath`）を引き継ぐ。nonce は宛先ごとで、別宛先へ持ち越さない。
    expect(proofRequests).toEqual([
      { htu: PAR_URL, ctx: undefined },
      { htu: PAR_URL, ctx: { nonce: PAR_NONCE } },
      { htu: TOKEN_URL, ctx: undefined },
      { htu: TOKEN_URL, ctx: { nonce: TOKEN_NONCE } },
      { htu: CREDENTIAL_URL, ctx: { accessToken: ACCESS_TOKEN } },
      { htu: CREDENTIAL_URL, ctx: { accessToken: ACCESS_TOKEN, nonce: CREDENTIAL_NONCE } },
    ]);
  });

  test('再送後の応答が再びチャレンジでも再々送しない（宛先ごとにちょうど 2 回）', async () => {
    const stub = createStubFetch({
      [PAR_URL]: asChallenge(PAR_NONCE),
    });
    let proofs = 0;
    await receiveCredentialViaAuthorizationCode(
      flowOptions(),
      flowDeps(stub, {
        createDpopProof: (htu) => {
          proofs += 1;
          return `proof(${htu})`;
        },
      }),
    ).catch(() => undefined);
    expect(stub.calls.filter((c) => c.url === PAR_URL)).toHaveLength(2);
    expect(proofs).toBe(2);
  });
});
