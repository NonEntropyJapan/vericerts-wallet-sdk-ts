/**
 * ファサード `receiveCredential` の相関 ID 伝播。
 *
 * 呼び出し側（Popup / Background SW）が 1 つ渡した相関 ID が、その受領で外へ出る要求すべてに
 * 同じ形で載ることを固定する。grant によって経路が変わる（pre-authorized_code は Token →
 * Credential、authorization_code は下位フローの PAR → Token → Credential）ため、片方だけ配線が
 * 抜けても気付けるよう両経路を見る。
 *
 * Metadata 取得（`fetchIssuerMetadata` / `fetchAuthorizationServerMetadata`）への伝播は対象外であり、ここでは OID4VCI の要求 3 経路のみを対象とする。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../../../errors.js';
import { createCorrelationContext } from '../../../../../observability/correlation.js';
import { receiveCredential } from '../../receive.js';
import {
  AS,
  AS_METADATA_URL,
  asMetadataResponse,
  authorizationCodeDeps,
  authorizationCodeOfferURI,
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  facadeDeps,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  PAR_URL,
  parResponse,
  preAuthorizedOfferURI,
  TOKEN_URL,
  tokenResponse,
} from '../facade-fixtures.js';

const CONTEXT = createCorrelationContext({ requestId: 'popup-click-42' });

/** pre-authorized_code 経路（Issuer Metadata → Token → Credential）の成功スタブ。 */
function preAuthorizedStub(): ReturnType<typeof createStubFetch> {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
    [TOKEN_URL]: tokenResponse(),
    [CREDENTIAL_URL]: credentialResponse,
  });
}

describe('receiveCredential の相関 ID 伝播', () => {
  test('pre-authorized_code 経路の Token / Credential に同じ相関 ID が載る', async () => {
    const stub = preAuthorizedStub();

    await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, { correlationContext: CONTEXT }),
    );

    for (const url of [TOKEN_URL, CREDENTIAL_URL]) {
      expect(stub.callTo(url)?.headers.traceparent).toBe(CONTEXT.traceparent);
      expect(stub.callTo(url)?.headers['X-Request-Id']).toBe(CONTEXT.requestId);
    }
  });

  test('authorization_code 経路では PAR にも同じ相関 ID が載る', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: [AS] }),
      [AS_METADATA_URL]: () => asMetadataResponse(),
      [PAR_URL]: parResponse,
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });

    await receiveCredential(
      authorizationCodeOfferURI(),
      authorizationCodeDeps(stub, { correlationContext: CONTEXT }),
    );

    for (const url of [PAR_URL, TOKEN_URL, CREDENTIAL_URL]) {
      expect(stub.callTo(url)?.headers.traceparent).toBe(CONTEXT.traceparent);
      expect(stub.callTo(url)?.headers['X-Request-Id']).toBe(CONTEXT.requestId);
    }
  });

  test('correlationContext 未指定なら相関ヘッダを出さない（後方互換）', async () => {
    const stub = preAuthorizedStub();

    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));

    for (const url of [TOKEN_URL, CREDENTIAL_URL]) {
      // 要求自体は出ている（ヘッダが無いことの検査が空振りしていないことの担保）。
      expect(stub.callTo(url)).toBeDefined();
      expect(stub.callTo(url)?.headers.traceparent).toBeUndefined();
      expect(stub.callTo(url)?.headers['X-Request-Id']).toBeUndefined();
    }
  });

  test('形の壊れた correlationContext は 8010 で弾き、HTTP を 1 度も出さない', async () => {
    const stub = preAuthorizedStub();
    const deps = facadeDeps(stub, {
      correlationContext: { requestId: 'req-1', traceparent: 123 } as never,
    });

    const error = await receiveCredential(preAuthorizedOfferURI(), deps).then(
      () => undefined,
      (err: unknown) => err as VericertsError,
    );

    expect(error?.code).toBe(ErrorCodes.TOKEN_REQUEST_FAILED);
    // 他の不正な純データ依存（`txCode` / `clientId` 等）と同じ理由コードへ寄せる。
    expect(error?.context).toMatchObject({ reason: 'invalid_receive_deps' });
    expect(stub.calls).toHaveLength(0);
  });
});
