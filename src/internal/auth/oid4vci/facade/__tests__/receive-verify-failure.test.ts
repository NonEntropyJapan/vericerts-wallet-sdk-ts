/**
 * `receiveCredential`（内部ファサード）の `deps.verifyReceived` が失敗したときの失敗コード。
 *
 * 署名不一致（`3010`）と `VericertsError` でない例外だけを `3010`
 * （`received_credential_signature_invalid`）へ正規化し、`3002` / `3024` など署名不一致以外の
 * `VericertsError` は元のコードのまま返す。フックの基本契約（throw → `3010`・生 VC を渡す・
 * 未指定なら呼ばない）は `receive.test.ts` にある。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { receiveCredential } from '../receive.js';
import {
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  facadeDeps,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  preAuthorizedOfferURI,
  type StubFetch,
  TOKEN_URL,
  tokenResponse,
} from './facade-fixtures.js';

function preAuthorizedStub(): StubFetch {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
    [TOKEN_URL]: tokenResponse(),
    [CREDENTIAL_URL]: credentialResponse,
  });
}

describe('receiveCredential: verifyReceived の失敗コード', () => {
  test('VericertsError（3010 以外）はそのコードを潰さず、同じ例外を伝播する', async () => {
    const original = new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    await expect(
      receiveCredential(
        preAuthorizedOfferURI(),
        facadeDeps(preAuthorizedStub(), {
          verifyReceived: () => {
            throw original;
          },
        }),
      ),
    ).rejects.toBe(original);
  });

  test('3010 の VericertsError は received_credential_signature_invalid の 3010 になる', async () => {
    await expect(
      receiveCredential(
        preAuthorizedOfferURI(),
        facadeDeps(preAuthorizedStub(), {
          verifyReceived: () => {
            throw new VericertsError(ErrorCodes.SIG_INVALID);
          },
        }),
      ),
    ).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
      context: { reason: 'received_credential_signature_invalid' },
    });
  });
});
