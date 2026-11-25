/**
 * Authorization Code Flow の相関 ID 配線。
 *
 * DPoP proof（`receive.dpop.test.ts`）とは対照的に、相関 ID は**送信先ごとに作り分けず
 * 3 経路すべてに同じ値を載せる**（1 回のユーザー操作 = 1 本のトレース）。ここが崩れると
 * PAR / Token / Credential が別トレースに割れ、同じ受領処理を追跡できない。
 *
 * 併せて、形の壊れた `correlationContext` が他の不正な依存と同じく 8010 で弾かれ、HTTP が
 * 1 度も出ないことを固定する（`deps.ts` の検証境界）。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../../errors.js';
import { createCorrelationContext } from '../../../../observability/correlation.js';
import { receiveCredentialViaAuthorizationCode } from '../receive.js';
import type { AuthorizationCodeFlowDeps } from '../types.js';
import {
  CREDENTIAL_URL,
  createHappyStub,
  flowDeps,
  flowOptions,
  PAR_URL,
  TOKEN_URL,
} from './flow-fixtures.js';

const CONTEXT = createCorrelationContext({ requestId: 'popup-click-42' });

describe('receiveCredentialViaAuthorizationCode の相関 ID', () => {
  test('PAR / Token / Credential の 3 経路に同じ traceparent / X-Request-Id が載る', async () => {
    const stub = createHappyStub();

    const result = await receiveCredentialViaAuthorizationCode(
      flowOptions(),
      flowDeps(stub, { correlationContext: CONTEXT }),
    );

    expect(result.status).toBe('issued');
    for (const url of [PAR_URL, TOKEN_URL, CREDENTIAL_URL]) {
      expect(stub.callTo(url)?.headers.traceparent).toBe(CONTEXT.traceparent);
      expect(stub.callTo(url)?.headers['X-Request-Id']).toBe(CONTEXT.requestId);
    }
  });

  test('correlationContext 未指定なら 3 経路とも相関ヘッダを出さない（後方互換）', async () => {
    const stub = createHappyStub();

    await receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(stub));

    for (const url of [PAR_URL, TOKEN_URL, CREDENTIAL_URL]) {
      // 3 経路とも実際に出ている（ヘッダが無いことの検査が空振りしていないことの担保）。
      expect(stub.callTo(url)).toBeDefined();
      expect(stub.callTo(url)?.headers.traceparent).toBeUndefined();
      expect(stub.callTo(url)?.headers['X-Request-Id']).toBeUndefined();
    }
  });

  test('形の壊れた correlationContext は 8010 で弾き、HTTP を 1 度も出さない', async () => {
    const stub = createHappyStub();
    const deps = flowDeps(stub, {
      correlationContext: { requestId: 'req-1', traceparent: 123 } as never,
    }) as AuthorizationCodeFlowDeps;

    const error = await receiveCredentialViaAuthorizationCode(flowOptions(), deps).then(
      () => undefined,
      (err: unknown) => err as VericertsError,
    );

    expect(error?.code).toBe(ErrorCodes.TOKEN_REQUEST_FAILED);
    // 他の不正な純データ依存（`holderDid` / `keyId`）と同じ理由コードへ寄せる。
    expect(error?.context).toMatchObject({ reason: 'invalid_flow_deps' });
    expect(stub.calls).toHaveLength(0);
  });
});
