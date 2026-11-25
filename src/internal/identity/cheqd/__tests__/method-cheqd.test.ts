/**
 * MethodCheqd の `DIDMethod` 契約（登録・`create` / `update` / `deactivate` の `2002`・キャッシュ）の検証。
 * 取得は `fetchFn` 注入のモックで行う。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { expectRejects, recordingFetch } from '../../__tests__/network-method.fixtures.js';
import { createResolutionWorkBudget } from '../../resolution-budget.js';
import { Resolver } from '../../resolver.js';
import { MethodCheqd } from '../method-cheqd.js';
import {
  LIVE_DID,
  LIVE_VERSION_ID,
  RESOLUTION_CONTENT_TYPE,
  RESOLVER_URL,
  resolutionResult,
} from './cheqd.fixtures.js';

const reply = (value: unknown, status = 200) => ({
  status,
  contentType: RESOLUTION_CONTENT_TYPE,
  body: JSON.stringify(value),
});

describe('MethodCheqd', () => {
  it('キャッシュ命中でも呼び出しの本文予算に計上し、不足時は 2001', async () => {
    const body = JSON.stringify(resolutionResult(LIVE_DID));
    const { fetchFn, calls } = recordingFetch(() => ({ body }));
    const method = new MethodCheqd({ fetchFn });
    await method.resolve(LIVE_DID);
    const scope = createResolutionWorkBudget(undefined, body.length + 1);
    await method.resolve(LIVE_DID, scope);
    expect(scope.remainingBodyLength).toBe(1);
    await expectRejects(
      method.resolveWithMetadata(LIVE_DID, scope),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(calls).toHaveLength(1);
  });

  it('method() は cheqd。create / update / deactivate は 2002', async () => {
    const method = new MethodCheqd();
    expect(method.method()).toBe('cheqd');
    await expectRejects(
      method.create({ keyType: 'Ed25519', publicKey: new Uint8Array(32) }),
      ErrorCodes.METHOD_NOT_SUPPORTED,
    );
    await expectRejects(method.update(LIVE_DID, {}), ErrorCodes.METHOD_NOT_SUPPORTED);
    await expectRejects(method.deactivate(LIVE_DID), ErrorCodes.METHOD_NOT_SUPPORTED);
  });

  it('Resolver に登録すると解決でき、2002 で拒否しなくなる', async () => {
    const { fetchFn } = recordingFetch(() => reply(resolutionResult(LIVE_DID)));
    const resolver = new Resolver();
    await expectRejects(resolver.resolve(LIVE_DID), ErrorCodes.METHOD_NOT_SUPPORTED);
    resolver.register(new MethodCheqd({ resolverUrl: RESOLVER_URL, fetchFn }));
    expect((await resolver.resolve(LIVE_DID)).id).toBe(LIVE_DID);
  });

  it('resolveWithMetadata は versionId / deactivated を返す', async () => {
    const { fetchFn } = recordingFetch(() => reply(resolutionResult(LIVE_DID)));
    const { metadata } = await new MethodCheqd({
      resolverUrl: RESOLVER_URL,
      fetchFn,
    }).resolveWithMetadata(LIVE_DID);
    expect(metadata).toEqual({ deactivated: false, versionId: LIVE_VERSION_ID });
  });

  it('キャッシュは DID ごと・TTL 600 秒。失敗は記憶しない', async () => {
    let now = 9_000;
    let failing = true;
    const { fetchFn, calls } = recordingFetch(() =>
      failing ? { status: 502, body: '' } : reply(resolutionResult(LIVE_DID)),
    );
    const method = new MethodCheqd({ resolverUrl: RESOLVER_URL, fetchFn, nowSeconds: () => now });
    await expectRejects(method.resolve(LIVE_DID), ErrorCodes.DID_NOT_FOUND);
    failing = false;
    await method.resolve(LIVE_DID);
    await method.resolve(LIVE_DID);
    expect(calls).toHaveLength(2);
    now += 599;
    await method.resolve(LIVE_DID);
    expect(calls).toHaveLength(2);
    now += 1;
    await method.resolve(LIVE_DID);
    expect(calls).toHaveLength(3);
  });

  it('形式不正の DID はキャッシュ・ネットワークに触れず 2001', async () => {
    const { fetchFn, calls } = recordingFetch(() => reply(resolutionResult(LIVE_DID)));
    await expectRejects(
      new MethodCheqd({ fetchFn }).resolve('did:cheqd:abc'),
      ErrorCodes.INVALID_DID,
    );
    expect(calls).toHaveLength(0);
  });
});
