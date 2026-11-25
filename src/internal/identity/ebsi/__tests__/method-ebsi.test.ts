/**
 * MethodEbsi の `DIDMethod` 契約（登録・`create` / `update` / `deactivate` の `2002`・キャッシュ）の検証。
 * 取得は `fetchFn` 注入のモックで行う。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import {
  expectRejects,
  jsonReply,
  recordingFetch,
} from '../../__tests__/network-method.fixtures.js';
import { createResolutionWorkBudget } from '../../resolution-budget.js';
import { Resolver } from '../../resolver.js';
import { MethodEbsi } from '../method-ebsi.js';
import { API_URL, DID, ebsiDocument } from './ebsi.fixtures.js';

describe('MethodEbsi', () => {
  it('キャッシュ命中でも呼び出しの本文予算に計上し、不足時は 2001', async () => {
    const body = JSON.stringify(ebsiDocument());
    const { fetchFn, calls } = recordingFetch(() => ({ body }));
    const method = new MethodEbsi({ apiUrl: API_URL, fetchFn });
    await method.resolve(DID);
    const scope = createResolutionWorkBudget(undefined, body.length + 1);
    await method.resolve(DID, scope);
    expect(scope.remainingBodyLength).toBe(1);
    await expectRejects(
      method.resolve(DID, scope),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(calls).toHaveLength(1);
  });

  it('method() は ebsi。create / update / deactivate は 2002', async () => {
    const method = new MethodEbsi({ apiUrl: API_URL });
    expect(method.method()).toBe('ebsi');
    await expectRejects(
      method.create({ keyType: 'P-256', publicKey: new Uint8Array(33) }),
      ErrorCodes.METHOD_NOT_SUPPORTED,
    );
    await expectRejects(method.update(DID, {}), ErrorCodes.METHOD_NOT_SUPPORTED);
    await expectRejects(method.deactivate(DID), ErrorCodes.METHOD_NOT_SUPPORTED);
  });

  it('Resolver に登録すると解決でき、2002 で拒否しなくなる', async () => {
    const { fetchFn } = recordingFetch(() => jsonReply(ebsiDocument()));
    const resolver = new Resolver();
    await expectRejects(resolver.resolve(DID), ErrorCodes.METHOD_NOT_SUPPORTED);
    resolver.register(new MethodEbsi({ apiUrl: API_URL, fetchFn }));
    expect((await resolver.resolve(DID)).id).toBe(DID);
  });

  it('resolve は valid-at なし、resolveAt は valid-at 付きで取得する', async () => {
    const { fetchFn, calls } = recordingFetch(() => jsonReply(ebsiDocument()));
    const method = new MethodEbsi({ apiUrl: API_URL, fetchFn });
    await method.resolve(DID);
    await method.resolveAt(DID, '2026-01-01T00:00:00Z');
    expect(calls.map((call) => call.url)).toEqual([
      `${API_URL}/v1/did-registry/identifiers/${DID}`,
      `${API_URL}/v1/did-registry/identifiers/${DID}?valid-at=2026-01-01T00%3A00%3A00Z`,
    ]);
  });

  it('キャッシュのキーは (did, validAt)。TTL（上限 600 秒）後は取り直し、失敗は記憶しない', async () => {
    let now = 1_000;
    let failing = true;
    const { fetchFn, calls } = recordingFetch(() => {
      if (failing) {
        return { status: 503, body: '' };
      }
      return jsonReply(ebsiDocument());
    });
    const method = new MethodEbsi({ apiUrl: API_URL, fetchFn, nowSeconds: () => now });
    await expectRejects(method.resolve(DID), ErrorCodes.DID_NOT_FOUND);
    failing = false;
    await method.resolve(DID);
    await method.resolve(DID);
    expect(calls).toHaveLength(2);
    await method.resolveAt(DID, '2026-01-01T00:00:00Z');
    await method.resolveAt(DID, '2026-01-01T00:00:00Z');
    expect(calls).toHaveLength(3);
    now += 599;
    await method.resolve(DID);
    expect(calls).toHaveLength(3);
    now += 1;
    await method.resolve(DID);
    expect(calls).toHaveLength(4);
  });

  it('キャッシュ命中でも形式不正の DID は取得せず 2001', async () => {
    const { fetchFn, calls } = recordingFetch(() => jsonReply(ebsiDocument()));
    const method = new MethodEbsi({ apiUrl: API_URL, fetchFn });
    await expectRejects(
      method.resolve('did:ebsi:test:zabc'),
      ErrorCodes.INVALID_DID,
      'ebsi_unsupported_form',
    );
    expect(calls).toHaveLength(0);
  });
});
