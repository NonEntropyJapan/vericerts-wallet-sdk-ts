import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { submitPlcOperation } from '../lifecycle.js';
import { expectVericertsError, genesis, makeKey, nextOperation } from './plc.fixtures.js';

const forbiddenServices = { religion: { type: 'T', endpoint: 'https://example.com' } };

function capture() {
  const bodies: string[] = [];
  const fetchFn = (async (_input: string | URL | Request, init?: RequestInit) => {
    bodies.push(String(init?.body));
    return new Response(null, { status: 200 });
  }) as typeof fetch;
  return { bodies, fetchFn };
}

describe('submitPlcOperation の送信本文スナップショット', () => {
  for (const placement of ['operation', 'services'] as const) {
    it(`${placement} の非列挙 toJSON が追加した禁止属性を送信前に拒否する`, async () => {
      const key = makeKey();
      const g = await genesis(key);
      const operation = await nextOperation(g.did, g.entries[0] as never, g.data, key);
      const serialized = { ...operation, services: forbiddenServices };
      Object.defineProperty(placement === 'operation' ? operation : operation.services, 'toJSON', {
        value: () => (placement === 'operation' ? serialized : forbiddenServices),
      });
      const { fetchFn, bodies } = capture();
      await expectVericertsError(
        () => submitPlcOperation(g.did, operation, { fetchFn }),
        ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN,
      );
      expect(bodies).toEqual([]);
    });
  }

  it('toJSON 後のジェネシス本文から DID を再計算する', async () => {
    const g = await genesis(makeKey());
    const changed = { ...g.operation, alsoKnownAs: ['at://changed.example'] };
    Object.defineProperty(g.operation, 'toJSON', { value: () => changed });
    const { fetchFn, bodies } = capture();
    await expectVericertsError(
      () => submitPlcOperation(g.did, g.operation, { fetchFn }),
      ErrorCodes.INVALID_DID,
      'plc_operation_invalid',
    );
    expect(bodies).toEqual([]);
  });

  it('入れ子の getter を一度だけ読み、検査した本文をそのまま送る', async () => {
    const g = await genesis(makeKey());
    const expected = JSON.stringify(g.operation);
    const services = g.operation.services as { atproto_pds: { endpoint: string } };
    const endpoint = services.atproto_pds.endpoint;
    let reads = 0;
    Object.defineProperty(services.atproto_pds, 'endpoint', {
      enumerable: true,
      get: () => {
        reads++;
        return reads === 1 ? endpoint : 'https://changed.example';
      },
    });
    const { fetchFn, bodies } = capture();
    await submitPlcOperation(g.did, g.operation, { fetchFn });
    expect(reads).toBe(1);
    expect(bodies).toEqual([expected]);
  });

  it('設定 getter が検査後に元入力を変更しても送信本文は変わらない', async () => {
    const g = await genesis(makeKey());
    const expected = JSON.stringify(g.operation);
    const { fetchFn, bodies } = capture();
    await submitPlcOperation(g.did, g.operation, {
      fetchFn,
      get directoryUrl() {
        g.operation.services = forbiddenServices;
        return 'https://plc.directory';
      },
    });
    expect(bodies).toEqual([expected]);
  });

  it('直列化失敗・undefined / 配列への変換は 2001 にし、送信しない', async () => {
    const { fetchFn, bodies } = capture();
    for (const toJSON of [
      () => undefined,
      () => [],
      () => {
        throw new Error('private input');
      },
    ]) {
      const g = await genesis(makeKey());
      Object.defineProperty(g.operation, 'toJSON', { value: toJSON });
      await expectVericertsError(
        () => submitPlcOperation(g.did, g.operation, { fetchFn }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
    }
    expect(bodies).toEqual([]);
  });
});
