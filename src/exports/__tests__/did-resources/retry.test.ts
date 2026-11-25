import { afterEach, describe, expect, it } from 'bun:test';
import {
  createDidResolutionResources,
  createDidResolver,
  type ResolutionWorkBudget,
} from '../../identity.js';
import {
  deferred,
  MIB,
  originalFetch,
  response,
  serve,
  signedLog,
  transition,
  webResponse,
} from './http-fixtures.js';

afterEach(() => {
  globalThis.fetch = originalFetch;
});
const units = 10_000;
const body = MIB;
const budget = (): ResolutionWorkBudget => ({ remaining: units, remainingBodyLength: body });

async function retryFixture(
  target: Awaited<ReturnType<typeof signedLog>>,
  scope: ResolutionWorkBudget,
  options: { failRetry?: boolean; sharedBlocker?: boolean } = {},
) {
  const blocker = deferred();
  const witness = deferred();
  let logCount = 0;
  const requests = serve(async (url) => {
    if (url.includes('block.example.org')) {
      await blocker.promise;
      return webResponse(url);
    }
    if (url.endsWith('did-witness.json')) {
      await witness.promise;
      return response(target.file, url);
    }
    if (url.endsWith('did.jsonl')) {
      logCount += 1;
      return logCount > 1 && options.failRetry
        ? new Response('', { status: 404 })
        : response(target.text, url);
    }
    return webResponse(url);
  });
  const resources = createDidResolutionResources({ maxInflightBytes: 2 * MIB });
  const resolver = createDidResolver({}, { webResolutionResources: resources });
  const held = resolver.resolve(
    'did:web:block.example.org',
    options.sharedBlocker ? scope : undefined,
  );
  await transition(() => requests.length === 1);
  const result = resolver.resolve(target.did, scope);
  void result.catch(() => undefined);
  await transition(() => logCount === 1);
  await Bun.sleep(0);
  return { resolver, result, held, blocker, witness, requests, logCount: () => logCount };
}

async function controlCost(target: Awaited<ReturnType<typeof signedLog>>) {
  serve(async (url) => response(url.endsWith('did-witness.json') ? target.file : target.text, url));
  const scope = budget();
  const resources = createDidResolutionResources({ maxInflightBytes: 2 * MIB });
  await createDidResolver({}, { webResolutionResources: resources }).resolve(target.did, scope);
  return { units: units - scope.remaining, body: body - scope.remainingBodyLength };
}

describe('DID resolution resources: real signed witness retry', () => {
  it('releases log reservation before atomically queueing 2 MiB and preserves FIFO', async () => {
    const target = await signedLog('retry.example.org', true, 2);
    const f = await retryFixture(target, budget());
    const late = f.resolver.resolve('did:web:late.example.org');
    expect(f.requests).toHaveLength(2);
    expect(f.requests.some((url) => url.endsWith('did-witness.json'))).toBe(false);
    f.blocker.release();
    await transition(() => f.requests.some((url) => url.endsWith('did-witness.json')));
    expect(f.logCount()).toBe(2);
    expect(f.requests.some((url) => url.includes('late.example.org'))).toBe(false);
    f.witness.release();
    const [document] = await Promise.all([f.result, f.held, late]);
    expect(document.id).toBe(target.did);
    expect(f.requests.at(-1)).toContain('late.example.org');
    expect(f.requests.filter((url) => url.endsWith('did-witness.json'))).toHaveLength(1);
  });

  it('charges one successful resolution even at the exact work/body limits', async () => {
    const target = await signedLog('tight.example.org', true, 3);
    const cost = await controlCost(target);
    expect(cost.units).toBeGreaterThan(0);
    expect(cost.body).toBeGreaterThan(0);
    const scope = { remaining: cost.units, remainingBodyLength: cost.body };
    const f = await retryFixture(target, scope);
    f.blocker.release();
    f.witness.release();
    await Promise.all([f.result, f.held]);
    expect(scope).toEqual({ remaining: 0, remainingBodyLength: 0 });
    expect(f.logCount()).toBe(2);
  });

  it('retains the first attempt charge when the retry fails cheaply', async () => {
    const target = await signedLog('cheap.example.org', true, 3);
    const scope = budget();
    const f = await retryFixture(target, scope, { failRetry: true });
    const afterFirst = { ...scope };
    expect(afterFirst.remaining).toBeLessThan(units);
    expect(afterFirst.remainingBodyLength).toBeLessThan(body);
    f.blocker.release();
    f.witness.release();
    await expect(f.result).rejects.toMatchObject({ code: '2003' });
    await f.held;
    expect(scope).toEqual(afterFirst);
    expect((await f.resolver.resolve('did:web:next.example.org')).id).toBe(
      'did:web:next.example.org',
    );
  });

  it('preserves parallel consumption by another resolve in the same scope', async () => {
    const target = await signedLog('shared-scope.example.org', true, 2);
    const cost = await controlCost(target);
    const webBody = await webResponse('https://block.example.org/.well-known/did.json').text();
    const scope = budget();
    const f = await retryFixture(target, scope, { sharedBlocker: true });
    f.blocker.release();
    f.witness.release();
    await Promise.all([f.result, f.held]);
    expect(scope.remaining).toBe(units - cost.units);
    expect(scope.remainingBodyLength).toBe(body - cost.body - webBody.length);
  });

  it('never carries retry credit into a later resolve', async () => {
    const target = await signedLog('next-scope.example.org', true, 2);
    const cost = await controlCost(target);
    const scope = budget();
    const f = await retryFixture(target, scope);
    f.blocker.release();
    f.witness.release();
    await Promise.all([f.result, f.held]);
    const before = { ...scope };
    await f.resolver.resolve(target.did, scope);
    expect(before.remaining - scope.remaining).toBe(cost.units);
    expect(before.remainingBodyLength - scope.remainingBodyLength).toBe(cost.body);
    expect(f.logCount()).toBe(3);
  });

  it('verifies witness without retry when the extra MiB is available', async () => {
    const target = await signedLog('spare.example.org', true);
    const calls = serve(async (url) =>
      response(url.endsWith('did-witness.json') ? target.file : target.text, url),
    );
    const handle = createDidResolutionResources({ maxInflightBytes: 2 * MIB });
    expect(
      (await createDidResolver({}, { webResolutionResources: handle }).resolve(target.did)).id,
    ).toBe(target.did);
    expect(calls.filter((url) => url.endsWith('did.jsonl'))).toHaveLength(1);
    expect(calls.filter((url) => url.endsWith('did-witness.json'))).toHaveLength(1);
  });
});
