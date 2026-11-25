import { afterEach, describe, expect, it } from 'bun:test';
import { createDidResolutionResources, createDidResolver } from '../../identity.js';
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

const failures = [
  { stage: 'web', kind: 'network', code: '2003' },
  { stage: 'web', kind: 'body', code: '2003' },
  { stage: 'web', kind: 'oversize', code: '2003' },
  { stage: 'log', kind: 'network', code: '2003' },
  { stage: 'log', kind: 'body', code: '2003' },
  { stage: 'log', kind: 'signature', code: '2001' },
  { stage: 'witness', kind: 'network', code: '2003' },
  { stage: 'witness', kind: 'body', code: '2003' },
  { stage: 'witness', kind: 'oversize', code: '2003' },
  { stage: 'witness', kind: 'signature', code: '2001' },
];

function brokenSignature(text: string): string {
  const value = JSON.parse(text);
  const proof = Array.isArray(value) ? value[0].proof[0] : value.proof[0];
  const last = proof.proofValue.at(-1);
  proof.proofValue = proof.proofValue.slice(0, -1) + (last === '1' ? '2' : '1');
  return JSON.stringify(value);
}

describe('DID resolution resources: public failure recovery', () => {
  it.each(failures)('$stage $kind releases reservations without exceeding capacity', async ({
    stage,
    kind,
    code,
  }) => {
    const target = await signedLog('failed.example.org', stage === 'witness');
    const fail = deferred();
    const peers = deferred();
    let failedRequestStarted = false;
    const requested = serve(async (url) => {
      if (!url.includes('failed.example.org')) {
        await peers.promise;
        return webResponse(url);
      }
      if (stage === 'witness' && url.endsWith('did.jsonl')) return response(target.text, url);
      failedRequestStarted = true;
      await fail.promise;
      if (kind === 'network') throw new Error('private network detail');
      if (kind === 'body') {
        return response(
          new ReadableStream({
            start(controller) {
              controller.error(new Error('private body detail'));
            },
          }),
          url,
        );
      }
      if (kind === 'oversize') return response('x'.repeat(MIB + 1), url);
      return response(brokenSignature(stage === 'witness' ? target.file : target.text), url);
    });
    const handle = createDidResolutionResources({ maxInflightBytes: 2 * MIB });
    const resolver = createDidResolver({}, { webResolutionResources: handle });
    const failed = resolver.resolve(stage === 'web' ? 'did:web:failed.example.org' : target.did);
    const observedFailure = failed.catch((error: unknown) => error);
    await transition(() => failedRequestStarted);
    const next = [0, 1, 2].map((n) => resolver.resolve(`did:web:peer${n}.example.org`));
    const initialPeerCount = stage === 'witness' ? 0 : 1;
    await transition(
      () => requested.filter((url) => url.includes('peer')).length >= initialPeerCount,
    );
    expect(requested.filter((url) => url.includes('peer'))).toHaveLength(initialPeerCount);
    fail.release();
    const error = await observedFailure;
    expect(error).toMatchObject({ code });
    expect(String(error)).not.toContain('private');
    await transition(() => requested.filter((url) => url.includes('peer')).length >= 2);
    // The failed reservation is fully released, and never released twice: only two peers fit.
    expect(requested.filter((url) => url.includes('peer'))).toHaveLength(2);
    peers.release();
    await Promise.all(next);
    expect(requested.filter((url) => url.includes('peer'))).toHaveLength(3);
  });

  it('releases after the real HTTP AbortController fires and queued requests can proceed', async () => {
    const peers = deferred();
    const originalTimeout = globalThis.setTimeout;
    let abortNow: (() => void) | undefined;
    let signal: AbortSignal | null | undefined;
    // Capture the existing SDK timeout, rather than adding a cancellation API to the resolver.
    globalThis.setTimeout = ((
      callback: (...args: unknown[]) => void,
      delay?: number,
      ...args: unknown[]
    ) => {
      if (delay === 10_000 && abortNow === undefined) {
        abortNow = () => callback(...args);
        return originalTimeout(() => undefined, delay);
      }
      return originalTimeout(callback, delay, ...args);
    }) as typeof setTimeout;
    try {
      const requested = serve(async (url, init) => {
        if (url.includes('abort.example.org')) {
          signal = init?.signal;
          return new Promise<Response>((_resolve, reject) => {
            signal?.addEventListener(
              'abort',
              () => reject(new DOMException('Aborted', 'AbortError')),
              { once: true },
            );
          });
        }
        await peers.promise;
        return webResponse(url);
      });
      const handle = createDidResolutionResources({ maxInflightBytes: 2 * MIB });
      const resolver = createDidResolver({}, { webResolutionResources: handle });
      const failed = resolver.resolve('did:web:abort.example.org');
      const observed = failed.catch((error: unknown) => error);
      await transition(() => signal !== undefined && abortNow !== undefined);
      globalThis.setTimeout = originalTimeout;
      const next = [0, 1, 2].map((n) => resolver.resolve(`did:web:peer${n}.example.org`));
      await transition(() => requested.length >= 2);
      expect(requested).toHaveLength(2);
      abortNow?.();
      expect(await observed).toMatchObject({ code: '2003' });
      expect(signal?.aborted).toBe(true);
      await transition(() => requested.length >= 3);
      expect(requested).toHaveLength(3);
      peers.release();
      await Promise.all(next);
    } finally {
      globalThis.setTimeout = originalTimeout;
      abortNow?.();
      peers.release();
    }
  });
});
