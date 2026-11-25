import { afterEach, describe, expect, it } from 'bun:test';
import { p256Jwk } from '../../../internal/identity/__tests__/network-method.fixtures.js';
import {
  API_URL,
  DID as EBSI_DID,
  ebsiDocument,
} from '../../../internal/identity/ebsi/__tests__/ebsi.fixtures.js';
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

describe('DID resolution resources: public HTTP scheduling', () => {
  it('shares 4 MiB across web/webvh, resolver regeneration and uncached calls, in FIFO order', async () => {
    const log = await signedLog('log.example.org');
    const gates = Array.from({ length: 6 }, deferred);
    const requested = serve(async (url) => {
      const index = url.includes('log.example.org') ? 3 : Number(new URL(url).hostname[1]);
      await gates[index]?.promise;
      return index === 3 ? response(log.text, url) : webResponse(url);
    });
    const handle = createDidResolutionResources({ maxInflightBytes: 4 * MIB });
    const first = createDidResolver({}, { webResolutionResources: handle });
    const rebuilt = createDidResolver({ rpcUrls: {} }, { webResolutionResources: handle });
    const jobs = [
      first.resolve('did:web:h0.example.org'),
      rebuilt.resolveUncached('did:web:h1.example.org'),
      first.resolve('did:web:h2.example.org'),
      rebuilt.resolve(log.did),
      first.resolve('did:web:h4.example.org'),
      rebuilt.resolveUncached('did:web:h5.example.org'),
    ];
    await transition(() => requested.length >= 4);
    expect(requested).toHaveLength(4);
    gates[0]?.release();
    await transition(() => requested.length === 5);
    expect(requested[4]).toContain('h4.example.org');
    gates[1]?.release();
    await transition(() => requested.length === 6);
    expect(requested[5]).toContain('h5.example.org');
    for (const gate of gates) gate.release();
    expect((await Promise.all(jobs)).map((doc) => doc.id)).toEqual([
      'did:web:h0.example.org',
      'did:web:h1.example.org',
      'did:web:h2.example.org',
      log.did,
      'did:web:h4.example.org',
      'did:web:h5.example.org',
    ]);
  });

  it('keeps the existing per-resolver cache and observes rotation with resolveUncached', async () => {
    let keySeed = 1;
    const requested = serve(async (url) => {
      const id = 'did:web:rotate.example.org';
      const result = response(
        JSON.stringify({
          '@context': ['https://www.w3.org/ns/did/v1'],
          id,
          verificationMethod: [
            {
              id: `${id}#key`,
              controller: id,
              type: 'JsonWebKey2020',
              publicKeyJwk: p256Jwk(keySeed),
            },
          ],
          assertionMethod: [`${id}#key`],
        }),
        url,
      );
      result.headers.set('cache-control', 'max-age=600');
      return result;
    });
    const handle = createDidResolutionResources({ maxInflightBytes: 2 * MIB });
    const resolver = createDidResolver({}, { webResolutionResources: handle });
    const did = 'did:web:rotate.example.org';
    const old = await resolver.resolve(did);
    keySeed = 2;
    expect(await resolver.resolve(did)).toEqual(old);
    const rotated = await resolver.resolveUncached(did);
    expect(rotated.verificationMethod?.[0]?.publicKeyJwk).toEqual(p256Jwk(2));
    expect(rotated).not.toEqual(old);
    expect(await resolver.resolve(did)).toEqual(old);
    expect(requested).toHaveLength(2);
  });

  it('does not impose an implicit capacity or block other DID methods', async () => {
    const gate = deferred();
    const requested = serve(async (url) => {
      if (url.startsWith(API_URL)) return response(JSON.stringify(ebsiDocument(EBSI_DID)), url);
      await gate.promise;
      return webResponse(url);
    });
    const handle = createDidResolutionResources({ maxInflightBytes: 2 * MIB });
    const limited = createDidResolver(
      { didNodeUrls: { ebsi: API_URL } },
      { webResolutionResources: handle },
    );
    const pending = [
      limited.resolve('did:web:h0.example.org'),
      limited.resolve('did:web:h1.example.org'),
    ];
    const key = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    expect((await limited.resolve(key)).id).toBe(key);
    expect((await limited.resolve(EBSI_DID)).id).toBe(EBSI_DID);
    const legacy = createDidResolver();
    for (let i = 2; i < 7; i += 1) pending.push(legacy.resolve(`did:web:h${i}.example.org`));
    await transition(() => requested.length >= 8);
    expect(requested).toHaveLength(8);
    gate.release();
    await Promise.all(pending);
  });
});
