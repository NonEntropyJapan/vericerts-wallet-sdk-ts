import { describe, expect, it } from 'bun:test';
import * as root from '../../../index.js';
import {
  createDidResolutionResources,
  createDidResolver,
  type DidResolutionResources,
} from '../../identity.js';

const MIB = 1024 * 1024;

describe('DID resolution resources: public validation', () => {
  it.each([2 * MIB, 4 * MIB, Number.MAX_SAFE_INTEGER])('accepts capacity %s', (bytes) => {
    const handle = createDidResolutionResources({ maxInflightBytes: bytes });
    expect(Object.isFrozen(handle)).toBe(true);
    expect(Reflect.ownKeys(handle)).toEqual([]);
    expect(Object.getPrototypeOf(handle)).toBe(null);
    expect(createDidResolver({}, { webResolutionResources: handle })).toBeDefined();
  });

  it.each([
    NaN,
    Infinity,
    -Infinity,
    -1,
    0,
    2 * MIB - 1,
    2 * MIB + 0.5,
    2 ** 53,
  ])('rejects invalid numeric capacity %s before resolving', (maxInflightBytes) => {
    expect(() => createDidResolutionResources({ maxInflightBytes })).toThrow(RangeError);
  });

  it.each(
    [undefined, null, [], 4 * MIB, () => undefined, {}, { maxInflightBytes: '4194304' }].map(
      (input) => ({ input }),
    ),
  )('rejects malformed factory options %s', ({ input }) => {
    expect(() =>
      createDidResolutionResources(input as unknown as { maxInflightBytes: number }),
    ).toThrow(TypeError);
  });

  it('does not read an inherited capacity getter and reads an own getter once', () => {
    let inheritedReads = 0;
    const inherited = Object.create({
      get maxInflightBytes() {
        inheritedReads += 1;
        return 4 * MIB;
      },
    });
    expect(() => createDidResolutionResources(inherited)).toThrow(TypeError);
    expect(inheritedReads).toBe(0);
    let reads = 0;
    createDidResolutionResources({
      get maxInflightBytes() {
        reads += 1;
        return 2 * MIB;
      },
    });
    expect(reads).toBe(1);
  });

  it('root and identity share the factory and accept each other’s handles', () => {
    expect(root.createDidResolutionResources).toBe(createDidResolutionResources);
    const fromRoot = root.createDidResolutionResources({ maxInflightBytes: 2 * MIB });
    const fromIdentity = createDidResolutionResources({ maxInflightBytes: 2 * MIB });
    expect(createDidResolver({}, { webResolutionResources: fromRoot })).toBeDefined();
    expect(root.createDidResolver({}, { webResolutionResources: fromIdentity })).toBeDefined();
  });

  it('accepts own non-enumerable options and reads the resource handle once', () => {
    const options = Object.create(null);
    Object.defineProperty(options, 'maxInflightBytes', { value: 2 * MIB });
    const handle = createDidResolutionResources(options);
    let reads = 0;
    const resources = Object.create(null);
    Object.defineProperty(resources, 'webResolutionResources', {
      get() {
        reads += 1;
        return handle;
      },
    });
    expect(createDidResolver({}, resources)).toBeDefined();
    expect(reads).toBe(1);
  });

  it('rejects forged, cloned, inherited and proxy handles', () => {
    const valid = createDidResolutionResources({ maxInflightBytes: 2 * MIB });
    for (const forged of [
      null,
      1,
      'handle',
      [],
      {},
      { ...valid },
      Object.create(valid),
      new Proxy(valid, {}),
    ]) {
      expect(() =>
        createDidResolver({}, { webResolutionResources: forged as DidResolutionResources }),
      ).toThrow(TypeError);
    }
  });

  it.each(
    [null, [], 1, 'resources', () => undefined].map((input) => ({ input })),
  )('rejects malformed resolver resources %s', ({ input }) => {
    expect(() => createDidResolver({}, input as object)).toThrow(TypeError);
  });

  it('rejects inherited resource handles without running their getters', () => {
    let reads = 0;
    const options = Object.create({
      get webResolutionResources() {
        reads += 1;
        return createDidResolutionResources({ maxInflightBytes: 2 * MIB });
      },
    });
    expect(() => createDidResolver({}, options)).toThrow(TypeError);
    expect(reads).toBe(0);
  });

  it('keeps omitted/empty/undefined resources equivalent to the legacy call', async () => {
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    for (const resources of [undefined, {}, { webResolutionResources: undefined }]) {
      expect((await createDidResolver({}, resources).resolve(did)).id).toBe(did);
    }
  });

  it('fails fast on polluted new options without changing legacy calls', async () => {
    Object.defineProperty(Object.prototype, 'webResolutionResources', {
      configurable: true,
      get() {
        throw new Error('inherited getter must not run');
      },
    });
    try {
      expect(() => createDidResolver({}, {})).toThrow(TypeError);
      expect(createDidResolver()).toBeDefined();
    } finally {
      Reflect.deleteProperty(Object.prototype, 'webResolutionResources');
    }
  });
});
