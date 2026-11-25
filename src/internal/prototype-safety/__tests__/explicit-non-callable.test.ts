import { describe, expect, test } from 'bun:test';
import { hasExplicitNonCallableProperty } from '../own-property.js';

describe('explicit non-callable descriptors', () => {
  test('missing descriptors remain unknown, including a null prototype', () => {
    expect(hasExplicitNonCallableProperty({}, 'sign')).toBe(false);
    expect(hasExplicitNonCallableProperty(Object.create(null) as object, 'sign')).toBe(false);
  });

  test('own and inherited data descriptors reject non-functions', () => {
    for (const sign of [undefined, null, false, 0, '', {}, []]) {
      expect(hasExplicitNonCallableProperty({ sign }, 'sign')).toBe(true);
      expect(hasExplicitNonCallableProperty(Object.create({ sign }) as object, 'sign')).toBe(true);
    }
  });

  test('a callable data descriptor is not invoked', () => {
    let calls = 0;
    const source = {
      sign() {
        calls += 1;
      },
    };
    expect(hasExplicitNonCallableProperty(source, 'sign')).toBe(false);
    expect(calls).toBe(0);
  });

  test('a getter remains unknown without being invoked', () => {
    let reads = 0;
    class Source {
      get sign() {
        reads += 1;
        return null;
      }
    }
    expect(hasExplicitNonCallableProperty(new Source(), 'sign')).toBe(false);
    expect(reads).toBe(0);
  });

  test('setter-only and empty accessors are explicitly non-callable', () => {
    let writes = 0;
    const setter = Object.defineProperty({}, 'sign', {
      set(_value) {
        writes += 1;
      },
    });
    const empty = Object.defineProperty({}, 'sign', { get: undefined, set: undefined });
    expect(hasExplicitNonCallableProperty(setter, 'sign')).toBe(true);
    expect(hasExplicitNonCallableProperty(empty, 'sign')).toBe(true);
    expect(writes).toBe(0);
  });

  test('the first own undefined shadows a prototype function', () => {
    const source = Object.create({ sign() {} }) as object;
    Object.defineProperty(source, 'sign', { value: undefined });
    expect(hasExplicitNonCallableProperty(source, 'sign')).toBe(true);
  });

  test('Object.prototype-only descriptors remain unknown and are not evaluated', () => {
    let reads = 0;
    Object.defineProperty(Object.prototype, 'sign', {
      configurable: true,
      get() {
        reads += 1;
        return null;
      },
    });
    let result: boolean;
    try {
      result = hasExplicitNonCallableProperty({}, 'sign');
    } finally {
      Reflect.deleteProperty(Object.prototype, 'sign');
    }
    expect(result).toBe(false);
    expect(reads).toBe(0);
  });

  test('descriptor classification ignores inherited value/get pollution', () => {
    const getter = Object.defineProperty({}, 'sign', { get: () => null });
    const setter = Object.defineProperty({}, 'sign', { set: () => {} });
    const data = { sign() {} };
    const descriptor = Object.assign(Object.create(null), { configurable: true, value: 0 });
    const results: boolean[] = [];
    Object.defineProperty(Object.prototype, 'value', descriptor);
    try {
      results.push(hasExplicitNonCallableProperty(getter, 'sign'));
    } finally {
      Reflect.deleteProperty(Object.prototype, 'value');
    }
    descriptor.value = () => {};
    Object.defineProperty(Object.prototype, 'get', descriptor);
    try {
      results.push(hasExplicitNonCallableProperty(data, 'sign'));
      results.push(hasExplicitNonCallableProperty(setter, 'sign'));
    } finally {
      Reflect.deleteProperty(Object.prototype, 'get');
    }
    expect(results).toEqual([false, false, true]);
  });

  test('virtual get-only proxies remain unknown without reading the value', () => {
    let gets = 0;
    const source = new Proxy(
      {},
      {
        get() {
          gets += 1;
          return () => {};
        },
      },
    );
    expect(hasExplicitNonCallableProperty(source, 'sign')).toBe(false);
    expect(gets).toBe(0);
  });

  test('a contradictory proxy is classified by its descriptor, not its virtual value', () => {
    let gets = 0;
    const source = new Proxy(
      { sign: null },
      {
        get() {
          gets += 1;
          return () => {};
        },
      },
    );
    expect(hasExplicitNonCallableProperty(source, 'sign')).toBe(true);
    expect(gets).toBe(0);
  });

  for (const trap of ['getOwnPropertyDescriptor', 'getPrototypeOf'] as const) {
    test(`${trap} exceptions are preserved`, () => {
      const failure = new Error(trap);
      const source = new Proxy(
        {},
        {
          [trap]: () => {
            throw failure;
          },
        },
      );
      let observed: unknown;
      try {
        hasExplicitNonCallableProperty(source, 'sign');
      } catch (error) {
        observed = error;
      }
      expect(observed).toBe(failure);
    });
  }
});
