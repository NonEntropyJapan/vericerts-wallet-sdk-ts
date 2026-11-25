import { describe, expect, test } from 'bun:test';
import { callsTo, receiveFixtures, signerWithDescriptor } from './fixtures.js';

for (const [name, create] of receiveFixtures) {
  describe(`${name}: original proof-time dispatch`, () => {
    for (const throws of [false, true]) {
      test(`Token-time method replacement ${throws ? 'throws before Credential' : 'continues to Credential'}`, async () => {
        const fixture = create();
        let oldCalls = 0;
        let newCalls = 0;
        const failure = new Error('revoked during Token');
        const signer = {
          ...fixture.signer,
          sign(input: Uint8Array) {
            oldCalls += 1;
            return fixture.signer.sign(input);
          },
        };
        fixture.setSigner(signer);
        fixture.duringToken(() => {
          signer.sign = (input) => {
            newCalls += 1;
            if (throws) throw failure;
            return fixture.signer.sign(input);
          };
        });
        if (throws) await expect(fixture.invoke()).rejects.toBe(failure);
        else await fixture.invoke();
        expect(oldCalls).toBe(0);
        expect(newCalls).toBe(1);
        expect(callsTo(fixture, fixture.tokenUrl)).toBe(1);
        expect(callsTo(fixture, fixture.credentialUrl)).toBe(throws ? 0 : 1);
      });
    }

    test('a getter selects the method made available during Token', async () => {
      const fixture = create();
      let reads = 0;
      let oldCalls = 0;
      let newCalls = 0;
      let current = (input: Uint8Array) => {
        oldCalls += 1;
        return fixture.signer.sign(input);
      };
      fixture.setSigner(
        signerWithDescriptor(fixture, {
          get() {
            reads += 1;
            return current;
          },
        }),
      );
      fixture.duringToken(() => {
        expect(reads).toBe(0);
        current = (input) => {
          newCalls += 1;
          return fixture.signer.sign(input);
        };
      });
      await fixture.invoke();
      expect(reads).toBe(1);
      expect(oldCalls).toBe(0);
      expect(newCalls).toBe(1);
      expect(callsTo(fixture, fixture.credentialUrl)).toBe(1);
    });

    test('Object.prototype-only sign is unknown until the existing proof lookup', async () => {
      const fixture = create();
      fixture.setSigner({ alg: fixture.signer.alg, publicKeyJwk: fixture.signer.publicKeyJwk });
      let reads = 0;
      fixture.duringToken(() => {
        expect(reads).toBe(0);
      });
      Object.defineProperty(Object.prototype, 'sign', {
        configurable: true,
        get() {
          reads += 1;
          return undefined;
        },
      });
      let observed: unknown;
      try {
        await fixture.invoke();
      } catch (error) {
        observed = error;
      } finally {
        Reflect.deleteProperty(Object.prototype, 'sign');
      }
      expect(observed).toBeInstanceOf(TypeError);
      expect(reads).toBe(1);
      expect(callsTo(fixture, fixture.tokenUrl)).toBe(1);
      expect(callsTo(fixture, fixture.credentialUrl)).toBe(0);
    });

    for (const trap of ['getOwnPropertyDescriptor', 'getPrototypeOf'] as const) {
      test(`${trap} errors are not converted into invalid-deps errors`, async () => {
        const fixture = create();
        const failure = new Error(trap);
        const source = { alg: fixture.signer.alg, publicKeyJwk: fixture.signer.publicKeyJwk };
        fixture.setSigner(
          new Proxy(source, {
            [trap]: () => {
              throw failure;
            },
          }),
        );
        await expect(fixture.invoke()).rejects.toBe(failure);
        expect(fixture.calls).toHaveLength(0);
      });
    }

    for (const [label, value] of [
      ['missing', undefined],
      ['undefined', undefined],
      ['null', null],
      ['number', 0],
      ['string', 'invalid'],
      ['function', () => {}],
    ] as const) {
      test(`outer signer ${label} keeps the existing deps error`, async () => {
        const fixture = create();
        if (label === 'missing') fixture.removeSigner();
        else fixture.setSigner(value);
        await expect(fixture.invoke()).rejects.toMatchObject({
          code: fixture.errorCode,
          context: { reason: fixture.reason },
        });
        expect(fixture.calls).toHaveLength(0);
      });
    }
  });
}
