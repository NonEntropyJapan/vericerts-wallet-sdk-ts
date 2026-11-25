import { describe, expect, test } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { callsTo, receiveFixtures, signerWithDescriptor } from './fixtures.js';

for (const [name, create] of receiveFixtures) {
  describe(`${name}: deferred signer compatibility`, () => {
    for (const alg of ['ES256', 'ES256K', 'EdDSA'] as const) {
      test(`${alg} still signs exactly once after Token`, async () => {
        const fixture = create();
        const actual = createPrivateKeySigner(new Uint8Array(32).fill(9), alg);
        let signs = 0;
        fixture.setSigner({
          ...actual,
          sign(input: Uint8Array) {
            expect(callsTo(fixture, fixture.tokenUrl)).toBe(1);
            signs += 1;
            return actual.sign(input);
          },
        });
        await fixture.invoke();
        expect(signs).toBe(1);
        expect(callsTo(fixture, fixture.credentialUrl)).toBe(1);
      });
    }

    test('the original class instance, private-field receiver and extra fields survive', async () => {
      const fixture = create();
      class Signer {
        readonly alg = fixture.signer.alg;
        readonly publicKeyJwk = fixture.signer.publicKeyJwk;
        readonly marker = {};
        #calls = 0;
        sign(input: Uint8Array) {
          this.#calls += 1;
          return fixture.signer.sign(input);
        }
        get calls() {
          return this.#calls;
        }
      }
      const signer = new Signer();
      fixture.setSigner(signer);
      expect(fixture.resolvedSigner()).toBe(signer);
      expect(fixture.resolvedSigner()).toBeInstanceOf(Signer);
      await fixture.invoke();
      expect(signer.calls).toBe(1);
      expect(callsTo(fixture, fixture.credentialUrl)).toBe(1);
    });

    test('outer getter is read once and nested getter only at the original proof time', async () => {
      const fixture = create();
      let outerReads = 0;
      let signReads = 0;
      let signs = 0;
      const signer = signerWithDescriptor(fixture, {
        get() {
          signReads += 1;
          expect(callsTo(fixture, fixture.tokenUrl)).toBe(1);
          return (input: Uint8Array) => {
            signs += 1;
            return fixture.signer.sign(input);
          };
        },
      });
      fixture.setSignerDescriptor({
        get() {
          outerReads += 1;
          return signer;
        },
      });
      fixture.duringToken(() => {
        expect(signReads).toBe(0);
      });
      await fixture.invoke();
      expect(outerReads).toBe(1);
      expect(signReads).toBe(1);
      expect(signs).toBe(1);
    });

    test('ordinary missing sign is unknown and still fails after Token', async () => {
      const fixture = create();
      fixture.setSigner({ alg: fixture.signer.alg, publicKeyJwk: fixture.signer.publicKeyJwk });
      await expect(fixture.invoke()).rejects.toBeInstanceOf(TypeError);
      expect(callsTo(fixture, fixture.tokenUrl)).toBe(1);
      expect(callsTo(fixture, fixture.credentialUrl)).toBe(0);
    });

    for (const mode of ['undefined', 'throw'] as const) {
      test(`getter ${mode} is deferred without new error normalization`, async () => {
        const fixture = create();
        const failure = new Error('getter failure');
        let reads = 0;
        fixture.setSigner(
          signerWithDescriptor(fixture, {
            get() {
              reads += 1;
              expect(callsTo(fixture, fixture.tokenUrl)).toBe(1);
              if (mode === 'throw') throw failure;
              return undefined;
            },
          }),
        );
        const promise = fixture.invoke();
        if (mode === 'throw') await expect(promise).rejects.toBe(failure);
        else await expect(promise).rejects.toBeInstanceOf(TypeError);
        expect(reads).toBe(1);
        expect(callsTo(fixture, fixture.credentialUrl)).toBe(0);
      });
    }

    test('transparent and descriptor-missing virtual proxies keep their proof lookup', async () => {
      for (const virtual of [false, true]) {
        const fixture = create();
        let signs = 0;
        const sign = (input: Uint8Array) => {
          signs += 1;
          return fixture.signer.sign(input);
        };
        const target = { alg: fixture.signer.alg, publicKeyJwk: fixture.signer.publicKeyJwk };
        const signer = virtual
          ? new Proxy(target, {
              get: (object, key, receiver) =>
                key === 'sign' ? sign : Reflect.get(object, key, receiver),
            })
          : new Proxy({ ...target, sign }, {});
        fixture.setSigner(signer);
        const resolved: object = fixture.resolvedSigner();
        expect(resolved).toBe(signer);
        await fixture.invoke();
        expect(signs).toBe(1);
        expect(callsTo(fixture, fixture.credentialUrl)).toBe(1);
      }
    });

    test('unused publicKeyJwk/kid getters are not evaluated by preflight', async () => {
      const fixture = create();
      const signer = {
        alg: fixture.signer.alg,
        sign: (input: Uint8Array) => fixture.signer.sign(input),
        get publicKeyJwk(): never {
          throw new Error('unused publicKeyJwk');
        },
        get kid(): never {
          throw new Error('unused kid');
        },
      };
      fixture.setSigner(signer);
      expect(fixture.resolvedSigner()).toBe(signer);
      await fixture.invoke();
      expect(callsTo(fixture, fixture.credentialUrl)).toBe(1);
    });
  });
}
