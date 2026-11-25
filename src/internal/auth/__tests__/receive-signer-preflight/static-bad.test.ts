import { describe, expect, test } from 'bun:test';
import { callsTo, type ReceiveFixture, receiveFixtures, signerWithDescriptor } from './fixtures.js';

async function expectStaticBad(fixture: ReceiveFixture): Promise<void> {
  const error: unknown = await fixture.invoke().then(
    () => undefined,
    (failure: unknown) => failure,
  );
  expect({
    error,
    token: callsTo(fixture, fixture.tokenUrl),
    credential: callsTo(fixture, fixture.credentialUrl),
  }).toMatchObject({
    error: { code: fixture.errorCode, context: { reason: fixture.reason } },
    token: 0,
    credential: 0,
  });
  expect(fixture.calls).toHaveLength(0);
}

for (const [name, create] of receiveFixtures) {
  describe(`${name}: statically invalid proof signer`, () => {
    for (const [label, value] of [
      ['undefined', undefined],
      ['null', null],
      ['number', 0],
      ['string', 'not-callable'],
      ['object', {}],
    ] as const) {
      test(`explicit sign ${label} fails before Token with the existing deps owner`, async () => {
        const fixture = create();
        fixture.setSigner(signerWithDescriptor(fixture, { value }));
        await expectStaticBad(fixture);
      });
    }

    test('own undefined shadows a callable prototype without falling through', async () => {
      const fixture = create();
      let signCalls = 0;
      const prototype = {
        sign(input: Uint8Array) {
          signCalls += 1;
          return fixture.signer.sign(input);
        },
      };
      const signer = Object.assign(Object.create(prototype), {
        alg: fixture.signer.alg,
        publicKeyJwk: fixture.signer.publicKeyJwk,
      });
      Object.defineProperty(signer, 'sign', { value: undefined });
      fixture.setSigner(signer);
      await expectStaticBad(fixture);
      expect(signCalls).toBe(0);
    });

    test('a setter-only descriptor fails before Token without executing its setter', async () => {
      const fixture = create();
      let setterCalls = 0;
      fixture.setSigner(
        signerWithDescriptor(fixture, {
          set(_value) {
            setterCalls += 1;
          },
        }),
      );
      await expectStaticBad(fixture);
      expect(setterCalls).toBe(0);
    });
  });
}
