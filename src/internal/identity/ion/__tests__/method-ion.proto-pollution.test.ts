import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../errors.js';
import {
  expectRejects,
  jsonReply,
  recordingFetch,
} from '../../__tests__/network-method.fixtures.js';
import { resolveDidIon } from '../method-ion.js';
import { ionResponse, makeIonCreate, NODE_URL } from './ion.fixtures.js';

const create = makeIonCreate();

describe('did:ion の文書正規化の汚染耐性', () => {
  it('継承した extraStatuses で HTTP エラーの本文を採用しない', async () => {
    const { fetchFn } = recordingFetch(() => ({
      ...jsonReply(ionResponse(create.shortForm, create)),
      status: 404,
    }));
    await withPollutedPrototypeAsync({ extraStatuses: [404] }, async () => {
      await expectRejects(
        resolveDidIon(create.shortForm, { nodeUrl: NODE_URL, fetchFn }),
        ErrorCodes.DID_NOT_FOUND,
      );
    });
  });

  it('省略された検証関係は継承値を採らず own の空配列にする', async () => {
    const { fetchFn } = recordingFetch(() =>
      jsonReply(
        ionResponse(create.shortForm, create, {
          document: { verificationMethod: undefined, assertionMethod: undefined },
        }),
      ),
    );
    await withPollutedPrototypeAsync(
      {
        verificationMethod: [{ id: '#attacker' }],
        authentication: ['#attacker'],
        assertionMethod: ['#attacker'],
      },
      async () => {
        const { document } = await resolveDidIon(create.shortForm, {
          nodeUrl: NODE_URL,
          fetchFn,
        });
        for (const key of ['verificationMethod', 'authentication', 'assertionMethod'] as const) {
          expect(Object.hasOwn(document, key)).toBe(true);
          expect(document[key]).toEqual([]);
        }
      },
    );
  });

  it('継承アクセサを呼ばずに相対 DID URL を正規化する', async () => {
    const { fetchFn } = recordingFetch(() => jsonReply(ionResponse(create.shortForm, create)));
    let reads = 0;
    await withPollutedPrototypeAccessorAsync(
      {
        authentication: () => {
          reads++;
          return undefined;
        },
      },
      async () => {
        const { document } = await resolveDidIon(create.shortForm, {
          nodeUrl: NODE_URL,
          fetchFn,
        });
        expect(document.authentication).toEqual([]);
        expect(document.verificationMethod[0]?.id).toBe(`${create.shortForm}#signing`);
        expect(document.assertionMethod).toEqual([`${create.shortForm}#signing`]);
        expect(document.service?.[0]?.id).toBe(`${create.shortForm}#hub`);
      },
    );
    expect(reads).toBe(0);
  });
});
