import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../errors.js';
import { expectRejects, p256Jwk, recordingFetch } from '../../__tests__/network-method.fixtures.js';
import { RELATIONSHIP_KEYS } from '../../did-document-read.js';
import { resolveDidCheqd } from '../method-cheqd.js';
import { keyJwk, LIVE_DID, RESOLUTION_CONTENT_TYPE, resolutionResult } from './cheqd.fixtures.js';

describe('resolveDidCheqd embedded verification methods', () => {
  const emptyDocumentFetch = () =>
    recordingFetch(() => ({
      contentType: RESOLUTION_CONTENT_TYPE,
      body: JSON.stringify({
        didDocument: { id: LIVE_DID },
        didDocumentMetadata: {},
        didResolutionMetadata: {},
      }),
    })).fetchFn;

  it('欠落した検証関係を継承値で補わず own の空配列にする', async () => {
    await withPollutedPrototypeAsync(
      {
        verificationMethod: [{ id: '#attacker' }],
        authentication: ['#attacker'],
        assertionMethod: ['#attacker'],
      },
      async () => {
        const { document } = await resolveDidCheqd(LIVE_DID, { fetchFn: emptyDocumentFetch() });
        for (const key of ['verificationMethod', 'authentication', 'assertionMethod'] as const) {
          expect(Object.hasOwn(document, key)).toBe(true);
          expect(document[key]).toEqual([]);
        }
      },
    );
  });

  it('欠落した検証関係の既定値設定で継承アクセサを呼ばない', async () => {
    let reads = 0;
    await withPollutedPrototypeAccessorAsync(
      {
        authentication: () => {
          reads++;
          return ['#attacker'];
        },
      },
      async () => {
        const { document } = await resolveDidCheqd(LIVE_DID, { fetchFn: emptyDocumentFetch() });
        expect(Object.hasOwn(document, 'authentication')).toBe(true);
        expect(document.authentication).toEqual([]);
      },
    );
    expect(reads).toBe(0);
  });

  for (const relationship of RELATIONSHIP_KEYS) {
    it(`${relationship} に埋め込まれた未対応鍵も 2010 で拒否する`, async () => {
      const vm = { ...keyJwk(LIVE_DID), publicKeyJwk: p256Jwk() };
      const { fetchFn } = recordingFetch(() => ({
        contentType: RESOLUTION_CONTENT_TYPE,
        body: JSON.stringify(resolutionResult(LIVE_DID, { document: { [relationship]: [vm] } })),
      }));
      await expectRejects(
        resolveDidCheqd(LIVE_DID, { fetchFn }),
        ErrorCodes.DID_DOC_INVALID,
        'cheqd_key_unsupported',
      );
    });
  }

  it('対応する埋め込み鍵は top-level verificationMethod が無くても受理する', async () => {
    const vm = keyJwk(LIVE_DID);
    const { fetchFn } = recordingFetch(() => ({
      contentType: RESOLUTION_CONTENT_TYPE,
      body: JSON.stringify(
        resolutionResult(LIVE_DID, { document: { verificationMethod: [], assertionMethod: [vm] } }),
      ),
    }));
    const { document } = await resolveDidCheqd(LIVE_DID, { fetchFn });
    expect(document.assertionMethod).toHaveLength(1);
    expect(document.assertionMethod[0]).toMatchObject(vm);
  });
});
