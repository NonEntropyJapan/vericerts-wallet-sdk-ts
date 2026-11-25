import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import {
  ed25519Jwk,
  expectRejects,
  jsonReply,
  p256Jwk,
  recordingFetch,
} from '../../__tests__/network-method.fixtures.js';
import { RELATIONSHIP_KEYS } from '../../did-document-read.js';
import { resolveDidEbsi } from '../method-ebsi.js';
import { API_URL, DID, ebsiDocument } from './ebsi.fixtures.js';

describe('resolveDidEbsi embedded verification methods', () => {
  for (const relationship of RELATIONSHIP_KEYS) {
    it(`${relationship} に埋め込まれた未対応鍵も 2010 で拒否する`, async () => {
      const vm = {
        id: `${DID}#embedded`,
        controller: DID,
        type: 'JsonWebKey2020',
        publicKeyJwk: ed25519Jwk(),
      };
      const { fetchFn } = recordingFetch(() =>
        jsonReply(ebsiDocument(DID, { [relationship]: [vm] })),
      );
      await expectRejects(
        resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn }),
        ErrorCodes.DID_DOC_INVALID,
        'ebsi_key_unsupported',
      );
    });
  }

  it('対応する埋め込み鍵は top-level verificationMethod が無くても受理する', async () => {
    const vm = {
      id: `${DID}#embedded`,
      controller: DID,
      type: 'JsonWebKey2020',
      publicKeyJwk: p256Jwk(),
    };
    const { fetchFn } = recordingFetch(() =>
      jsonReply(ebsiDocument(DID, { verificationMethod: [], assertionMethod: [vm] })),
    );
    expect((await resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn })).assertionMethod).toEqual([vm]);
  });
});
