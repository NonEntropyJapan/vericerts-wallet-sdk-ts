/**
 * DID Log の proof 型と、解決で選んだ state の配列形状。
 *
 * `__tests__` 直下はディレクトリ行数の上限に近いため、この回帰だけサブディレクトリに置く。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { parseDidLog, type WebVhLogEntry } from '../../codec.js';
import type { WebVhCreateDocument } from '../../lifecycle/lifecycle.js';
import { createDidWebVh, resolveDidWebVh } from '../../method-webvh.js';
import { verifyEntryProof } from '../../proof.js';
import { generateKey, mockFetchOnce, restoreFetch, signEntry, toJsonl } from '../webvh-fixtures.js';

afterEach(() => {
  restoreFetch();
});

const base = {
  versionId: '1-zScid',
  versionTime: '2026-04-01T00:00:00Z',
  parameters: {},
  state: { id: 'did:webvh:zScid:vericerts.io' },
};

describe('parseDidLog / verifyEntryProof の proof 型', () => {
  it.each([{}, 5, [null]])('proof が %j の行は INVALID_DID', (proof) => {
    const line = JSON.stringify({ ...base, proof });
    expect(() => parseDidLog(line)).toThrow(new VericertsError(ErrorCodes.INVALID_DID));
  });

  it.each([{}, 5, [null]])('verifyEntryProof は proof が %j でも生 TypeError にしない', (proof) => {
    expect(() => verifyEntryProof({ ...base, proof } as WebVhLogEntry, new Set())).toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });
});

describe('resolveDidWebVh の state 形状', () => {
  it('verificationMethod が配列でない署名済みログは 2010', async () => {
    const key = generateKey();
    const { did, logEntry } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
      document: {
        verificationMethod: 'oops',
        assertionMethod: 7,
      } as unknown as WebVhCreateDocument,
    });
    mockFetchOnce(toJsonl([signEntry(logEntry, key)]));
    await expect(resolveDidWebVh(did)).rejects.toThrow(
      new VericertsError(ErrorCodes.DID_DOC_INVALID),
    );
  });
});
