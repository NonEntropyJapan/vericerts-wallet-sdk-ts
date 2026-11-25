/**
 * buildDidEthrDocument の生成量の上限。
 *
 * 任意の `Erc1056EventSource` が返すイベントでも、異なる (name,value) ごとに VerificationMethod を
 * 1 件ずつ増やして巨大文書を作り切らない。読み手側の上限（`MAX_DID_DOCUMENT_ARRAY_ENTRIES`）と同じ値で
 * 生成側も打ち切り、超過は fail-closed（2010）にする。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { MAX_DID_DOCUMENT_ARRAY_ENTRIES } from '../../did-document-read.js';
import { buildDidEthrDocument, MAX_ERC1056_EVENTS } from '../events.js';

const IDENTITY = '0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb';
const NOW = 1_700_000_000;
const invalid = new VericertsError(ErrorCodes.DID_DOC_INVALID);

function pubkeyEvent(i: number) {
  const value = `0x02${i.toString(16).padStart(64, '0')}`;
  return {
    name: 'did/pub/Secp256k1/sigAuth/hex',
    value,
    validTo: NOW + 1000,
    blockNumber: 1 + i,
    logIndex: 0,
  };
}

describe('buildDidEthrDocument: 生成量の上限', () => {
  it('VerificationMethod が読み手上限を超える水増し（異なる value）は 2010', () => {
    // #controller と合わせて上限を 1 件超える。
    const attributeChanges = Array.from({ length: MAX_DID_DOCUMENT_ARRAY_ENTRIES }, (_, i) =>
      pubkeyEvent(i),
    );
    expect(() =>
      buildDidEthrDocument(
        `did:ethr:${IDENTITY}`,
        IDENTITY,
        1,
        { ownerChanges: [], attributeChanges },
        NOW,
      ),
    ).toThrow(invalid);
  });

  it('上限ちょうどの VerificationMethod は生成できる', () => {
    const attributeChanges = Array.from({ length: MAX_DID_DOCUMENT_ARRAY_ENTRIES - 1 }, (_, i) =>
      pubkeyEvent(i),
    );
    const doc = buildDidEthrDocument(
      `did:ethr:${IDENTITY}`,
      IDENTITY,
      1,
      { ownerChanges: [], attributeChanges },
      NOW,
    );
    expect(doc.verificationMethod).toHaveLength(MAX_DID_DOCUMENT_ARRAY_ENTRIES);
  });

  it('同一 (name,value) の繰り返しでもイベント総数が上限を超えれば 2010', () => {
    const one = pubkeyEvent(0);
    const attributeChanges = Array.from({ length: MAX_ERC1056_EVENTS + 1 }, (_, i) => ({
      ...one,
      blockNumber: 1 + i,
    }));
    expect(() =>
      buildDidEthrDocument(
        `did:ethr:${IDENTITY}`,
        IDENTITY,
        1,
        { ownerChanges: [], attributeChanges },
        NOW,
      ),
    ).toThrow(invalid);
  });
});
