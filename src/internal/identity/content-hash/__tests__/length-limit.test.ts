/**
 * contentHash 表記の入力長上限の検証。
 *
 * `contentHash` クレームと DID 末尾セグメントは署名検証前の攻撃者制御入力。実時間ではなく
 * 「上限超過の入力は base58 デコードに到達しない」ことを `@scure/base` の `base58.decode` スパイの
 * 呼び出し回数で決定的に確認する。
 */

import { beforeEach, describe, expect, it, spyOn } from 'bun:test';
import { base58, hex } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { extractDidContentHash } from '../did-subpath.js';
import { decodeMultibase, MAX_CONTENT_HASH_TEXT_LENGTH } from '../digest-codec.js';
import { parseContentHash } from '../notation.js';
import { verifyVcContentHashClaim } from '../verify.js';

const decodeSpy = spyOn(base58, 'decode');

beforeEach(() => {
  decodeSpy.mockClear();
});

const INVALID_HASH = new VericertsError(ErrorCodes.CONTENT_HASH_FORMAT_INVALID);
const DIGEST_HEX = 'ab'.repeat(32);

describe('parseContentHash の長さ上限', () => {
  it('上限超の multibase(base58) は base58 デコードせず 2016', () => {
    const text = `sha256-z${'2'.repeat(MAX_CONTENT_HASH_TEXT_LENGTH)}`;
    expect(() => parseContentHash(text)).toThrow(INVALID_HASH);
    expect(decodeSpy).not.toHaveBeenCalled();
  });

  it('`-` を大量に含む上限超の入力も 2016（辞書引きの二次走査に到達しない）', () => {
    expect(() => parseContentHash('a-'.repeat(MAX_CONTENT_HASH_TEXT_LENGTH))).toThrow(INVALID_HASH);
  });

  it('上限内の正当な表記は通る（対照）', () => {
    expect(parseContentHash(`sha256-${DIGEST_HEX}`).notation).toBe(`sha2-256-${DIGEST_HEX}`);
    expect(hex.encode(parseContentHash(`sha2-256-${DIGEST_HEX}`).digest)).toBe(DIGEST_HEX);
  });
});

describe('署名検証前の contentHash 経路は長大入力を base58 デコード前に拒否する', () => {
  it('verifyVcContentHashClaim: クレームが上限超なら 2016 でデコードに到達しない', () => {
    const did = `did:example:abc:sha256-${DIGEST_HEX}`;
    const claim = `sha256-z${'2'.repeat(MAX_CONTENT_HASH_TEXT_LENGTH)}`;
    expect(() => verifyVcContentHashClaim(did, claim)).toThrow(INVALID_HASH);
    expect(decodeSpy).not.toHaveBeenCalled();
  });

  it('extractDidContentHash: DID 末尾が上限超なら 2016 でデコードに到達しない', () => {
    const did = `did:example:abc:sha256-z${'2'.repeat(MAX_CONTENT_HASH_TEXT_LENGTH)}`;
    expect(() => extractDidContentHash(did)).toThrow(INVALID_HASH);
    expect(decodeSpy).not.toHaveBeenCalled();
  });

  it('decodeMultibase: 上限超は undefined（CID 経路の共有デコーダも打ち切る）', () => {
    expect(decodeMultibase(`z${'2'.repeat(MAX_CONTENT_HASH_TEXT_LENGTH)}`)).toBeUndefined();
    expect(decodeSpy).not.toHaveBeenCalled();
  });
});
