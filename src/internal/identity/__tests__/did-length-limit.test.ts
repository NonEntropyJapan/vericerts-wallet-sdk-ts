/**
 * 署名検証前の DID 解決における base58 二次時間 DoS の入力長上限の検証。
 *
 * 実時間ではなく「上限超過の入力は base58 デコードに到達しない」ことを
 * `@scure/base` の `base58.decode` スパイの呼び出し回数で決定的に確認する。
 */

import { afterEach, describe, expect, it, setDefaultTimeout, spyOn } from 'bun:test';
import { base58 } from '@scure/base';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../__tests__/heavy-input-timeout.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { MAX_DID_LENGTH, MAX_PEER4_ENCODED_DOCUMENT_LENGTH } from '../did-format.js';
import { MethodKey, resolveDidKey } from '../method-key.js';
import { MAX_BASE58_TEXT_LENGTH, multibaseBase58Decode } from '../multibase.js';
import { createDidPeer4, MethodPeer } from '../peer/method-peer.js';
import { Resolver } from '../resolver.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);

const decodeSpy = spyOn(base58, 'decode');

afterEach(() => {
  decodeSpy.mockClear();
});

/** numalgo 4 の必須フィールドだけを持つ最小ドキュメント。 */
function peer4Document(): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
  };
}

function newResolver(): Resolver {
  const resolver = new Resolver();
  resolver.register(new MethodKey());
  resolver.register(new MethodPeer());
  return resolver;
}

describe('multibaseBase58Decode の長さ上限', () => {
  it('既定上限を超える入力は base58 デコードせず 2001', () => {
    expect(() => multibaseBase58Decode(`z${'Z'.repeat(MAX_BASE58_TEXT_LENGTH)}`)).toThrow(
      INVALID_DID,
    );
    expect(decodeSpy).not.toHaveBeenCalled();
  });

  it('上限ちょうどはデコードへ進む（境界）', () => {
    multibaseBase58Decode(`z${'Z'.repeat(MAX_BASE58_TEXT_LENGTH - 1)}`);
    expect(decodeSpy).toHaveBeenCalledTimes(1);
  });

  it('呼び出し側が渡した上限を尊重する', () => {
    expect(() => multibaseBase58Decode('zabcd', 4)).toThrow(INVALID_DID);
    expect(decodeSpy).not.toHaveBeenCalled();
  });
});

describe('署名検証前の DID 解決は長大入力を base58 デコード前に拒否する', () => {
  it('did:key:z + 長文字列（resolveDidKey）は 2001 でデコードに到達しない', () => {
    expect(() => resolveDidKey(`did:key:z${'Z'.repeat(100_000)}`)).toThrow(INVALID_DID);
    expect(decodeSpy).not.toHaveBeenCalled();
  });

  it('Resolver.resolve は MAX_DID_LENGTH 超の DID を 2001 で拒否する', async () => {
    const did = `did:key:z${'Z'.repeat(MAX_DID_LENGTH)}`;
    await expect(newResolver().resolve(did)).rejects.toThrow(INVALID_DID);
    expect(decodeSpy).not.toHaveBeenCalled();
  });

  it('Resolver.update も同じ上限を適用する（未対応メソッドの 2002 より先に 2001）', async () => {
    const did = `did:key:z${'Z'.repeat(MAX_DID_LENGTH)}`;
    await expect(newResolver().update(did, {} as never)).rejects.toThrow(INVALID_DID);
  });

  it('did:peer:4（ハッシュ整合済み）のドキュメントが上限超なら 2001 でデコードに到達しない', async () => {
    const did = createDidPeer4({ ...peer4Document(), padding: 'a'.repeat(13_000) });
    expect(did.length).toBeGreaterThan(MAX_PEER4_ENCODED_DOCUMENT_LENGTH);
    await expect(newResolver().resolve(did)).rejects.toThrow(INVALID_DID);
    expect(decodeSpy).not.toHaveBeenCalled();
  });

  it('did:peer:4 は旧上限 16 KiB 内でも 4 KiB を超えれば 2001', async () => {
    const did = createDidPeer4({ ...peer4Document(), padding: 'a'.repeat(4_000) });
    expect(did.length).toBeGreaterThan(MAX_PEER4_ENCODED_DOCUMENT_LENGTH);
    expect(did.length).toBeLessThan(16 * 1024);
    await expect(newResolver().resolve(did)).rejects.toThrow(INVALID_DID);
    expect(decodeSpy).not.toHaveBeenCalled();
  });

  it('did:peer:4 は上限内なら MAX_DID_LENGTH 超でも解決できる（対照）', async () => {
    const did = createDidPeer4({ ...peer4Document(), padding: 'a'.repeat(2_000) });
    expect(did.length).toBeGreaterThan(MAX_DID_LENGTH);
    const doc = await newResolver().resolve(did);
    expect(doc.id).toBe(did);
  });
});
