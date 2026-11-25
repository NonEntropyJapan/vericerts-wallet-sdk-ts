/**
 * DER パーサ入口の入力サイズ・子要素数の上限。
 *
 * 自己署名 TSL/LOTL の KeyInfo 内 X.509 は、アンカー検証より前に `parseCertificate` を通る。外側の
 * `signatureAlgorithm` に `05 00`（NULL）を数百万個並べると、全子ノードの配列確保だけで RSS が約 840 MB に
 * 達した。実時間・RSS ではなく、確保される `Asn1Node` の個数（`subarray` の呼び出し回数）・境界値・
 * 例外メッセージで pin する。個数とサイズの比率を変えた複数形状で確認する。
 */

import { afterEach, describe, expect, setDefaultTimeout, spyOn, test } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../__tests__/heavy-input-timeout.js';
import {
  Asn1Error,
  type Asn1Node,
  MAX_ASN1_CHILDREN,
  MAX_DER_BYTES,
  readChildren,
  readNode,
} from '../asn1.js';
import { oid, tlv } from '../etsi-tsl/__tests__/der.js';
import { makeCertificate } from '../etsi-tsl/__tests__/fixtures.js';
import { parseCertificate } from '../etsi-tsl/x509.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

const NULL_TLV = [0x05, 0x00];
const SHA256_WITH_ECDSA = '1.2.840.10045.4.3.2';

/** 正規な証明書の `signatureAlgorithm` に `extraChildren` 個の NULL を足した証明書を作る（TBS・署名は正規のまま）。 */
function certWithPaddedSigAlg(extraChildren: number): Uint8Array {
  const valid = makeCertificate({ cn: 'padded', kind: 'ec' }).der;
  const sigValue = readChildren(readNode(valid))[2] as Asn1Node;
  const sigValueBytes = valid.subarray(valid.length - sigValue.totalLength);
  const sigAlg = tlv(0x30, [
    ...oid(SHA256_WITH_ECDSA),
    ...Array(extraChildren).fill(NULL_TLV).flat(),
  ]);
  return Uint8Array.from(
    tlv(0x30, [...parseCertificate(valid).tbsBytes, ...sigAlg, ...sigValueBytes]),
  );
}

let subarraySpy: { mockRestore(): void; mock: { calls: unknown[] } } | undefined;
afterEach(() => {
  subarraySpy?.mockRestore();
  subarraySpy = undefined;
});

function countNodeAllocations(fn: () => unknown): { thrown: unknown; allocations: number } {
  subarraySpy = spyOn(Uint8Array.prototype, 'subarray');
  let thrown: unknown;
  try {
    fn();
  } catch (error) {
    thrown = error;
  }
  const allocations = subarraySpy.mock.calls.length;
  subarraySpy.mockRestore();
  subarraySpy = undefined;
  return { thrown, allocations };
}

describe('readNode: 入力全体の大きさの上限', () => {
  test('MAX_DER_BYTES ちょうどは読め、1 バイト超は 1 ノードも確保せず拒否する', () => {
    const exact = new Uint8Array(MAX_DER_BYTES);
    exact.set([0x04, 0x82, 0xff, 0xfc]);
    expect(readNode(exact).totalLength).toBe(MAX_DER_BYTES);
    const { thrown, allocations } = countNodeAllocations(() =>
      readNode(new Uint8Array(MAX_DER_BYTES + 1)),
    );
    expect(thrown).toBeInstanceOf(Asn1Error);
    expect((thrown as Asn1Error).message).toBe('DER: input too large');
    expect(allocations).toBe(0);
  });
});

describe('readChildren: 子要素数の上限', () => {
  const sequenceOf = (count: number) =>
    readNode(Uint8Array.from(tlv(0x30, Array(count).fill(NULL_TLV).flat())));

  test('MAX_ASN1_CHILDREN ちょうどは読め、1 個超は拒否する', () => {
    expect(readChildren(sequenceOf(MAX_ASN1_CHILDREN))).toHaveLength(MAX_ASN1_CHILDREN);
    const { thrown, allocations } = countNodeAllocations(() =>
      readChildren(sequenceOf(MAX_ASN1_CHILDREN + 1)),
    );
    expect(thrown).toBeInstanceOf(Asn1Error);
    expect((thrown as Asn1Error).message).toBe('DER: too many child nodes');
    // 上限を超えた時点で打ち切る: 確保したノードは上限ぶんだけ（+ 入力側の sequenceOf が作った 1 ノード）。
    expect(allocations).toBeLessThanOrEqual(MAX_ASN1_CHILDREN + 1);
  });

  test('入れ子にしても 1 ノードあたりの子要素数の上限は各階層で効く', () => {
    const inner = tlv(
      0x30,
      Array(MAX_ASN1_CHILDREN + 1)
        .fill(NULL_TLV)
        .flat(),
    );
    const outer = readNode(Uint8Array.from(tlv(0x30, tlv(0x30, inner))));
    const [middle] = readChildren(outer) as [Asn1Node];
    const [leaf] = readChildren(middle) as [Asn1Node];
    expect(() => readChildren(leaf)).toThrow('DER: too many child nodes');
  });
});

describe('parseCertificate: 水増しした signatureAlgorithm', () => {
  // [NULL の個数, 期待する拒否理由]: 巨大（元の攻撃: 290 万個 ≒ 5.8 MB）/ 入力上限を僅かに超える /
  // 入力上限内だが子要素数の上限を超える。
  test.each([
    [2_900_000, 'DER: input too large'],
    [MAX_DER_BYTES / 2, 'DER: input too large'],
    [MAX_ASN1_CHILDREN, 'DER: too many child nodes'],
    [MAX_ASN1_CHILDREN + 1, 'DER: too many child nodes'],
  ])('NULL を %d 個並べた証明書は拒否される（%s）', (count, message) => {
    const der = certWithPaddedSigAlg(count);
    const { thrown, allocations } = countNodeAllocations(() => parseCertificate(der));
    expect(thrown).toBeInstanceOf(Asn1Error);
    expect((thrown as Asn1Error).message).toBe(message);
    // 確保するノードは入力上限・子要素数上限のどちらかで頭打ちになる（水増し量に比例しない）。
    expect(allocations).toBeLessThanOrEqual(MAX_ASN1_CHILDREN + 32);
  });

  test('正規の証明書は従来どおりパースできる', () => {
    const { der } = makeCertificate({ cn: 'ok', kind: 'ec' });
    expect(parseCertificate(der).signatureAlg).toBeDefined();
  });
});
