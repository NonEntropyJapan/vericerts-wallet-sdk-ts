/**
 * DN(RDNSequence) 正規化（`dn.ts`）の単体テスト。
 *
 * 正規化キーは nameConstraints の directoryName 照合に使われる。**別バイト列の 2 つの DN が
 * 同じキーに畳まれる**と `permittedSubtrees` が 1 段緩む（本来は範囲外の名前が base の配下と
 * みなされる）ため、畳める表現の境界をここで固定する。上位の
 * `__tests__/name-constraints.test.ts` は照合結果を見るので、構造の受理条件そのものは見えない。
 */

import { describe, expect, it } from 'bun:test';
import { oid, tlv } from '../../etsi-tsl/__tests__/der.js';
import { normalizedRdns } from '../dn.js';

/** commonName の属性型 OID。 */
const OID_COMMON_NAME = '2.5.4.3';

/** UTF8String。 */
function utf8(value: string): number[] {
  return tlv(0x0c, [...Buffer.from(value, 'utf8')]);
}

/** `AttributeTypeAndValue` を任意の要素列で組む（余剰要素を足せる形）。 */
function attributeTypeAndValue(...fields: number[][]): number[] {
  return tlv(0x30, fields.flat());
}

/** 1 つの RDN（SET OF AttributeTypeAndValue）だけを持つ Name(DER)。 */
function singleRdnDn(attribute: number[]): Uint8Array {
  return Uint8Array.from(tlv(0x30, tlv(0x31, attribute)));
}

describe('normalizedRdns', () => {
  it('2 要素の AttributeTypeAndValue を "<oid>=<値>" に畳む', () => {
    const dn = singleRdnDn(attributeTypeAndValue(oid(OID_COMMON_NAME), utf8('Acme Corp')));
    expect(normalizedRdns(dn)).toEqual([`${OID_COMMON_NAME}=acme corp`]);
  });

  // `AttributeTypeAndValue ::= SEQUENCE { type, value }` は 2 要素ちょうどである。先頭 2 要素
  // だけを見て畳むと、3 つ目を足しただけの別 DN が正規の 2 要素版と**同じ照合キー**になり、
  // `permittedSubtrees` の base に一致しないはずの名前が配下として通る。
  it('3 要素の AttributeTypeAndValue は評価不能に倒す（2 要素版と衝突させない）', () => {
    const extra = singleRdnDn(
      attributeTypeAndValue(oid(OID_COMMON_NAME), utf8('Acme Corp'), utf8('padding')),
    );
    expect(normalizedRdns(extra)).toBeUndefined();
  });

  it('1 要素しかない AttributeTypeAndValue も評価不能に倒す', () => {
    const truncated = singleRdnDn(attributeTypeAndValue(oid(OID_COMMON_NAME)));
    expect(normalizedRdns(truncated)).toBeUndefined();
  });
});
