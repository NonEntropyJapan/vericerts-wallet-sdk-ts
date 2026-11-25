/**
 * nameConstraints の読み取り（`name-constraints.ts`）と照合（`name-matching.ts`）の単体テスト。
 *
 * 上位の回帰テスト（`etsi-tsl/__tests__/chain.name-constraints.test.ts`）は「制約の外に出た
 * チェーンが落ちること」を見るが、照合の**中身** — DN を正規化して文字列型の書き換えを吸収する
 * こと、URI base の `.` 有無で一致範囲が変わること — までは示せない。ここは値の解釈を直接固定する。
 */

import { describe, expect, it } from 'bun:test';
import { type Asn1Node, readNode } from '../../asn1.js';
import { dnWithTag, octetString, oid, tlv } from '../../etsi-tsl/__tests__/der.js';
import {
  type AltNames,
  type NameConstraints,
  nameConstraintsOf,
  OID_NAME_CONSTRAINTS,
} from '../name-constraints.js';
import { namesSatisfyConstraints } from '../name-matching.js';
import { certificateExtensions } from '../san.js';

/** 属性値の文字列型タグ。 */
const TAG_UTF8_STRING = 0x0c;
const TAG_PRINTABLE_STRING = 0x13;
const TAG_BMP_STRING = 0x1e;

/** nameConstraints 拡張だけを持つ証明書の TBSCertificate 子要素列を作る。 */
function constraintsOf(value: number[]): NameConstraints {
  const ext = tlv(0x30, [...oid(OID_NAME_CONSTRAINTS), ...octetString(value)]);
  const extensions: Asn1Node = readNode(Uint8Array.from(tlv(0xa3, tlv(0x30, ext))));
  const parsed = nameConstraintsOf(certificateExtensions([extensions]));
  if (parsed === undefined) {
    throw new Error('nameConstraints extension not found');
  }
  return parsed;
}

/** URI [6] の GeneralName。 */
function uriGeneralName(base: string): number[] {
  return tlv(0x86, [...Buffer.from(base, 'utf8')]);
}

/** directoryName [4] の base 1 件だけを excludedSubtrees [1] に持つ制約。 */
function excludedDirectoryName(dn: number[]): NameConstraints {
  return constraintsOf(tlv(0x30, tlv(0xa1, tlv(0x30, tlv(0xa4, dn)))));
}

/** uniformResourceIdentifier [6] の base 1 件だけを permittedSubtrees [0] に持つ制約。 */
function permittedUri(base: string): NameConstraints {
  return constraintsOf(tlv(0x30, tlv(0xa0, tlv(0x30, uriGeneralName(base)))));
}

/** URI SAN だけを持つ証明書の名前。 */
function uriAltNames(...uris: string[]): AltNames {
  return { uris, hasUnevaluable: false };
}

/** SAN を持たない証明書の名前。 */
const NO_ALT_NAMES: AltNames = { uris: [], hasUnevaluable: false };

/** `CN=<cn>` の subject DN（DER）。 */
function subject(cn: string, tag: number): Uint8Array {
  return Uint8Array.from(dnWithTag(cn, tag));
}

describe('namesSatisfyConstraints（directoryName）', () => {
  it('文字列型を書き換えても excludedSubtrees を回避できない', () => {
    // base は PrintableString、subject は UTF8String。バイト列一致で比較すると素通りする。
    const constraints = excludedDirectoryName(dnWithTag('Acme Corp', TAG_PRINTABLE_STRING));
    expect(constraints.evaluable).toBe(true);
    const blocked = subject('Acme Corp', TAG_UTF8_STRING);
    expect(namesSatisfyConstraints(blocked, NO_ALT_NAMES, constraints)).toBe(false);
    // 別名は制約に掛からない（上の false が「常に false」ではないことの確認）。
    const other = subject('Other Corp', TAG_UTF8_STRING);
    expect(namesSatisfyConstraints(other, NO_ALT_NAMES, constraints)).toBe(true);
  });

  it('大文字小文字・前後空白・連続空白の違いを吸収する', () => {
    const constraints = excludedDirectoryName(dnWithTag('Acme  Corp', TAG_PRINTABLE_STRING));
    const blocked = subject('  ACME Corp  ', TAG_UTF8_STRING);
    expect(namesSatisfyConstraints(blocked, NO_ALT_NAMES, constraints)).toBe(false);
  });

  it('対応外の文字列型（BMPString）の subject は評価不能として通さない', () => {
    // 制約は別名を除外しているだけなので、評価できていれば true になるはずの subject。
    const constraints = excludedDirectoryName(dnWithTag('Other Corp', TAG_PRINTABLE_STRING));
    const bmp = subject('Acme Corp', TAG_BMP_STRING);
    expect(namesSatisfyConstraints(bmp, NO_ALT_NAMES, constraints)).toBe(false);
  });
});

describe('namesSatisfyConstraints（URI）', () => {
  const permittedDn = subject('Leaf', TAG_UTF8_STRING);

  it('base `.example.com` は host.example.com に一致し example.com には一致しない', () => {
    const constraints = permittedUri('.example.com');
    const host = namesSatisfyConstraints(
      permittedDn,
      uriAltNames('https://host.example.com/vc'),
      constraints,
    );
    expect(host).toBe(true);
    const apex = namesSatisfyConstraints(
      permittedDn,
      uriAltNames('https://example.com/vc'),
      constraints,
    );
    expect(apex).toBe(false);
  });

  it('base `example.com` は example.com にのみ一致し sub.example.com には一致しない', () => {
    const constraints = permittedUri('example.com');
    const apex = namesSatisfyConstraints(
      permittedDn,
      uriAltNames('https://example.com/vc'),
      constraints,
    );
    expect(apex).toBe(true);
    const sub = namesSatisfyConstraints(
      permittedDn,
      uriAltNames('https://sub.example.com/vc'),
      constraints,
    );
    expect(sub).toBe(false);
  });

  it('末尾ドット付きホスト（root label 付き）は同じホストとして照合する', () => {
    // WHATWG URL は `https://host.example.com./vc` の hostname を `host.example.com.` のまま
    // 返す。落とさないと接尾辞一致が外れ、`permittedSubtrees` では範囲内の名前が弾かれ、
    // `excludedSubtrees` では除外したはずの名前が素通りする（除外専用のバイパス）。
    const constraints = permittedUri('.example.com');
    const dotted = namesSatisfyConstraints(
      permittedDn,
      uriAltNames('https://host.example.com./vc'),
      constraints,
    );
    expect(dotted).toBe(true);
  });

  it('空ラベルを含むホスト（`a..example.com`）は評価不能として通さない', () => {
    // WHATWG URL は受理するが、ラベル境界の意味が定まらない表現は fail-closed に倒す。
    const constraints = permittedUri('.example.com');
    const empty = namesSatisfyConstraints(
      permittedDn,
      uriAltNames('https://a..example.com/vc'),
      constraints,
    );
    expect(empty).toBe(false);
  });

  it('ホストを取り出せない SAN URI は、URI base があるときだけ通さない', () => {
    const constraints = permittedUri('example.com');
    expect(namesSatisfyConstraints(permittedDn, uriAltNames('not a url'), constraints)).toBe(false);
    // scheme はあるがホストを持たない URI も同じく評価不能。
    const urn = uriAltNames('urn:uuid:8f1d0f6e-2a1a-4b9a-9f1e-1a2b3c4d5e6f');
    expect(namesSatisfyConstraints(permittedDn, urn, constraints)).toBe(false);
  });

  it('URI base を持たない制約の下では、ホストを取り出せない SAN URI があっても通る', () => {
    // 制約は directoryName の別名を除外するだけで URI には何も言っていない。URI を照合対象に
    // しないのだから、ホストを取り出せないこと自体は拒否の理由にならない。
    const constraints = excludedDirectoryName(dnWithTag('Other Corp', TAG_PRINTABLE_STRING));
    const urn = uriAltNames('urn:uuid:8f1d0f6e-2a1a-4b9a-9f1e-1a2b3c4d5e6f');
    expect(namesSatisfyConstraints(permittedDn, urn, constraints)).toBe(true);
  });

  it('permittedSubtrees に URI base があっても URI SAN を 1 件も持たない証明書は通る', () => {
    // RFC 5280 §4.2.1.10 の permittedSubtrees は「その種別の名前を持つなら base 配下であること」
    // を課すだけで、名前を持たない証明書には掛からない（空の全称）。
    const constraints = permittedUri('example.com');
    expect(namesSatisfyConstraints(permittedDn, NO_ALT_NAMES, constraints)).toBe(true);
  });
});

describe('nameConstraintsOf（fail-closed）', () => {
  it('空の NameConstraints ::= SEQUENCE {} は評価不能（全許可にしない）', () => {
    // RFC 5280 §4.2.1.10 は permittedSubtrees / excludedSubtrees のいずれかを要求する。
    // 中身を空にするだけで制約が消えるなら、制約を読む意味が無い。
    expect(constraintsOf(tlv(0x30, [])).evaluable).toBe(false);
  });

  it('permittedSubtrees が 2 度現れる制約は評価不能（last-wins にしない）', () => {
    const first = tlv(0xa0, tlv(0x30, uriGeneralName('a.example.com')));
    const second = tlv(0xa0, tlv(0x30, uriGeneralName('b.example.com')));
    expect(constraintsOf(tlv(0x30, [...first, ...second])).evaluable).toBe(false);
  });

  it('ホスト形式でない URI base（完全な URI）は評価不能', () => {
    // `hostWithinBase` はホスト文字列としか突き合わせないため、この base は永久に一致しない。
    // 「一致しない」で黙って全拒否するより、評価不能として配下ごと落とすほうが原因が分かる。
    expect(permittedUri('https://example.com/vc').evaluable).toBe(false);
  });
});

describe('namesSatisfyConstraints（DN の正規化）', () => {
  it('UTF-8 として読めない属性値の subject は評価不能として通さない', () => {
    // 非 fatal なデコードだと不正バイトがすべて U+FFFD へ潰れ、実体の違う名前どうしが一致する。
    const constraints = excludedDirectoryName(dnWithTag('Other Corp', TAG_PRINTABLE_STRING));
    const brokenValue = tlv(TAG_UTF8_STRING, [0xff, 0xfe, 0xfd]);
    const attr = tlv(0x30, [...oid('2.5.4.3'), ...brokenValue]);
    const broken = Uint8Array.from(tlv(0x30, tlv(0x31, attr)));

    expect(namesSatisfyConstraints(broken, NO_ALT_NAMES, constraints)).toBe(false);
  });
});
