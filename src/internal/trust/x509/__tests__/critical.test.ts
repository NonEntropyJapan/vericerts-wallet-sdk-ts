/**
 * 解釈できない critical 拡張の判定（`critical.ts`・RFC 5280 §6.1.4 (f)）の単体テスト。
 *
 * `critical` は CA が「この制限を解釈できないなら証明書を使うな」と書くフラグである。認識集合が
 * 広すぎると「知っているが見ていない」拡張ができて判定が無意味になり、狭すぎると SDK が現に値を
 * 読んでいる拡張まで拒否理由になって、正当な証明書が診断不能な `trusted:false` で落ちる。
 * 上位のチェーン検証（`etsi-tsl/__tests__/chain.candidate-selection.test.ts`）は配線を見るので、
 * ここでは集合の境界そのものを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { OID_BASIC_CONSTRAINTS, OID_KEY_USAGE } from '../ca-constraints.js';
import { hasUnrecognizedCriticalExtension } from '../critical.js';
import { OID_NAME_CONSTRAINTS } from '../name-constraints.js';
import { type CertificateExtensions, OID_SUBJECT_ALT_NAME, OID_SUBJECT_DIR_ATTRS } from '../san.js';

/** extendedKeyUsage の OID（SDK が値を読まない拡張の代表）。 */
const OID_EXTENDED_KEY_USAGE = '2.5.29.37';

/** 指定の OID を critical として持つ拡張集合（`byOid` は判定に使われない）。 */
function withCritical(...oids: string[]): CertificateExtensions {
  return { byOid: new Map(), criticalOids: new Set(oids) };
}

describe('hasUnrecognizedCriticalExtension', () => {
  it.each([
    ['basicConstraints', OID_BASIC_CONSTRAINTS],
    ['keyUsage', OID_KEY_USAGE],
    ['nameConstraints', OID_NAME_CONSTRAINTS],
    ['subjectAltName', OID_SUBJECT_ALT_NAME],
    // `trust/rp-access/cert.ts` が値を読み `authorizeClaims` の認可判断に使う。読む以上、
    // §6.1.4 (f) の「解釈する」に数える（RFC 5280 §4.2.1.8 は non-critical を要求するので、
    // ここで緩む相手は規格非適合の証明書に限られる）。
    ['subjectDirectoryAttributes', OID_SUBJECT_DIR_ATTRS],
  ])('%s が critical でも拒否しない（値を読んで判断に使う拡張）', (_label, oid) => {
    expect(hasUnrecognizedCriticalExtension(withCritical(oid))).toBe(false);
  });

  it('値を読まない拡張（extendedKeyUsage）が critical なら拒否する', () => {
    expect(hasUnrecognizedCriticalExtension(withCritical(OID_EXTENDED_KEY_USAGE))).toBe(true);
  });

  it('認識する拡張に 1 つでも未知の critical が混ざれば拒否する', () => {
    const mixed = withCritical(OID_BASIC_CONSTRAINTS, OID_EXTENDED_KEY_USAGE);
    expect(hasUnrecognizedCriticalExtension(mixed)).toBe(true);
  });

  it('critical 拡張を 1 つも持たなければ拒否しない', () => {
    expect(hasUnrecognizedCriticalExtension(withCritical())).toBe(false);
  });

  it('拡張そのものを読めなかった場合は拒否する（critical の有無すら確かめられない）', () => {
    expect(hasUnrecognizedCriticalExtension(undefined)).toBe(true);
  });
});
