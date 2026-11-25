import { describe, expect, test } from 'bun:test';
import { oid, tlv } from '../../etsi-tsl/__tests__/der.js';
import { parseRpAccessCertificate, RP_ACCESS_ATTR_OIDS } from '../cert.js';
import { makeRpCertificate } from './fixtures.js';

describe('parseRpAccessCertificate', () => {
  test('Subject DN 属性（法人名・識別子・国）と SAN の origin を抽出する', () => {
    const fixture = makeRpCertificate({
      kind: 'ec',
      subject: {
        organizationName: 'Example Retailer',
        organizationIdentifier: 'VATDE-123456789',
        country: 'DE',
      },
      origin: 'https://rp.example.de',
    });
    const parsed = parseRpAccessCertificate(fixture.der);
    expect(parsed.identity.legalName).toBe('Example Retailer');
    expect(parsed.identity.legalId).toBe('VATDE-123456789');
    expect(parsed.identity.country).toBe('DE');
    expect(parsed.identity.origin).toBe('https://rp.example.de');
  });

  test('organizationName が無ければ commonName を legalName にフォールバックする', () => {
    const fixture = makeRpCertificate({
      kind: 'ec',
      subject: { commonName: 'RP Fallback', country: 'FR' },
    });
    const parsed = parseRpAccessCertificate(fixture.der);
    expect(parsed.identity.legalName).toBe('RP Fallback');
    expect(parsed.identity.legalId).toBe('');
  });

  test('SubjectDirectoryAttributes から認可属性 / 目的 / カテゴリを抽出する', () => {
    const fixture = makeRpCertificate({
      kind: 'ec',
      subject: { organizationName: 'RP', country: 'IT' },
      scope: {
        attributes: ['family_name', 'age_over_18'],
        purposes: ['identification', 'age_verification'],
        categories: ['identification', 'authorization'],
      },
    });
    const parsed = parseRpAccessCertificate(fixture.der);
    expect(parsed.scope.attributes).toEqual(['family_name', 'age_over_18']);
    expect(parsed.scope.purposes).toEqual(['identification', 'age_verification']);
    expect(parsed.scope.categories).toEqual(['identification', 'authorization']);
  });

  test('認可拡張が無い場合はスコープが空配列になる', () => {
    const fixture = makeRpCertificate({
      kind: 'rsa',
      subject: { organizationName: 'RP', country: 'ES' },
    });
    const parsed = parseRpAccessCertificate(fixture.der);
    expect(parsed.scope.attributes).toEqual([]);
    expect(parsed.scope.purposes).toEqual([]);
    expect(parsed.scope.categories).toEqual([]);
  });

  test('serial 番号を 16 進で抽出する', () => {
    const fixture = makeRpCertificate({
      kind: 'ec',
      subject: { organizationName: 'RP', country: 'NL' },
      serial: 255,
    });
    const parsed = parseRpAccessCertificate(fixture.der);
    expect(parsed.serialHex).toBe('ff');
  });

  test('不正な DER は例外を投げる', () => {
    expect(() => parseRpAccessCertificate(new Uint8Array([0x00, 0x01]))).toThrow();
  });

  // SubjectDirectoryAttributes ::= SEQUENCE OF Attribute。`extnValue` が SEQUENCE でないのに
  // 中身を Attribute の並びとして読み直すと（`readChildren` は constructed ビットを見ない）、
  // 別構造のバイト列からタグ次第で `authorizeClaims` 用の属性 / purposes / categories が
  // 生成される。SAN 側（`x509/san.ts`）と同じくタグを確かめ、読めない拡張は空スコープに倒す。
  test('SubjectDirectoryAttributes の extnValue が SEQUENCE でなければスコープは空になる', () => {
    // 中身は正規の Attribute 列そのものだが、外側のタグだけ OCTET STRING(0x04) にしてある。
    // タグを見ない実装ではこの属性がそのまま認可スコープとして読まれる。
    const attributes = tlv(0x30, [
      ...oid(RP_ACCESS_ATTR_OIDS.authorizedAttributes),
      ...tlv(0x31, tlv(0x0c, [...Buffer.from('family_name', 'utf8')])),
    ]);
    const fixture = makeRpCertificate({
      kind: 'ec',
      subject: { organizationName: 'RP', country: 'BE' },
      rawScopeExtnValue: tlv(0x04, attributes),
    });
    const parsed = parseRpAccessCertificate(fixture.der);
    expect(parsed.scope.attributes).toEqual([]);
    expect(parsed.scope.purposes).toEqual([]);
    expect(parsed.scope.categories).toEqual([]);
  });

  test('SEQUENCE でない Attribute 要素は読み飛ばし、正規の要素だけを採る', () => {
    const bogus = tlv(0x04, [
      ...oid(RP_ACCESS_ATTR_OIDS.authorizedPurposes),
      ...tlv(0x31, tlv(0x0c, [...Buffer.from('spoofed', 'utf8')])),
    ]);
    const genuine = tlv(0x30, [
      ...oid(RP_ACCESS_ATTR_OIDS.authorizedAttributes),
      ...tlv(0x31, tlv(0x0c, [...Buffer.from('family_name', 'utf8')])),
    ]);
    const fixture = makeRpCertificate({
      kind: 'ec',
      subject: { organizationName: 'RP', country: 'BE' },
      rawScopeExtnValue: tlv(0x30, [...bogus, ...genuine]),
    });
    const parsed = parseRpAccessCertificate(fixture.der);
    expect(parsed.scope.attributes).toEqual(['family_name']);
    expect(parsed.scope.purposes).toEqual([]);
  });
});
