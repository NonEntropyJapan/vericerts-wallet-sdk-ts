/**
 * `trust/x509`（SubjectAltName の展開 / SPKI → JWK 変換）の単体テスト。
 *
 * 受領した SD-JWT VC の `iss` ↔ 証明書の結び付けと、証明書鍵での JWS 検証はこの 2 つの変換の
 * 上に載る。入口の取りこぼし（SAN が読めないのに空でなく返る・非対応鍵が JWK に化ける）は
 * 上位の fail-closed をすり抜けるため、ここで直接固定する。
 */

import { describe, expect, it } from 'bun:test';
import { createPublicKey } from 'node:crypto';
import { Asn1Error, readNode } from '../../asn1.js';
import { octetString, oid, tlv } from '../../etsi-tsl/__tests__/der.js';
import { parseCertificate } from '../../etsi-tsl/x509.js';
import { makeRpCertificate } from '../../rp-access/__tests__/fixtures.js';
import {
  certificateExtensions,
  OID_SUBJECT_ALT_NAME,
  subjectAltNameUris,
  subjectAltNameUrisOfCertificate,
} from '../san.js';
import { spkiToPublicKeyJwk } from '../spki-jwk.js';

/** `extensions [3]` ノードを拡張の TLV 列から組む。 */
function extensionsNode(...exts: number[][]): ReturnType<typeof readNode> {
  return readNode(Uint8Array.from(tlv(0xa3, tlv(0x30, exts.flat()))));
}

describe('subjectAltNameUrisOfCertificate', () => {
  it('SubjectAltName の URI を取り出す', () => {
    const cert = makeRpCertificate({
      subject: { organizationName: 'Issuer' },
      kind: 'ec',
      origin: 'https://issuer.example.eu',
    });

    expect(subjectAltNameUrisOfCertificate(cert.der)).toEqual(['https://issuer.example.eu']);
  });

  it('SAN 拡張を持たない証明書は空を返す（突き合わせ不成立）', () => {
    const cert = makeRpCertificate({ subject: { organizationName: 'No SAN' }, kind: 'ec' });

    expect(subjectAltNameUrisOfCertificate(cert.der)).toEqual([]);
  });

  it('DER として読めない入力は例外ではなく空を返す（fail-closed）', () => {
    expect(subjectAltNameUrisOfCertificate(new Uint8Array([0x30, 0x80, 0x01]))).toEqual([]);
  });
});

describe('certificateExtensions', () => {
  it('critical BOOLEAN のある拡張でも extnValue を取り違えない', () => {
    const san = tlv(0x30, tlv(0x86, [...Buffer.from('https://issuer.example.eu', 'utf8')]));
    const ext = tlv(0x30, [
      ...oid(OID_SUBJECT_ALT_NAME),
      ...tlv(0x01, [0xff]),
      ...octetString(san),
    ]);
    const extensions = certificateExtensions([extensionsNode(ext)]);

    expect(subjectAltNameUris(extensions)).toEqual(['https://issuer.example.eu']);
    expect(extensions.criticalOids.has(OID_SUBJECT_ALT_NAME)).toBe(true);
  });

  it('extnID しか持たない Extension は読み飛ばす（OID の content を値にしない）', () => {
    const ext = tlv(0x30, oid(OID_SUBJECT_ALT_NAME));
    const extensions = certificateExtensions([extensionsNode(ext)]);

    expect(extensions.byOid.size).toBe(0);
  });

  it('extnValue が SEQUENCE でない SAN は GeneralName として読まない', () => {
    // OCTET STRING の中身が [6] URI に見えるバイト列でも、GeneralNames（SEQUENCE）でなければ
    // 走査してはならない。
    const notASequence = tlv(0x04, [...Buffer.from('https://spoofed.example', 'utf8')]);
    const ext = tlv(0x30, [...oid(OID_SUBJECT_ALT_NAME), ...octetString(notASequence)]);

    expect(subjectAltNameUris(certificateExtensions([extensionsNode(ext)]))).toEqual([]);
  });

  it('同一 OID の拡張が 2 つある証明書は例外にする（RFC 5280 §4.2）', () => {
    const san = (uri: string): number[] =>
      tlv(0x30, [
        ...oid(OID_SUBJECT_ALT_NAME),
        ...octetString(tlv(0x30, tlv(0x86, [...Buffer.from(uri, 'utf8')]))),
      ]);
    const node = extensionsNode(san('https://a.example'), san('https://b.example'));

    // 素の `Error` ではなく `Asn1Error` であること。`trust/rp-access/cert.ts` は
    // 「パース失敗はすべて `Asn1Error`」を前提に失敗を正規化する。
    expect(() => certificateExtensions([node])).toThrow(Asn1Error);
  });
});

describe('spkiToPublicKeyJwk', () => {
  it('EC P-256 の SPKI を JWK（kty/crv/x/y）へ変換する', () => {
    const cert = makeRpCertificate({ subject: { organizationName: 'Issuer' }, kind: 'ec' });
    const expected = createPublicKey(cert.privateKey).export({ format: 'jwk' });

    expect(spkiToPublicKeyJwk(parseCertificate(cert.der).spki)).toEqual({
      kty: 'EC',
      crv: 'P-256',
      x: expected.x,
      y: expected.y,
    });
  });

  it('RSA の SPKI は undefined（SD-JWT の Issuer 署名には使えない）', () => {
    const cert = makeRpCertificate({ subject: { organizationName: 'Issuer' }, kind: 'rsa' });

    expect(spkiToPublicKeyJwk(parseCertificate(cert.der).spki)).toBeUndefined();
  });

  it('DER として読めない入力は undefined', () => {
    expect(spkiToPublicKeyJwk(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]))).toBeUndefined();
  });

  it('subjectPublicKey の未使用ビット数が 0 でない SPKI は undefined（RFC 5280 §4.1.2.7）', () => {
    const cert = makeRpCertificate({ subject: { organizationName: 'Issuer' }, kind: 'ec' });
    const spki = Uint8Array.from(parseCertificate(cert.der).spki);
    // 末尾 65 バイトが SEC1 の非圧縮点（0x04 || x(32) || y(32)）なので、その手前が BIT STRING の
    // 未使用ビット数バイトである。点そのものは触らずそこだけを書き換える。
    const unusedBitsIndex = spki.length - 66;
    expect(spki[unusedBitsIndex]).toBe(0x00);
    expect(spki[unusedBitsIndex + 1]).toBe(0x04);
    spki[unusedBitsIndex] = 0x01;

    expect(spkiToPublicKeyJwk(spki)).toBeUndefined();
  });
});
