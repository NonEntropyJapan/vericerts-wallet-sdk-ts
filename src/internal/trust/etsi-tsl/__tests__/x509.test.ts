import { describe, expect, test } from 'bun:test';
import { decodeOid, readChildren, readNode } from '../../asn1.js';
import { derEquals, parseCertificate, parseTimeForTest } from '../x509.js';
import { makeCertificate } from './fixtures.js';

/** テスト用に UTCTime / GeneralizedTime の DER ノードを組み立てる。 */
function timeNode(tag: number, ascii: string): ReturnType<typeof readNode> {
  const bytes = Uint8Array.from(Buffer.from(ascii, 'ascii'));
  const der = Uint8Array.from([tag, bytes.length, ...bytes]);
  return readNode(der);
}

describe('asn1 DER reader', () => {
  test('SEQUENCE の子要素を読み出す', () => {
    // SEQUENCE { INTEGER 1, INTEGER 2 }
    const der = Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    const node = readNode(der);
    expect(node.tag).toBe(0x30);
    const children = readChildren(node);
    expect(children.length).toBe(2);
    expect(children[0]?.content[0]).toBe(1);
    expect(children[1]?.content[0]).toBe(2);
  });

  test('OID を dotted-decimal にデコードする（sha256WithRSA）', () => {
    // 1.2.840.113549.1.1.11
    const der = Uint8Array.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
    const node = readNode(der);
    expect(decodeOid(node.content)).toBe('1.2.840.113549.1.1.11');
  });

  test('切り詰められたヘッダは例外', () => {
    expect(() => readNode(Uint8Array.from([0x30]))).toThrow();
  });
});

describe('parseCertificate', () => {
  test('RSA 自己署名証明書の各フィールドを抽出する', () => {
    const cert = makeCertificate({ cn: 'Test RSA CA', kind: 'rsa' });
    const parsed = parseCertificate(cert.der);
    expect(parsed.signatureAlg).toBe('RSASSA-PKCS1-v1_5-SHA256');
    expect(parsed.spki[0]).toBe(0x30);
    expect(parsed.signature.length).toBeGreaterThan(200);
    // 自己署名なので issuer === subject。
    expect(derEquals(parsed.issuerDer, parsed.subjectDer)).toBe(true);
    expect(parsed.notBefore).toBeLessThan(parsed.notAfter);
  });

  test('EC P-256 証明書は ECDSA-P256-SHA256 と判定する', () => {
    const cert = makeCertificate({ cn: 'Test EC CA', kind: 'ec' });
    const parsed = parseCertificate(cert.der);
    expect(parsed.signatureAlg).toBe('ECDSA-P256-SHA256');
  });

  test('tbsBytes は SEQUENCE(0x30) で始まる署名対象である', () => {
    const cert = makeCertificate({ cn: 'Test', kind: 'rsa' });
    const parsed = parseCertificate(cert.der);
    expect(parsed.tbsBytes[0]).toBe(0x30);
  });

  test('SEQUENCE でない入力は例外', () => {
    expect(() => parseCertificate(Uint8Array.from([0x02, 0x01, 0x01]))).toThrow();
  });
});

describe('parseTime（UTCTime / GeneralizedTime）', () => {
  const UTC_TIME = 0x17;
  const GENERALIZED_TIME = 0x18;

  test('UTCTime YYMMDDHHMMSSZ を Unix 秒に変換する', () => {
    const t = parseTimeForTest(timeNode(UTC_TIME, '260101000000Z'));
    expect(t).toBe(Math.floor(Date.UTC(2026, 0, 1, 0, 0, 0) / 1000));
  });

  test('UTCTime の 2 桁年は 50 境界で世紀を補完する', () => {
    const past = parseTimeForTest(timeNode(UTC_TIME, '990101000000Z'));
    expect(past).toBe(Math.floor(Date.UTC(1999, 0, 1) / 1000));
    const future = parseTimeForTest(timeNode(UTC_TIME, '490101000000Z'));
    expect(future).toBe(Math.floor(Date.UTC(2049, 0, 1) / 1000));
  });

  test('GeneralizedTime YYYYMMDDHHMMSSZ を変換する', () => {
    const t = parseTimeForTest(timeNode(GENERALIZED_TIME, '20260101120000Z'));
    expect(t).toBe(Math.floor(Date.UTC(2026, 0, 1, 12, 0, 0) / 1000));
  });

  test('GeneralizedTime の小数秒は秒未満として切り捨てる', () => {
    const t = parseTimeForTest(timeNode(GENERALIZED_TIME, '20260101120000.500Z'));
    expect(t).toBe(Math.floor(Date.UTC(2026, 0, 1, 12, 0, 0) / 1000));
  });

  test('末尾 Z が無い時刻は拒否する（RFC 5280 は UTC 必須）', () => {
    expect(() => parseTimeForTest(timeNode(UTC_TIME, '260101000000'))).toThrow();
  });

  test('タイムゾーンオフセット付きは拒否する', () => {
    expect(() => parseTimeForTest(timeNode(GENERALIZED_TIME, '20260101120000+0900'))).toThrow();
  });

  test('不正な小数秒（非数字）は拒否する', () => {
    expect(() => parseTimeForTest(timeNode(GENERALIZED_TIME, '20260101120000.xxZ'))).toThrow();
  });

  test('非数字を含む時刻は拒否する', () => {
    expect(() => parseTimeForTest(timeNode(UTC_TIME, '2601010000ZZZ'))).toThrow();
  });
});

describe('derEquals', () => {
  test('同一バイト列は true、差異があれば false', () => {
    expect(derEquals(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2, 3]))).toBe(true);
    expect(derEquals(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2, 4]))).toBe(false);
    expect(derEquals(Uint8Array.from([1, 2]), Uint8Array.from([1, 2, 3]))).toBe(false);
  });
});

describe('parseCertificate（signatureAlgorithm の一致）', () => {
  test('外側の signatureAlgorithm と tbsCertificate.signature が違う証明書は拒否する', () => {
    // RFC 5280 §4.1.1.2 は両者が同一であることを要求する。食い違うと「署名対象に書かれた
    // アルゴリズム」と「実際に検証するアルゴリズム」が別物になり、署名の意味が確定しない。
    const cert = makeCertificate({ cn: 'Issuer', kind: 'ec' });
    const der = Uint8Array.from(cert.der);
    // ecdsa-with-SHA256（1.2.840.10045.4.3.2）の最後の 1 バイトを SHA384 側へ書き換える。
    // 2 度現れる（tbsCertificate.signature と外側）ので、後ろ = 外側だけを触る。
    const ecdsaSha256 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    const at = lastIndexOfBytes(der, ecdsaSha256);
    expect(at).toBeGreaterThan(0);
    der[at + ecdsaSha256.length - 1] = 0x03;

    expect(() => parseCertificate(der)).toThrow();
  });
});

/** `haystack` の中で `needle` が最後に現れる位置（見つからなければ -1）。 */
function lastIndexOfBytes(haystack: Uint8Array, needle: readonly number[]): number {
  for (let i = haystack.length - needle.length; i >= 0; i--) {
    if (needle.every((byte, j) => haystack[i + j] === byte)) {
      return i;
    }
  }
  return -1;
}
