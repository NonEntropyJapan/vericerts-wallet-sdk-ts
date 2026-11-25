import { describe, expect, test } from 'bun:test';
import { Asn1Error, decodeOid, readChildren, readNode } from '../asn1.js';
import { parseCertificate } from '../etsi-tsl/x509.js';

describe('asn1.readNode: length は符号なしで扱う', () => {
  // 外側 SEQUENCE(長さ 6) の中に、length = 0xFFFFFFFA の SEQUENCE ヘッダ（6 バイト）を 1 つ置いた細工入力。
  const crafted = Uint8Array.from([0x30, 0x06, 0x30, 0x84, 0xff, 0xff, 0xff, 0xfa]);

  test('最上位ビットが立つ 4 バイト length は負数にならず、範囲超過として拒否する', () => {
    expect(() => readNode(crafted, 2)).toThrow(Asn1Error);
  });

  test('細工した入力で readChildren が前進せず無限ループしない（Asn1Error で終わる）', () => {
    expect(() => readChildren(readNode(crafted))).toThrow(Asn1Error);
  });

  test('細工した証明書は parseCertificate が戻る（ハングしない）', () => {
    expect(() => parseCertificate(crafted)).toThrow();
  });

  test('0x80000000 以上の length も範囲超過（符号付き 32bit の折り返しで通らない）', () => {
    for (const len of [
      [0x80, 0, 0, 0],
      [0xff, 0xff, 0xff, 0xff],
      [0x80, 0, 0, 0x06],
    ]) {
      expect(() => readNode(Uint8Array.from([0x04, 0x84, ...len, 0x00]))).toThrow(Asn1Error);
    }
  });

  test('正常な short / long form は読め、totalLength は常に 2 以上で範囲内に収まる', () => {
    const long = new Uint8Array(0x100 + 4);
    long.set([0x04, 0x82, 0x01, 0x00]);
    const cases = [Uint8Array.from([0x05, 0x00]), Uint8Array.from([0x04, 0x01, 0xaa]), long];
    for (const bytes of cases) {
      const node = readNode(bytes);
      expect(node.totalLength).toBeGreaterThanOrEqual(2);
      expect(node.totalLength).toBe(bytes.length);
    }
  });

  test('非最短の length（先頭 0x00 / 127 以下の long form）は拒否する', () => {
    expect(() => readNode(Uint8Array.from([0x04, 0x81, 0x01, 0xaa]))).toThrow(Asn1Error);
    expect(() =>
      readNode(Uint8Array.from([0x04, 0x82, 0x00, 0x80, ...new Array(0x80).fill(0)])),
    ).toThrow(Asn1Error);
  });
});

describe('asn1.decodeOid: arc は安全整数で組み立てる', () => {
  /** 非負整数を base-128（最短）にエンコードする。 */
  const base128 = (n: number): number[] => {
    const out = [n % 128];
    for (let rest = Math.floor(n / 128); rest > 0; rest = Math.floor(rest / 128)) {
      out.unshift((rest % 128) | 0x80);
    }
    return out;
  };

  test('通常の OID はこれまでどおり読める', () => {
    expect(decodeOid(Uint8Array.from([0x55, 0x1d, 0x13]))).toBe('2.5.29.19');
    expect(decodeOid(Uint8Array.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]))).toBe(
      '1.2.840.113549.1.1.11',
    );
  });

  test('2^25 以上の arc が小さな既知 OID（2.5.29.19）に化けず、安全整数の arc はそのまま読める', () => {
    expect(() => decodeOid(Uint8Array.from([0x55, 0x1d, ...base128(2 ** 35 + 19)]))).not.toThrow();
    expect(decodeOid(Uint8Array.from([0x55, 0x1d, ...base128(2 ** 35 + 19)]))).toBe(
      `2.5.29.${2 ** 35 + 19}`,
    );
    expect(decodeOid(Uint8Array.from([0x55, 0x1d, ...base128(2 ** 25 + 19)]))).toBe(
      `2.5.29.${2 ** 25 + 19}`,
    );
  });

  test('安全整数を超える arc は拒否する', () => {
    expect(() =>
      decodeOid(Uint8Array.from([0x55, 0x1d, ...base128(2 ** 53 - 1), 0x01])),
    ).not.toThrow();
    expect(() =>
      decodeOid(Uint8Array.from([0x55, 0x1d, ...new Array(9).fill(0xff), 0x7f])),
    ).toThrow(Asn1Error);
  });

  test('先頭 0x80 の非最短 arc（2.5.29.19 への別名）を拒否する', () => {
    expect(() => decodeOid(Uint8Array.from([0x55, 0x1d, 0x80, 0x13]))).toThrow(Asn1Error);
  });

  test('継続ビットで終わる未終端 OID を拒否する', () => {
    expect(() => decodeOid(Uint8Array.from([0x55, 0x1d, 0x93]))).toThrow(Asn1Error);
  });

  test('第 1 subidentifier: 2.x（x>=40）は多バイトで第 2 arc を正しく復元する', () => {
    expect(decodeOid(Uint8Array.from(base128(80 + 999)))).toBe('2.999');
    expect(decodeOid(Uint8Array.from([0x27]))).toBe('0.39');
    expect(decodeOid(Uint8Array.from([0x28]))).toBe('1.0');
    expect(decodeOid(Uint8Array.from([0x4f]))).toBe('1.39');
    expect(decodeOid(Uint8Array.from([0x50]))).toBe('2.0');
  });
});
