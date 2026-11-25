/**
 * `trust/x509/ca-constraints`（basicConstraints / keyUsage）の単体テスト。
 *
 * チェーン検証（`etsi-tsl/chain.ts`）が中間証明書を絞り込む唯一の材料なので、ビット位置と
 * 未使用ビットの扱いをここで直接固定する。上位の回帰テスト（`etsi-tsl/__tests__/chain.test.ts`）は
 * 「攻撃チェーンが落ちること」を見るが、`keyCertSign` を 1 ビット取り違えても落ちるため、
 * 正しいビットを読めていることまでは示せない。
 */

import { describe, expect, it } from 'bun:test';
import { makeCertificate } from '../../etsi-tsl/__tests__/fixtures.js';
import { parseCertificate } from '../../etsi-tsl/x509.js';

describe('ParsedCertificate.ca', () => {
  it('拡張を持たない証明書は CA を名乗っていない', () => {
    const cert = parseCertificate(makeCertificate({ cn: 'Plain', kind: 'ec' }).der);
    expect(cert.ca.isCa).toBe(false);
    // keyUsage 拡張が無い場合は制限なし（RFC 5280 §6.1.4 (n)）。
    expect(cert.ca.canSignCertificates).toBe(true);
  });

  it('basicConstraints の cA を読む', () => {
    expect(parseCertificate(makeCertificate({ cn: 'CA', kind: 'ec', ca: true }).der).ca.isCa).toBe(
      true,
    );
    expect(parseCertificate(makeCertificate({ cn: 'EE', kind: 'ec', ca: false }).der).ca.isCa).toBe(
      false,
    );
  });

  it('basicConstraints の pathLenConstraint を読む', () => {
    // pathLenConstraint は「この CA の下に続けてよい中間 CA の最大数」（RFC 5280 §4.2.1.9）。
    const noSubCa = makeCertificate({ cn: 'CA', kind: 'ec', ca: true, pathLen: 0 });
    expect(parseCertificate(noSubCa.der).ca.pathLenConstraint).toBe(0);
    const twoSubCa = makeCertificate({ cn: 'CA', kind: 'ec', ca: true, pathLen: 2 });
    expect(parseCertificate(twoSubCa.der).ca.pathLenConstraint).toBe(2);
    // pathLenConstraint は OPTIONAL。省略は「無制約」なので undefined。
    const unconstrained = makeCertificate({ cn: 'CA', kind: 'ec', ca: true });
    expect(parseCertificate(unconstrained.der).ca.pathLenConstraint).toBeUndefined();
  });

  it('keyUsage の keyCertSign（bit 5）だけを許可と読む', () => {
    const signing = makeCertificate({ cn: 'CA', kind: 'ec', ca: true, keyUsage: ['keyCertSign'] });
    expect(parseCertificate(signing.der).ca.canSignCertificates).toBe(true);
    // bit 6（cRLSign）は隣接ビット。取り違えるとここが true になる。
    const crlOnly = makeCertificate({ cn: 'CA', kind: 'ec', ca: true, keyUsage: ['cRLSign'] });
    expect(parseCertificate(crlOnly.der).ca.canSignCertificates).toBe(false);
    // bit 0（digitalSignature）だけの keyUsage は未使用ビットが 7 で、bit 5 はそもそも存在しない。
    const signOnly = makeCertificate({
      cn: 'EE',
      kind: 'ec',
      ca: true,
      keyUsage: ['digitalSignature'],
    });
    expect(parseCertificate(signOnly.der).ca.canSignCertificates).toBe(false);
  });
});

describe('ParsedCertificate.canSignData', () => {
  it('digitalSignature（bit 0）を許可と読む', () => {
    const cert = makeCertificate({ cn: 'EE', kind: 'ec', keyUsage: ['digitalSignature'] });
    expect(parseCertificate(cert.der).canSignData).toBe(true);
  });

  it('nonRepudiation（bit 1）だけでも許可と読む', () => {
    // eIDAS の署名用 Qualified 証明書は nonRepudiation だけを立てるものが普通にある。
    // bit 0 しか見ない実装ではここが false になる。
    const cert = makeCertificate({ cn: 'EE', kind: 'ec', keyUsage: ['nonRepudiation'] });
    expect(parseCertificate(cert.der).canSignData).toBe(true);
  });

  it('keyEncipherment（bit 2）だけなら許可しない', () => {
    // 隣接ビット。取り違えるとここが true になる。
    const cert = makeCertificate({ cn: 'EE', kind: 'ec', keyUsage: ['keyEncipherment'] });
    expect(parseCertificate(cert.der).canSignData).toBe(false);
  });

  it('keyCertSign（bit 5）だけなら許可しない', () => {
    // 証明書 / CRL への署名しか許されていない鍵。任意データへの署名は許可されていない。
    const cert = makeCertificate({ cn: 'CA', kind: 'ec', ca: true, keyUsage: ['keyCertSign'] });
    expect(parseCertificate(cert.der).canSignData).toBe(false);
  });

  it('keyUsage 拡張が無ければ許可と読む', () => {
    // 任意拡張なので存在しなければ制限なし（`canSignCertificates` と同じ扱い）。
    const cert = makeCertificate({ cn: 'Plain', kind: 'ec' });
    expect(parseCertificate(cert.der).canSignData).toBe(true);
  });

  it('複数ビットのうち 1 つでも該当すれば許可と読む', () => {
    const cert = makeCertificate({
      cn: 'CA',
      kind: 'ec',
      ca: true,
      keyUsage: ['digitalSignature', 'keyCertSign', 'cRLSign'],
    });
    const parsed = parseCertificate(cert.der);
    expect(parsed.canSignData).toBe(true);
    expect(parsed.ca.canSignCertificates).toBe(true);
  });
});
