import { describe, expect, test } from 'bun:test';
import { makeCertificate } from '../../etsi-tsl/__tests__/fixtures.js';
import { parseCertificate } from '../../etsi-tsl/x509.js';
import type { ArfCatalogueEntry } from '../arf-types.js';
import { mapArfToTsl, type TslServiceCertificate } from '../mapping.js';

/** 証明書から SPKI を取り出す。 */
function spkiOf(der: Uint8Array): Uint8Array {
  return parseCertificate(der).spki;
}

/** ARF エントリを作る。 */
function entry(id: string, spki?: Uint8Array): ArfCatalogueEntry {
  return { id, role: 'issuer', ...(spki !== undefined ? { spki } : {}) };
}

describe('mapArfToTsl', () => {
  test('SPKI 一致で ARF ⇔ TSL を突き合わせる', () => {
    const certA = makeCertificate({ cn: 'A', kind: 'ec' });
    const certB = makeCertificate({ cn: 'B', kind: 'rsa' });
    const tsl: TslServiceCertificate[] = [
      { certDer: certA.der, granted: true },
      { certDer: certB.der, granted: true },
    ];
    const arf = [entry('issuer-a', spkiOf(certA.der)), entry('issuer-b', spkiOf(certB.der))];

    const result = mapArfToTsl(arf, tsl);

    expect(result.matched.length).toBe(2);
    expect(result.arfOnly.length).toBe(0);
    expect(result.tslOnly.length).toBe(0);
    const ids = result.matched.map((m) => m.entry.id).sort();
    expect(ids).toEqual(['issuer-a', 'issuer-b']);
    expect(result.matched[0]?.tslCertDer).toBeInstanceOf(Uint8Array);
  });

  test('ARF のみ・TSL のみを分類する', () => {
    const shared = makeCertificate({ cn: 'S', kind: 'ec' });
    const tslExtra = makeCertificate({ cn: 'T', kind: 'ec' });
    const arfExtra = makeCertificate({ cn: 'R', kind: 'rsa' });

    const tsl: TslServiceCertificate[] = [
      { certDer: shared.der, granted: true },
      { certDer: tslExtra.der, granted: true },
    ];
    const arf = [entry('shared', spkiOf(shared.der)), entry('arf-only', spkiOf(arfExtra.der))];

    const result = mapArfToTsl(arf, tsl);

    expect(result.matched.map((m) => m.entry.id)).toEqual(['shared']);
    expect(result.arfOnly.map((e) => e.id)).toEqual(['arf-only']);
    expect(result.tslOnly.length).toBe(1);
    expect(result.tslOnly[0]).toEqual(tslExtra.der);
  });

  test('granted でない TSL 証明書はマッチにも tslOnly にも含めない', () => {
    const cert = makeCertificate({ cn: 'W', kind: 'ec' });
    const tsl: TslServiceCertificate[] = [{ certDer: cert.der, granted: false }];
    const arf = [entry('a', spkiOf(cert.der))];

    const result = mapArfToTsl(arf, tsl);

    expect(result.matched.length).toBe(0);
    expect(result.tslOnly.length).toBe(0);
    expect(result.arfOnly.map((e) => e.id)).toEqual(['a']);
  });

  test('SPKI を持たない ARF エントリはスキップされる', () => {
    const cert = makeCertificate({ cn: 'X', kind: 'ec' });
    const tsl: TslServiceCertificate[] = [{ certDer: cert.der, granted: true }];
    const arf = [entry('no-key')];

    const result = mapArfToTsl(arf, tsl);

    expect(result.matched.length).toBe(0);
    expect(result.arfOnly.length).toBe(0);
    expect(result.tslOnly.length).toBe(1);
  });

  test('パース不能な TSL 証明書は除外される（fail-closed）', () => {
    const cert = makeCertificate({ cn: 'Y', kind: 'ec' });
    const tsl: TslServiceCertificate[] = [
      { certDer: new Uint8Array([0x00, 0x01]), granted: true },
      { certDer: cert.der, granted: true },
    ];
    const arf = [entry('y', spkiOf(cert.der))];

    const result = mapArfToTsl(arf, tsl);

    expect(result.matched.length).toBe(1);
    expect(result.tslOnly.length).toBe(0);
  });

  test('同一 TSL 証明書は 1 つの ARF エントリにしか対応しない', () => {
    const cert = makeCertificate({ cn: 'Z', kind: 'ec' });
    const spki = spkiOf(cert.der);
    const tsl: TslServiceCertificate[] = [{ certDer: cert.der, granted: true }];
    const arf = [entry('first', spki), entry('second', spki)];

    const result = mapArfToTsl(arf, tsl);

    expect(result.matched.map((m) => m.entry.id)).toEqual(['first']);
    expect(result.arfOnly.map((e) => e.id)).toEqual(['second']);
    expect(result.tslOnly.length).toBe(0);
  });

  test('空入力は空マッピングを返す', () => {
    const result = mapArfToTsl([], []);
    expect(result.matched.length).toBe(0);
    expect(result.arfOnly.length).toBe(0);
    expect(result.tslOnly.length).toBe(0);
  });
});
