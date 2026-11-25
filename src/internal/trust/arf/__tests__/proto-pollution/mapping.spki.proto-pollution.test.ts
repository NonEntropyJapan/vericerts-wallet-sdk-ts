/**
 * `mapArfToTsl` の `entry.spki` / `cert.granted` 汚染耐性。
 *
 * `loadArfTrustAnchor` は SPKI を持たない ARF エントリ（Layer 3 のみ）に `spki` プロパティを生やさない。
 * 素で読むと `Object.prototype.spki` に TSL の granted 証明書の SPKI（公開情報）を置くだけで、ARF にしか
 * 載っていないエントリが TSL と突き合わさって `matched` になる。汚染前後で結果が変わらないことで検証する。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { makeCertificate } from '../../../etsi-tsl/__tests__/fixtures.js';
import { parseCertificate } from '../../../etsi-tsl/x509.js';
import type { ArfCatalogueEntry } from '../../arf-types.js';
import { arfEntrySpki, mapArfToTsl, type TslServiceCertificate } from '../../mapping.js';

const cert = makeCertificate({ cn: 'Qualified', kind: 'ec' });
const spki = parseCertificate(cert.der).spki;
const tsl: TslServiceCertificate[] = [{ certDer: cert.der, granted: true }];
/** SPKI なし = ARF のみの登録エントリ。 */
const arfOnlyEntry: ArfCatalogueEntry = { id: 'https://rp.example', role: 'relying-party' };

describe('mapArfToTsl の spki / granted 汚染耐性', () => {
  test('SPKI を持たない ARF エントリは汚染 spki で TSL に突き合わさらない', () => {
    const clean = mapArfToTsl([arfOnlyEntry], tsl);
    expect(clean.matched).toHaveLength(0);
    const polluted = withPollutedPrototype({ spki }, () => mapArfToTsl([arfOnlyEntry], tsl));
    expect(polluted.matched).toHaveLength(0);
    expect(polluted.arfOnly).toEqual(clean.arfOnly);
    expect(polluted.tslOnly).toHaveLength(clean.tslOnly.length);
  });

  test('arfEntrySpki は own の Uint8Array だけを返し、汚染値・非 Uint8Array は無いものとする', () => {
    withPollutedPrototype({ spki }, () => {
      expect(arfEntrySpki(arfOnlyEntry)).toBeUndefined();
      expect(arfEntrySpki({ ...arfOnlyEntry, spki })).toBe(spki);
    });
    const forged = { ...arfOnlyEntry, spki: 'AAAA' } as unknown as ArfCatalogueEntry;
    expect(arfEntrySpki(forged)).toBeUndefined();
  });

  test('own の SPKI は汚染下でも従来どおり突き合わさる（正常系）', () => {
    const other = makeCertificate({ cn: 'Other', kind: 'ec' });
    const result = withPollutedPrototype({ spki: parseCertificate(other.der).spki }, () =>
      mapArfToTsl([{ ...arfOnlyEntry, spki }], tsl),
    );
    expect(result.matched).toHaveLength(1);
  });

  test('granted を欠く TSL 証明書は汚染 granted:true で granted 扱いにならない', () => {
    const ungranted = [{ certDer: cert.der }] as unknown as TslServiceCertificate[];
    const result = withPollutedPrototype({ granted: true }, () =>
      mapArfToTsl([{ ...arfOnlyEntry, spki }], ungranted),
    );
    expect(result.matched).toHaveLength(0);
    expect(result.tslOnly).toHaveLength(0);
  });
});
