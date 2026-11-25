/**
 * (Q)EAA Catalogue 解決のテスト。
 *
 * vct → AttestationCatalogueEntry の解決と、未登録時の 10003 エラーを検証する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createRecordCatalogueSource, resolveAttestationCatalogue } from '../catalogue.js';
import type { AttestationCatalogueEntry } from '../types.js';
import { PID_VCT } from '../types.js';

const pidEntry: AttestationCatalogueEntry = {
  vct: PID_VCT,
  rulebookUrl: 'https://arf.ec.europa.eu/rulebooks/pid.md',
  schemaUrl: 'https://arf.ec.europa.eu/schemas/pid.schema.json',
  version: '1.5',
};

const mdlEntry: AttestationCatalogueEntry = {
  vct: 'urn:eudi:mdl:1',
  rulebookUrl: 'https://arf.ec.europa.eu/rulebooks/mdl.md',
  schemaUrl: 'https://arf.ec.europa.eu/schemas/mdl.schema.json',
  issuerAllowList: ['did:web:dmv.example'],
  version: '1.0',
};

function source() {
  return createRecordCatalogueSource({
    [PID_VCT]: pidEntry,
    'urn:eudi:mdl:1': mdlEntry,
  });
}

describe('resolveAttestationCatalogue', () => {
  test('登録済み vct を解決し schemaUrl を返す', () => {
    const entry = resolveAttestationCatalogue(source(), PID_VCT);
    expect(entry.schemaUrl).toBe('https://arf.ec.europa.eu/schemas/pid.schema.json');
    expect(entry.rulebookUrl).toBe('https://arf.ec.europa.eu/rulebooks/pid.md');
    expect(entry.version).toBe('1.5');
  });

  test('issuerAllowList 付きエントリも解決できる', () => {
    const entry = resolveAttestationCatalogue(source(), 'urn:eudi:mdl:1');
    expect(entry.issuerAllowList).toEqual(['did:web:dmv.example']);
  });

  test('未登録 vct は 10003 EAA_CATALOGUE_NOT_FOUND を投げる', () => {
    expect(() => resolveAttestationCatalogue(source(), 'urn:eudi:unknown:1')).toThrow(
      VericertsError,
    );
    try {
      resolveAttestationCatalogue(source(), 'urn:eudi:unknown:1');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.EAA_CATALOGUE_NOT_FOUND);
      expect((e as VericertsError).category).toBe('eudi');
    }
  });
});

describe('createRecordCatalogueSource', () => {
  test('キーとエントリの vct が食い違う場合は未登録扱い', () => {
    const src = createRecordCatalogueSource({
      'urn:eudi:pid:1': { ...pidEntry, vct: 'urn:eudi:other:1' },
    });
    expect(src.lookup('urn:eudi:pid:1')).toBeUndefined();
  });

  test('lookup は未登録 vct に undefined を返す', () => {
    expect(source().lookup('urn:eudi:none:1')).toBeUndefined();
  });
});
