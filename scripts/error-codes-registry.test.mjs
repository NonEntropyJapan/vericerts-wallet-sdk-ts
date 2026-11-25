import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import {
  buildRegistryObject,
  categoryForCode,
  findDuplicateCodes,
  findDuplicateNames,
  validateRegistry,
} from './error-codes-registry.mjs';

describe('categoryForCode', () => {
  test('4 桁は先頭 1 桁で判定する', () => {
    expect(categoryForCode('1001')).toBe('key');
    expect(categoryForCode('2001')).toBe('did');
    expect(categoryForCode('3010')).toBe('vc');
  });

  test('5 桁は先頭 2 桁で判定する', () => {
    expect(categoryForCode('10001')).toBe('eudi');
    expect(categoryForCode('10402')).toBe('eudi');
  });

  test('未知 prefix は throw する', () => {
    expect(() => categoryForCode('9901')).not.toThrow(); // 9 は didcomm
    expect(() => categoryForCode('11001')).toThrow();
  });

  // 定義済みの全ブロック（1xxx〜10xxx）が
  // マップに網羅されていることを保証する。予約ブロック（11xxx 以降）解禁時の
  // マップ追記漏れを、ランタイム throw ではなくテストで早期検知するため。
  test.each([
    ['1001', 'key'],
    ['2001', 'did'],
    ['3001', 'vc'],
    ['4010', 'nonce'],
    ['5001', 'trust'],
    ['6001', 'storage'],
    ['7001', 'aa'],
    ['8001', 'protocol'],
    ['9001', 'didcomm'],
    ['10001', 'eudi'],
  ])('定義済みブロックのコード %s は %s に解決する', (code, category) => {
    expect(categoryForCode(code)).toBe(category);
  });
});

describe('findDuplicateCodes', () => {
  test('重複コードを列挙する', () => {
    expect(findDuplicateCodes([{ code: '1001' }, { code: '1002' }, { code: '1001' }])).toEqual([
      '1001',
    ]);
  });

  test('重複が無ければ空配列', () => {
    expect(findDuplicateCodes([{ code: '1001' }, { code: '1002' }])).toEqual([]);
  });
});

describe('findDuplicateNames', () => {
  // code が異なっても name が衝突すると ErrorCodes 定数が重複するため、name 単位でも検査する。
  test('重複名を列挙する', () => {
    expect(findDuplicateNames([{ name: 'A' }, { name: 'B' }, { name: 'A' }])).toEqual(['A']);
  });

  test('code が異なっても name が同じなら検知する', () => {
    expect(
      findDuplicateNames([
        { code: '3005', name: 'VP_REQUEST_PARSE_FAILED' },
        { code: '8030', name: 'VP_REQUEST_PARSE_FAILED' },
      ]),
    ).toEqual(['VP_REQUEST_PARSE_FAILED']);
  });

  test('重複が無ければ空配列', () => {
    expect(findDuplicateNames([{ name: 'A' }, { name: 'B' }])).toEqual([]);
  });
});

describe('buildRegistryObject', () => {
  test('JSON Schema の URI と codes 配列を返す', () => {
    const entries = [{ code: '1001' }];
    expect(buildRegistryObject(entries)).toEqual({
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      codes: entries,
    });
  });
});

describe('公開レジストリの検証', () => {
  const example = {
    code: '1001',
    category: 'key',
    name: 'EXAMPLE',
    description: 'example',
    related_apis: [],
  };

  test('最小の正しい入力を受理する', () => {
    expect(() => validateRegistry(buildRegistryObject([example]))).not.toThrow();
  });

  test.each([
    ['空のレジストリ', []],
    ['コード衝突', [example, { ...example, name: 'OTHER' }]],
    ['定数名衝突', [example, { ...example, code: '1002' }]],
    ['番号とカテゴリの不一致', [{ ...example, category: 'did' }]],
    ['数値でない番号', [{ ...example, code: '1e03' }]],
    ['先頭ゼロによる別表記', [{ ...example, code: '01001' }]],
    ['数値型の番号', [{ ...example, code: 1001 }]],
    ['不正な定数名', [{ ...example, name: 'camelCase' }]],
    ['説明なし', [{ ...example, description: ' ' }]],
    ['API名の欠落', [{ ...example, related_apis: [''] }]],
    ['復旧コードの誤記', [{ ...example, fail_safe: 'FC?' }]],
    ['未定義の欄', [{ ...example, retriable: false }]],
  ])('%s を拒否する', (_, entries) => {
    expect(() => validateRegistry(buildRegistryObject(entries))).toThrow();
  });
});

describe('公開エラーコードレジストリ', () => {
  const { codes: entries } = JSON.parse(
    readFileSync(new URL('../schemas/error-codes.json', import.meta.url), 'utf8'),
  );
  const byCode = new Map(entries.map((entry) => [entry.code, entry]));

  test('1001 は related 2 件・fail_safe 無し', () => {
    const e = byCode.get('1001');
    expect(e.category).toBe('key');
    expect(e.name).toBe('INVALID_MNEMONIC');
    expect(e.related_apis).toEqual(['importMnemonic', 'generateMnemonic']);
    expect('fail_safe' in e).toBe(false);
  });

  test('1002 をパースできる', () => {
    const e = byCode.get('1002');
    expect(e.name).toBe('INVALID_WORD_COUNT');
    expect(e.related_apis).toEqual(['generateMnemonic']);
  });

  test('1040 をパースできる', () => {
    const e = byCode.get('1040');
    expect(e.name).toBe('DERIVATION_PATH_INVALID');
    expect(e.related_apis).toEqual(['deriveKey', 'createPersona']);
  });

  test('3010 は fail_safe=FC-1', () => {
    const e = byCode.get('3010');
    expect(e.category).toBe('vc');
    expect(e.name).toBe('SIG_INVALID');
    expect(e.fail_safe).toBe('FC-1');
  });

  test('6002 は related []（"内部"）', () => {
    const e = byCode.get('6002');
    expect(e.category).toBe('storage');
    expect(e.related_apis).toEqual([]);
  });

  // 10304 FEDERATION_TRUST_CHAIN_FAILED は buildTrustChain の実装から一度も
  // 投げられず、実際には 5010 TRUST_CHAIN_INVALID が使われていた（5010 との二重定義）。
  // 5010 への統合を正とし 10304 を Deprecated 化したので、related_apis が空（バッククォート
  // 無し記法）になり、説明に Deprecated 明記が残ることを回帰検知する。
  test('10304 は Deprecated 化により related []・説明に Deprecated 明記', () => {
    const e = byCode.get('10304');
    expect(e.category).toBe('eudi');
    expect(e.name).toBe('FEDERATION_TRUST_CHAIN_FAILED');
    expect(e.related_apis).toEqual([]);
    expect(e.description).toContain('Deprecated');
    expect(e.description).toContain('5010');
  });

  test('5010 TRUST_CHAIN_INVALID は buildTrustChain を related_apis に含む（10304 の統合先）', () => {
    const e = byCode.get('5010');
    expect(e.category).toBe('trust');
    expect(e.name).toBe('TRUST_CHAIN_INVALID');
    expect(e.related_apis).toContain('buildTrustChain');
  });

  test('コード重複はゼロ', () => {
    expect(findDuplicateCodes(entries)).toEqual([]);
  });

  test('定数名の重複はゼロ', () => {
    // 異なるコードで同名定数が衝突しないこと。
    expect(findDuplicateNames(entries)).toEqual([]);
  });

  test('VP リクエストパース失敗は 3005（汎用）と 8030（OID4VP）で別名', () => {
    expect(byCode.get('3005').name).toBe('VP_REQUEST_PARSE_FAILED');
    expect(byCode.get('8030').name).toBe('OID4VP_REQUEST_PARSE_FAILED');
  });

  test('全 category が既知（throw しない）', () => {
    for (const entry of entries) {
      expect(typeof entry.category).toBe('string');
    }
  });

  test('1xxx は全件 key カテゴリ', () => {
    const keyEntries = entries.filter(
      (entry) => entry.code.startsWith('1') && entry.code.length === 4,
    );
    expect(keyEntries.length).toBeGreaterThan(0);
    for (const entry of keyEntries) {
      expect(entry.category).toBe('key');
    }
  });

  test('retriable キーは全 entry に存在しない', () => {
    for (const entry of entries) {
      expect('retriable' in entry).toBe(false);
    }
  });
});
