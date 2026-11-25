/**
 * `parseCredentialManifest` とその内部パーサ（`parseIssuer` / `parseOutputDescriptor` /
 * `parsePresentationDefinition`）が Manifest JSON の各メンバを**同じキーで 2 度読まない**こと
 * （「検査と採用を同じ 1 回の読み取り結果で行う」）。
 *
 * 是正前は検査と採用が別々の読み取りだった（`isNonBlankString(raw.id) ? raw.id : …` の形）。
 * プロパティがアクセサなら getter は呼ばれるたびに別の値を返せるため、
 * **`isNonBlankString` を通した値と実際に採用される値が食い違う**（TOCTOU）。
 *
 * `Object.prototype` 汚染そのものは `manifest-parse.proto-pollution.test.ts` の own 限定読みで
 * 塞がるが、2 度読みはそれとは独立した欠陥として残る（own のアクセサでも成立する）。
 * `parseCredentialManifest` は `credential/index.ts` から公開されており、`JSON.parse` 由来とは
 * 限らない任意のオブジェクトを呼び出し側から受け取りうるため、own のアクセサで固定する。
 *
 * 各テストは getter の呼び出し回数も確認する（1 回だけ読むことの直接の固定）。1 回目に honest 値、
 * 2 回目以降に attacker 値を返す accessor を仕込み、2 度読みする実装なら検査は通しつつ 2 回目の
 * attacker 値を採用してしまうことを検出する。
 */

import { describe, expect, it } from 'bun:test';
import { parseCredentialManifest } from '../../parse.js';

const SUPPORTED_SPEC_VERSION = 'https://identity.foundation/credential-manifest/spec/v1.0.0/';
const UNSUPPORTED_SPEC_VERSION = 'https://example.org/credential-manifest/v9.9.9/';

/**
 * `key` を **own のアクセサ**として持つオブジェクトを作る。
 *
 * getter は 1 回目に `first`、2 回目以降は `rest` を返す。2 度読みする実装では検査に `first` を
 * 使いながら `rest` を採用してしまう。読み取り回数を `reads()` で観測する。
 */
function withTogglingAccessor(
  key: string,
  first: unknown,
  rest: unknown,
  base: Record<string, unknown> = {},
): { raw: Record<string, unknown>; reads: () => number } {
  let reads = 0;
  const raw: Record<string, unknown> = { ...base };
  Object.defineProperty(raw, key, {
    get: () => {
      reads += 1;
      return reads === 1 ? first : rest;
    },
    enumerable: true,
    configurable: true,
  });
  return { raw, reads: () => reads };
}

/** honest な Manifest 本体（トップレベルのトグル対象キーを除く）。 */
function baseManifest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'manifest-1',
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: 'https://issuer.example' },
    output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
    ...overrides,
  };
}

describe('parseCredentialManifest: 同一キーを 2 度読まない（アクセサ TOCTOU、トップレベル）', () => {
  it('id は 1 回だけ読み、検査した値をそのまま採用する', () => {
    const { raw, reads } = withTogglingAccessor(
      'id',
      'honest-manifest-id',
      'attacker-manifest-id',
      {
        spec_version: SUPPORTED_SPEC_VERSION,
        issuer: { id: 'https://issuer.example' },
        output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
      },
    );

    const manifest = parseCredentialManifest(raw);

    expect(reads()).toBe(1);
    expect(manifest.id).toBe('honest-manifest-id');
  });

  it('spec_version は 1 回だけ読み、検査（非空・対応版）と採用に同じ値を使う', () => {
    const { raw, reads } = withTogglingAccessor(
      'spec_version',
      SUPPORTED_SPEC_VERSION,
      UNSUPPORTED_SPEC_VERSION,
      {
        id: 'manifest-1',
        issuer: { id: 'https://issuer.example' },
        output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
      },
    );

    const manifest = parseCredentialManifest(raw);

    expect(reads()).toBe(1);
    expect(manifest.spec_version).toBe(SUPPORTED_SPEC_VERSION);
  });

  it('output_descriptors は 1 回だけ読み、検査（配列・1 件以上）と採用に同じ配列を使う', () => {
    const honest = [{ id: 'od-honest', schema: 'https://schema.example/Honest' }];
    const attacker = [{ id: 'od-attacker', schema: 'https://attacker.example/Attacker' }];
    const { raw, reads } = withTogglingAccessor('output_descriptors', honest, attacker, {
      id: 'manifest-1',
      spec_version: SUPPORTED_SPEC_VERSION,
      issuer: { id: 'https://issuer.example' },
    });

    const manifest = parseCredentialManifest(raw);

    expect(reads()).toBe(1);
    expect(manifest.output_descriptors).toHaveLength(1);
    expect(manifest.output_descriptors[0]?.id).toBe('od-honest');
  });

  it('issuer は 1 回だけ読み、検査（plain object）と parseIssuer への引き渡しに同じ値を使う', () => {
    const honest = { id: 'https://honest-issuer.example' };
    const attacker = { id: 'https://attacker-issuer.example' };
    const { raw, reads } = withTogglingAccessor('issuer', honest, attacker, {
      id: 'manifest-1',
      spec_version: SUPPORTED_SPEC_VERSION,
      output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
    });

    const manifest = parseCredentialManifest(raw);

    expect(reads()).toBe(1);
    expect(manifest.issuer.id).toBe('https://honest-issuer.example');
  });

  it('format は 1 回だけ読み、検査（plain object）と採用に同じ値を使う', () => {
    const honest = { jwt_vc_json: { alg: ['ES256'] } };
    const attacker = { jwt_vc_json: { alg: ['none'] } };
    const { raw, reads } = withTogglingAccessor('format', honest, attacker, baseManifest());

    const manifest = parseCredentialManifest(raw);

    expect(reads()).toBe(1);
    expect(manifest.format).toEqual(honest);
  });

  it('presentation_definition は 1 回だけ読み、undefined 判定と parsePresentationDefinition への引き渡しに同じ値を使う', () => {
    const honest = { id: 'pd-honest' };
    const attacker = { id: 'pd-attacker' };
    const { raw, reads } = withTogglingAccessor(
      'presentation_definition',
      honest,
      attacker,
      baseManifest(),
    );

    const manifest = parseCredentialManifest(raw);

    expect(reads()).toBe(1);
    expect(manifest.presentation_definition?.id).toBe('pd-honest');
  });
});

describe('parseCredentialManifest: 同一キーを 2 度読まない（アクセサ TOCTOU、issuer 内側）', () => {
  it('issuer.id は 1 回だけ読み、検査した値をそのまま採用する', () => {
    const inner = withTogglingAccessor(
      'id',
      'https://honest-issuer.example',
      'https://attacker.example/submit',
    );

    const manifest = parseCredentialManifest(baseManifest({ issuer: inner.raw }));

    expect(inner.reads()).toBe(1);
    expect(manifest.issuer.id).toBe('https://honest-issuer.example');
  });

  it('issuer.name は 1 回だけ読み、検査した値をそのまま採用する', () => {
    const inner = withTogglingAccessor('name', 'Honest Issuer', 'Attacker Issuer', {
      id: 'https://issuer.example',
    });

    const manifest = parseCredentialManifest(baseManifest({ issuer: inner.raw }));

    expect(inner.reads()).toBe(1);
    expect(manifest.issuer.name).toBe('Honest Issuer');
  });

  it('issuer.styles は 1 回だけ読み、検査した値をそのまま採用する', () => {
    const honestStyles = { text: { color: '#000000' } };
    const attackerStyles = { text: { color: '#ff0000' } };
    const inner = withTogglingAccessor('styles', honestStyles, attackerStyles, {
      id: 'https://issuer.example',
    });

    const manifest = parseCredentialManifest(baseManifest({ issuer: inner.raw }));

    expect(inner.reads()).toBe(1);
    expect(manifest.issuer.styles).toEqual(honestStyles);
  });
});

describe('parseCredentialManifest: 同一キーを 2 度読まない（アクセサ TOCTOU、output_descriptor 内側）', () => {
  it('output_descriptor.id は 1 回だけ読み、検査した値をそのまま採用する', () => {
    const inner = withTogglingAccessor('id', 'od-honest', 'od-attacker', {
      schema: 'https://schema.example/IdCard',
    });

    const manifest = parseCredentialManifest(baseManifest({ output_descriptors: [inner.raw] }));

    expect(inner.reads()).toBe(1);
    expect(manifest.output_descriptors[0]?.id).toBe('od-honest');
  });

  it('output_descriptor.schema は 1 回だけ読み、検査した値をそのまま採用する', () => {
    const inner = withTogglingAccessor(
      'schema',
      'https://schema.example/Honest',
      'https://attacker.example/Attacker',
      { id: 'od-1' },
    );

    const manifest = parseCredentialManifest(baseManifest({ output_descriptors: [inner.raw] }));

    expect(inner.reads()).toBe(1);
    expect(manifest.output_descriptors[0]?.schema).toBe('https://schema.example/Honest');
  });

  it('output_descriptor.name / .description / .styles / .display はそれぞれ 1 回だけ読む', () => {
    for (const key of ['name', 'description', 'styles', 'display'] as const) {
      const honest = key === 'styles' || key === 'display' ? { k: 'honest' } : 'honest-value';
      const attacker = key === 'styles' || key === 'display' ? { k: 'attacker' } : 'attacker-value';
      const inner = withTogglingAccessor(key, honest, attacker, {
        id: 'od-1',
        schema: 'https://schema.example/IdCard',
      });

      const manifest = parseCredentialManifest(baseManifest({ output_descriptors: [inner.raw] }));

      expect(inner.reads()).toBe(1);
      expect(manifest.output_descriptors[0]?.[key]).toEqual(honest);
    }
  });
});

// `presentation_definition.id` の TOCTOU は検証しない: `parsePresentationDefinition` は id 以外の
// メンバを不透明な PEx v2 構造として扱うため、検証した `raw` をそのまま返し、
// 他パーサのように値を新しいオブジェクトリテラルへ repack しない。そのため呼び出し側
// （`buildCredentialApplication` の `definition.id` 等）が `.id` へアクセスするたびに元の
// アクセサが**改めて**呼ばれるのは意図された仕様であり、2 度読みの欠陥ではない
// （欠陥はあくまで `parsePresentationDefinition` 内部の検査・採用が同じ 1 回の読み取りを使うことで、
// それは `manifest-parse.proto-pollution.test.ts` の own 限定読みテストで担保している）。
