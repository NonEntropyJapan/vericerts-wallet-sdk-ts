/**
 * DIF Credential Manifest 取得・パースのユニット / 統合テスト
 *
 * 検証内容:
 * - parseCredentialManifest: 必須フィールド検証（3031）、未対応 spec_version（3032）、任意フィールド保持。
 * - fetchCredentialManifest: HTTPS 取得成功（統合）、非 HTTPS / HTTP エラー / ネットワーク失敗 / JSON 不正で 3034。
 *
 * ネットワークは FetchLike スタブで注入し、実 HTTP は行わない（ロジックの実挙動を検証する）。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../auth/oid4vci/oid4vci.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { fetchCredentialManifest, parseCredentialManifest } from '../parse.js';

const SUPPORTED_SPEC_VERSION = 'https://identity.foundation/credential-manifest/spec/v1.0.0/';

/** 最小の有効な Manifest（生 JSON 形）。 */
function rawManifest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'manifest-1',
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: 'https://issuer.example', name: 'Example Issuer' },
    output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
    ...overrides,
  };
}

/** JSON 応答を返す FetchLike スタブ。 */
function jsonFetch(status: number, body: unknown): FetchLike {
  return async () =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });
}

describe('parseCredentialManifest', () => {
  it('有効な Manifest を必須・任意フィールドごとパースする', () => {
    const pd = { id: 'pd-1', input_descriptors: [{ id: 'in-1' }] };
    const format = { jwt_vc_json: { alg: ['ES256'] } };
    const manifest = parseCredentialManifest(rawManifest({ format, presentation_definition: pd }));
    expect(manifest.id).toBe('manifest-1');
    expect(manifest.spec_version).toBe(SUPPORTED_SPEC_VERSION);
    expect(manifest.issuer.id).toBe('https://issuer.example');
    expect(manifest.issuer.name).toBe('Example Issuer');
    expect(manifest.output_descriptors).toHaveLength(1);
    expect(manifest.output_descriptors[0]?.schema).toBe('https://schema.example/IdCard');
    expect(manifest.format).toEqual(format);
    expect(manifest.presentation_definition?.id).toBe('pd-1');
  });

  it('id 欠落で MANIFEST_SCHEMA_INVALID（3031）', () => {
    const raw = rawManifest();
    delete raw.id;
    expect(() => parseCredentialManifest(raw)).toThrow(VericertsError);
    try {
      parseCredentialManifest(raw);
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.MANIFEST_SCHEMA_INVALID);
    }
  });

  it('issuer.id 欠落で 3031', () => {
    try {
      parseCredentialManifest(rawManifest({ issuer: { name: 'no id' } }));
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.MANIFEST_SCHEMA_INVALID);
    }
  });

  it('output_descriptors 空配列で 3031', () => {
    try {
      parseCredentialManifest(rawManifest({ output_descriptors: [] }));
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.MANIFEST_SCHEMA_INVALID);
    }
  });

  it('output_descriptor の schema 欠落で 3031', () => {
    try {
      parseCredentialManifest(rawManifest({ output_descriptors: [{ id: 'od-1' }] }));
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.MANIFEST_SCHEMA_INVALID);
    }
  });

  it('未対応 spec_version で MANIFEST_SPEC_VERSION_UNSUPPORTED（3032）', () => {
    try {
      parseCredentialManifest(
        rawManifest({ spec_version: 'https://example.org/credential-manifest/v2.0.0/' }),
      );
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.MANIFEST_SPEC_VERSION_UNSUPPORTED);
    }
  });

  it('object でない入力で 3031', () => {
    for (const bad of [null, undefined, 'str', 42, []]) {
      try {
        parseCredentialManifest(bad);
        throw new Error('should throw');
      } catch (e) {
        expect((e as VericertsError).code).toBe(ErrorCodes.MANIFEST_SCHEMA_INVALID);
      }
    }
  });

  // `required_loa`。`parseCredentialManifest` が構造不正扱いで丸ごと
  // ホワイトリスト組み立てしており、Issuer が実際に値を載せても `manifest.required_loa` が常に
  // `undefined` になっていた。own 読み + `isLoA` 検証の配線を回帰確認する。
  it('required_loa を required_loa としてパースする', () => {
    const manifest = parseCredentialManifest(rawManifest({ required_loa: 'substantial' }));
    expect(manifest.required_loa).toBe('substantial');
  });

  it('required_loa を指定しない場合は own プロパティとして持たない', () => {
    const manifest = parseCredentialManifest(rawManifest());
    expect(Object.hasOwn(manifest, 'required_loa')).toBe(false);
  });

  it('low / substantial / high 以外の required_loa は 3031 で拒否する', () => {
    try {
      parseCredentialManifest(rawManifest({ required_loa: 'HIGH' }));
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.MANIFEST_SCHEMA_INVALID);
    }
  });
});

describe('fetchCredentialManifest', () => {
  it('HTTPS で取得しパースする（統合）', async () => {
    const manifest = await fetchCredentialManifest('https://issuer.example/manifest.json', {
      fetchImpl: jsonFetch(200, rawManifest()),
    });
    expect(manifest.id).toBe('manifest-1');
  });

  it('非 HTTPS URL で MANIFEST_FETCH_FAILED（3034）', async () => {
    await expect(
      fetchCredentialManifest('http://issuer.example/manifest.json'),
    ).rejects.toMatchObject({ code: ErrorCodes.MANIFEST_FETCH_FAILED });
  });

  it('HTTP エラーで 3034', async () => {
    await expect(
      fetchCredentialManifest('https://issuer.example/manifest.json', {
        fetchImpl: jsonFetch(404, {}),
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.MANIFEST_FETCH_FAILED });
  });

  it('ネットワーク失敗で 3034', async () => {
    const failing: FetchLike = async () => {
      throw new Error('network down');
    };
    await expect(
      fetchCredentialManifest('https://issuer.example/manifest.json', { fetchImpl: failing }),
    ).rejects.toMatchObject({ code: ErrorCodes.MANIFEST_FETCH_FAILED });
  });

  it('JSON パース失敗で 3034', async () => {
    await expect(
      fetchCredentialManifest('https://issuer.example/manifest.json', {
        fetchImpl: jsonFetch(200, 'not-json{'),
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.MANIFEST_FETCH_FAILED });
  });

  it('GET の init に body を載せない（実 fetch は GET+body を TypeError にする）', async () => {
    // GET に body を付けると Node/undici とブラウザは `Request` 構築の時点で
    // `TypeError: Request with GET/HEAD method cannot have body.` を投げる（空文字でも例外）。
    // Bun の fetch だけがこれを許容するため、スタブを注入するこのテスト群では緑のまま
    // 本番経路（`fetchImpl` 未注入）だけが常に 3034 へ潰れる。init を直接見て固定する。
    let seen: Record<string, unknown> | undefined;
    const recording: FetchLike = (_url, init) => {
      seen = init as unknown as Record<string, unknown>;
      return jsonFetch(200, rawManifest())(_url, init);
    };
    await fetchCredentialManifest('https://issuer.example/manifest.json', {
      fetchImpl: recording,
    });
    expect(seen?.method).toBe('GET');
    expect(Object.hasOwn(seen as object, 'body')).toBe(false);
  });

  it('取得後のスキーマ不正は 3031 に伝播する', async () => {
    await expect(
      fetchCredentialManifest('https://issuer.example/manifest.json', {
        fetchImpl: jsonFetch(200, { id: 'x', spec_version: SUPPORTED_SPEC_VERSION }),
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.MANIFEST_SCHEMA_INVALID });
  });
});
