/**
 * `buildCredentialApplication` の `manifest.format` / `manifest.presentation_definition` の
 * `Object.prototype` 汚染耐性。
 *
 * `parseCredentialManifest` が返す `CredentialManifest` は、Manifest が `format` /
 * `presentation_definition` を持たない場合その own プロパティを一切定義しない（条件付きスプレッドで
 * 丸ごと省く）。ただのオブジェクトリテラルなので `Object.prototype` を継承しており、
 * `buildCredentialApplication` がこの 2 メンバを鎖読みすると、`format` / `presentation_definition`
 * を省略した正当な Manifest でも `Object.prototype` の汚染値を拾ってしまう。純データ（Manifest の
 * 宣言値）なので own 限定（`ownProperty`）で読む。
 *
 * データプロパティ汚染・アクセサ（getter）汚染の両形式を固定する。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { buildCredentialApplication } from '../../application-build.js';
import { parseCredentialManifest } from '../../parse.js';
import type { CredentialManifest } from '../../types.js';

const SUPPORTED_SPEC_VERSION = 'https://identity.foundation/credential-manifest/spec/v1.0.0/';

/** `format` / `presentation_definition` を持たない正当な Manifest。 */
function manifestWithoutOptionalFields(): CredentialManifest {
  return parseCredentialManifest({
    id: 'manifest-1',
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: 'https://issuer.example/apply' },
    output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
  });
}

/** `format` のみを持つ正当な Manifest（`presentation_definition` は無し）。 */
function manifestWithFormatOnly(): CredentialManifest {
  return parseCredentialManifest({
    id: 'manifest-1',
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: 'https://issuer.example/apply' },
    output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
    format: { jwt_vc_json: {} },
  });
}

/** `presentation_definition` を持つ正当な Manifest。 */
function manifestWithPresentationDefinition(): CredentialManifest {
  return parseCredentialManifest({
    id: 'manifest-1',
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: 'https://issuer.example/apply' },
    output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
    presentation_definition: { id: 'pd-honest' },
  });
}

describe('buildCredentialApplication: manifest.format の Object.prototype 汚染耐性', () => {
  it('format を持たない Manifest は汚染値を own プロパティとして採用しない（データ汚染）', () => {
    withPollutedPrototype({ format: { jwt_vc_json_sw: {} } }, () => {
      const app = buildCredentialApplication(
        manifestWithoutOptionalFields(),
        {},
        {
          generateId: () => 'id-1',
        },
      );
      // `app.format` は `Object.prototype.format` を汚染している間は own 性によらず汚染値を
      // 返してしまう（鎖読みである以上、出力オブジェクト側の検証もこの罠を踏む）ため、
      // `Object.hasOwn` で「own プロパティとして持ち込まれていないこと」を検証する。
      expect(Object.hasOwn(app, 'format')).toBe(false);
    });
  });

  it('format を持たない Manifest は汚染値を own プロパティとして採用しない（アクセサ汚染）', () => {
    withPollutedPrototypeAccessor({ format: () => ({ jwt_vc_json_sw: {} }) }, () => {
      const app = buildCredentialApplication(
        manifestWithoutOptionalFields(),
        {},
        {
          generateId: () => 'id-1',
        },
      );
      expect(Object.hasOwn(app, 'format')).toBe(false);
    });
  });

  it('format を持つ Manifest は汚染下でも Manifest 自身の値を own プロパティとしてエコーバックする（非退行）', () => {
    withPollutedPrototype({ format: { jwt_vc_json_sw: {} } }, () => {
      const app = buildCredentialApplication(
        manifestWithFormatOnly(),
        {},
        {
          generateId: () => 'id-1',
        },
      );
      expect(Object.hasOwn(app, 'format')).toBe(true);
      expect(Object.getOwnPropertyDescriptor(app, 'format')?.value).toEqual({
        jwt_vc_json: {},
      });
    });
  });
});

describe('buildCredentialApplication: manifest.presentation_definition の Object.prototype 汚染耐性', () => {
  it('presentation_definition を持たない Manifest は汚染値を採用せず presentation_submission を構築しない（データ汚染）', () => {
    withPollutedPrototype({ presentation_definition: { id: 'attacker-pd' } }, () => {
      // 汚染値が採用されると、answers が空のため VC_REQUIREMENT_MISMATCH（3080）へ誤って倒れる。
      const app = buildCredentialApplication(
        manifestWithoutOptionalFields(),
        {},
        {
          generateId: () => 'id-1',
        },
      );
      expect(Object.hasOwn(app, 'presentation_submission')).toBe(false);
    });
  });

  it('presentation_definition を持たない Manifest は汚染値を採用せず presentation_submission を構築しない（アクセサ汚染）', () => {
    withPollutedPrototypeAccessor(
      { presentation_definition: () => ({ id: 'attacker-pd' }) },
      () => {
        const app = buildCredentialApplication(
          manifestWithoutOptionalFields(),
          {},
          {
            generateId: () => 'id-1',
          },
        );
        expect(Object.hasOwn(app, 'presentation_submission')).toBe(false);
      },
    );
  });

  it('presentation_definition を持つ Manifest は汚染下でも Manifest 自身の定義で submission を構築する（非退行）', () => {
    withPollutedPrototype({ presentation_definition: { id: 'attacker-pd' } }, () => {
      const app = buildCredentialApplication(
        manifestWithPresentationDefinition(),
        { 'od-1': 'answer' },
        { generateId: () => 'id-1' },
      );
      expect(app.presentation_submission?.definition_id).toBe('pd-honest');
    });
  });
});
