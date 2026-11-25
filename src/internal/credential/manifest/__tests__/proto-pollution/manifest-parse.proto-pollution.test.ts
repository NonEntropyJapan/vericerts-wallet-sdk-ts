/**
 * `parseCredentialManifest`（DIF Credential Manifest のパース）の `Object.prototype` 汚染耐性
 *
 * `raw`（および `issuer` / `output_descriptors[i]` / `presentation_definition` の各サブ構造）は
 * `JSON.parse` 由来で `Object.prototype` を継承する。鎖読みだと、対象キーを**持たない**正当な
 * Manifest でも汚染値が採用され、それぞれ別の実害になる。
 *
 * - `issuer.id`: `issuer.id` を持たない Manifest が検証を通過し、汚染値が
 *   `manifest.issuer.id` として own プロパティに repack される。これは
 *   `submitCredentialApplication`（`application.ts`）の POST 先
 *   （`opts.submitEndpoint ?? manifest.issuer.id`）になるため、**申請が攻撃者のエンドポイントへ
 *   飛ぶ**。
 * - `output_descriptor.id` / `.schema`: DIF 必須フィールドの欠落チェックが素通りする。
 * - `presentation_definition.id`: submission 構築時に使う `definition_id` が汚染値になり得る。
 * - トップレベル `id` / `spec_version` / `output_descriptors` / `issuer`:
 *   必須フィールド欠落そのものが検知不能になる（`output_descriptors` は「1 件以上の配列」判定が
 *   汚染配列で素通りし、`issuer` は汚染オブジェクトがまるごと採用される）。
 *
 * `isNonBlankString` / `isPlainObject` のガードは汚染値が空白のみでない文字列 / オブジェクトで
 * あれば素通りするため防げない。
 *
 * テストは**キーを 1 つずつ単独で汚染する**（mutation check が「この 1 行を戻すとこのテストが
 * 落ちる」という形で成立するように）。`parseCredentialManifest` は同期関数なので
 * `withPollutedPrototype` / `withPollutedPrototypeAccessor`（同期版）を使う。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { parseCredentialManifest } from '../../parse.js';
import type { CredentialManifest } from '../../types.js';

const SUPPORTED_SPEC_VERSION = 'https://identity.foundation/credential-manifest/spec/v1.0.0/';
const HONEST_ISSUER_ID = 'https://issuer.example';
const ATTACKER_ISSUER_ID = 'https://attacker.example/submit';

/** 最小の有効な Manifest（生 JSON 形）。全キーを own プロパティとして持つ。 */
function honestManifest(): Record<string, unknown> {
  return {
    id: 'manifest-1',
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: HONEST_ISSUER_ID },
    output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
    presentation_definition: { id: 'pd-1' },
  };
}

/** 汚染キー 1 つと、そのキーを own プロパティとして持たない Manifest（または部分構造）の組。 */
interface OwnReadCase {
  /** 単独で汚染するキー。 */
  readonly key: string;
  /** 汚染値。 */
  readonly value: unknown;
  /** `key` を own プロパティとして持たない Manifest。 */
  readonly manifest: Record<string, unknown>;
  /** 鎖読みだと何が起きるか（テスト名に出す）。 */
  readonly harm: string;
}

const OWN_READ_CASES: readonly OwnReadCase[] = [
  {
    key: 'id',
    value: 'attacker-manifest-id',
    manifest: (() => {
      const m = honestManifest();
      delete m.id;
      return m;
    })(),
    harm: 'Manifest.id 欠落が検知されない',
  },
  {
    key: 'spec_version',
    value: SUPPORTED_SPEC_VERSION,
    manifest: (() => {
      const m = honestManifest();
      delete m.spec_version;
      return m;
    })(),
    harm: 'spec_version 欠落が検知されない',
  },
  {
    key: 'output_descriptors',
    value: [{ id: 'attacker-od', schema: 'https://attacker.example/schema' }],
    manifest: (() => {
      const m = honestManifest();
      delete m.output_descriptors;
      return m;
    })(),
    harm: '偽の output_descriptors が採用される',
  },
  {
    key: 'issuer',
    value: { id: ATTACKER_ISSUER_ID },
    manifest: (() => {
      const m = honestManifest();
      delete m.issuer;
      return m;
    })(),
    harm: '偽の issuer が採用される（申請提出先の乗っ取りに直結）',
  },
  {
    key: 'id',
    value: ATTACKER_ISSUER_ID,
    manifest: { ...honestManifest(), issuer: {} },
    harm: 'issuer.id 欠落が検知されず申請提出先が攻撃者エンドポイントに化ける',
  },
  {
    key: 'id',
    value: 'attacker-od-id',
    manifest: {
      ...honestManifest(),
      output_descriptors: [{ schema: 'https://schema.example/IdCard' }],
    },
    harm: 'output_descriptor.id 欠落が検知されない',
  },
  {
    key: 'schema',
    value: 'https://attacker.example/schema',
    manifest: { ...honestManifest(), output_descriptors: [{ id: 'od-1' }] },
    harm: 'output_descriptor.schema 欠落が検知されない',
  },
  {
    key: 'id',
    value: 'attacker-pd-id',
    manifest: { ...honestManifest(), presentation_definition: {} },
    harm: 'presentation_definition.id 欠落が検知されない',
  },
];

describe('parseCredentialManifest: Object.prototype 汚染耐性', () => {
  for (const testCase of OWN_READ_CASES) {
    const title = `${testCase.key} の汚染で${testCase.harm}`;

    it(`${title}（データ汚染）`, () => {
      withPollutedPrototype({ [testCase.key]: testCase.value }, () => {
        expect(() => parseCredentialManifest(testCase.manifest)).toThrow(VericertsError);
        try {
          parseCredentialManifest(testCase.manifest);
          throw new Error('should throw');
        } catch (e) {
          expect((e as VericertsError).code).toBe(ErrorCodes.MANIFEST_SCHEMA_INVALID);
        }
      });
    });

    it(`${title}（アクセサ汚染）`, () => {
      withPollutedPrototypeAccessor({ [testCase.key]: () => testCase.value }, () => {
        try {
          parseCredentialManifest(testCase.manifest);
          throw new Error('should throw');
        } catch (e) {
          expect((e as VericertsError).code).toBe(ErrorCodes.MANIFEST_SCHEMA_INVALID);
        }
      });
    });
  }
});

/**
 * 汚染下でも Issuer が**実際に発行した**正当な Manifest はそのまま採用されること（非退行）。
 *
 * own 化が「常に 3031 へ倒れるだけ」の退行になっていないことを示すため、全キーを汚染した状態で
 * 完全な正当 Manifest がこれまでどおりパースされ、かつネストした各値（`issuer.id` /
 * `output_descriptors[i].id` / `.schema` / `presentation_definition.id`）が汚染値ではなく
 * Issuer が実際に返した値で、**own プロパティとして** repack されていることを確認する
 * （repack で継承値が own 化される回帰の逆、正当な own 値が壊れていないことの確認）。
 */
describe('parseCredentialManifest: 汚染下でも正当な Manifest をそのまま採用する', () => {
  const ALL_POLLUTED: Record<string, unknown> = {
    id: 'attacker-manifest-id',
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: ATTACKER_ISSUER_ID },
    output_descriptors: [{ id: 'attacker-od', schema: 'https://attacker.example/schema' }],
    schema: 'https://attacker.example/schema',
    presentation_definition: { id: 'attacker-pd-id' },
  };
  const ALL_POLLUTED_GETTERS = Object.fromEntries(
    Object.entries(ALL_POLLUTED).map(([key, value]) => [key, () => value]),
  );

  type PollutionRunner = (fn: () => CredentialManifest) => CredentialManifest;
  const FORMS: readonly (readonly [string, PollutionRunner])[] = [
    ['データ汚染', (fn) => withPollutedPrototype(ALL_POLLUTED, fn)],
    ['アクセサ汚染', (fn) => withPollutedPrototypeAccessor(ALL_POLLUTED_GETTERS, fn)],
  ];

  for (const [form, run] of FORMS) {
    it(`正当な Manifest は Issuer が返した値どおりにパースされる（${form}）`, () => {
      const manifest = run(() => parseCredentialManifest(honestManifest()));

      expect(manifest.id).toBe('manifest-1');
      expect(manifest.spec_version).toBe(SUPPORTED_SPEC_VERSION);
      expect(manifest.issuer.id).toBe(HONEST_ISSUER_ID);
      expect(manifest.output_descriptors[0]?.id).toBe('od-1');
      expect(manifest.output_descriptors[0]?.schema).toBe('https://schema.example/IdCard');
      expect(manifest.presentation_definition?.id).toBe('pd-1');

      expect(Object.hasOwn(manifest, 'id')).toBe(true);
      expect(Object.hasOwn(manifest.issuer, 'id')).toBe(true);
      expect(Object.hasOwn(manifest.output_descriptors[0] as object, 'id')).toBe(true);
      expect(Object.hasOwn(manifest.output_descriptors[0] as object, 'schema')).toBe(true);
    });
  }
});
