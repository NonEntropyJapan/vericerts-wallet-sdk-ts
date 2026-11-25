/**
 * スキーマ検証ディスパッチャテストの共有フィクスチャ。
 *
 * 実ネットワークを使わないために `fetchImpl` を注入する（`vc/credential-schema` /
 * `sdjwt/type-metadata` のテストと同方針）。`fetchImpl` と VC ビルダは既存の
 * `vc/credential-schema/__tests__/fixtures.ts` を再利用し、二重定義による乖離を避ける。
 */

import { createFailOpenWindow } from '../../../failsafe-policy/index.js';
import type { JsonSchema } from '../../json-schema/index.js';
import { TypeMetadataCache } from '../../sdjwt/type-metadata/cache.js';
import type { SdJwtTypeMetadata } from '../../sdjwt/type-metadata/types.js';
import { CredentialSchemaCache } from '../../vc/credential-schema/cache.js';
import type { RoutedSchemaValidationOptions } from '../types.js';

export {
  buildVc,
  createFetchStub,
  type FetchStub,
  PERSON_SCHEMA,
  SCHEMA_URL,
  type StubResponse,
} from '../../vc/credential-schema/__tests__/fixtures.js';

/** SD-JWT VC 側の `vct`（HTTPS URL = Type Metadata が存在する形）。 */
export const VCT_URL = 'https://issuer.example.com/vct/person/1.0';

/** `given_name`（必須）と `nickname`（任意 / 最大 8 文字）を定義する Type Metadata。 */
export const PERSON_TYPE_METADATA = {
  vct: VCT_URL,
  name: 'Person Credential',
  schema: {
    type: 'object',
    required: ['given_name'],
    properties: {
      given_name: { type: 'string', minLength: 1 },
      nickname: { type: 'string', maxLength: 8 },
    },
  },
};

/** `vct` + `claims` を持つ SD-JWT VC 形式の検証入力を組み立てる。 */
export function buildSdJwt(
  claims: Readonly<Record<string, unknown>>,
  vct: string = VCT_URL,
): { readonly claims: Readonly<Record<string, unknown>>; readonly vct: string } {
  return { claims, vct };
}

/**
 * テストごとに独立したキャッシュと Fail-open 計時ウィンドウを持つ経路固有オプションを作る。
 *
 * モジュール既定の共有キャッシュ / 共有ウィンドウを使うとテスト間でフェッチ回数や fail-open の
 * 可否が変わるため、必ず注入する。
 */
export function freshRouteOptions(): Pick<
  RoutedSchemaValidationOptions,
  'credentialSchemaOptions' | 'typeMetadataOptions'
> {
  return {
    typeMetadataOptions: {
      metadataCache: new TypeMetadataCache<SdJwtTypeMetadata>(),
      schemaCache: new TypeMetadataCache<JsonSchema>(),
      failOpenWindow: createFailOpenWindow(),
    },
    credentialSchemaOptions: {
      schemaCache: new CredentialSchemaCache(),
      failOpenWindow: createFailOpenWindow(),
    },
  };
}

/**
 * Fail-open の成立条件（同意 + 監査記録先）を満たす共通オプション。
 *
 * これらが無いと FO-3 / FO-4 は警告通過しない。計時ウィンドウは
 * 経路固有オプション側（{@link freshRouteOptions}）で注入する。
 */
export function failOpenGrant(): Pick<
  RoutedSchemaValidationOptions,
  'onPolicyEvent' | 'requestConsent'
> {
  return { requestConsent: () => true, onPolicyEvent: () => {} };
}
