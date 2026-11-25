/**
 * `matchCredentials` の単体テスト（実鍵・モック禁止）。
 *
 * `__tests__/` 直下ではなくサブディレクトリへ切り出すのは 1 ディレクトリ行数上限
 * （.linterly.yml）対応（`proto-pollution/` 等と同じ理由）。
 *
 * 検証内容:
 * - `dcql_query` に合致する保有 VC を返す。
 * - `dcql_query` に合致しない場合は空配列を返す。
 * - `dcql_query` も `presentation_definition` も無い要求は空配列を返す。
 * - `presentation_definition` 単独の要求は `matchCredentialsByPresentationDefinition`（同じ
 *   internal/auth 層、PEx v2 評価エンジン `evaluatePresentationDefinition` を使う。ラッパー
 *   `matchCredentialsByPresentationDefinitionWith` とも共有）へ委譲して評価する（
 *   PEx v2 評価エンジンを共有する）。
 * - `presentation_definition` の構造が不正な場合は `parsePresentationDefinition` 由来の `8030` を
 *   伝播する（`8050` ではなく評価不能を明示的に拒否する fail-closed）。
 * - 要求のパース自体に失敗した場合は `parsePresentationRequest` 由来の `8030` を伝播する。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../credential/index.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { matchCredentials } from '../../match-credentials/index.js';

const CLIENT_ID = 'https://verifier.example.com';
const RESPONSE_URI = 'https://verifier.example.com/callback';
const NONCE = 'n-0S6_WzA2Mj-0123456789';
const STATE = 'af0ifjsldkj';

/** DCQL クエリを含む直接形式の requestURI を組み立てる。 */
function buildRequestUri(overrides: Record<string, string | undefined> = {}): string {
  const dcql = {
    credentials: [
      {
        id: 'degree',
        format: 'jwt_vc_json',
        claims: [{ path: ['credentialSubject', 'name'], values: ['Bob'] }],
      },
    ],
  };
  const params: Record<string, string | undefined> = {
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: NONCE,
    state: STATE,
    dcql_query: JSON.stringify(dcql),
    ...overrides,
  };
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      search.set(key, value);
    }
  }
  return `openid4vp://?${search.toString()}`;
}

function makeVc(id: string, name: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'UniversityDegree'],
    issuer: 'did:example:issuer',
    credentialSubject: { name },
    issuanceDate: '2025-01-01T00:00:00Z',
    id,
  };
}

describe('matchCredentials', () => {
  it('dcql_query に合致する保有 VC を返す', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const alice = makeVc('urn:vc:alice', 'Alice');

    const result = await matchCredentials(buildRequestUri(), [alice, bob]);

    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe('urn:vc:bob');
  });

  it('dcql_query に合致しない場合は空配列を返す', async () => {
    const alice = makeVc('urn:vc:alice', 'Alice');

    const result = await matchCredentials(buildRequestUri(), [alice]);

    expect(result).toEqual([]);
  });

  it('dcql_query も presentation_definition も無い要求は空配列を返す', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');

    const result = await matchCredentials(buildRequestUri({ dcql_query: undefined }), [bob]);

    expect(result).toEqual([]);
  });

  it('presentation_definition 単独の要求は PEx v2 評価エンジンへ委譲してマッチする VC を返す', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const alice = makeVc('urn:vc:alice', 'Alice');
    const pd = {
      id: 'pd-1',
      input_descriptors: [
        {
          id: 'd1',
          constraints: {
            fields: [
              { path: ['$.credentialSubject.name'], filter: { type: 'string', const: 'Bob' } },
            ],
          },
        },
      ],
    };
    const requestURI = buildRequestUri({
      dcql_query: undefined,
      presentation_definition: JSON.stringify(pd),
    });

    const result = await matchCredentials(requestURI, [alice, bob]);

    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe('urn:vc:bob');
  });

  it('presentation_definition の構造が不正な場合は OID4VP_REQUEST_PARSE_FAILED(8030) を伝播する', async () => {
    const pd = { id: 'pd-1', input_descriptors: [] };
    const requestURI = buildRequestUri({
      dcql_query: undefined,
      presentation_definition: JSON.stringify(pd),
    });

    await expect(matchCredentials(requestURI, [])).rejects.toThrow(
      new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED),
    );
  });

  it('要求のパース失敗（必須パラメータ欠落）は OID4VP_REQUEST_PARSE_FAILED(8030) を伝播する', async () => {
    const requestURI = buildRequestUri({ nonce: undefined });

    await expect(matchCredentials(requestURI, [])).rejects.toThrow(
      new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED),
    );
  });
});
