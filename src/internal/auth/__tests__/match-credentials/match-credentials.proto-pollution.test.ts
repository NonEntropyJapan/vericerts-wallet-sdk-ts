/**
 * `matchCredentialsAgainstRequest`（`internal/auth/match-credentials/index.ts`）が
 * `Object.prototype` 汚染下でも own-property 規律を守ることの回帰テスト。
 *
 * `request.dcqlQuery !== undefined` / `request.presentationDefinition !== undefined` は鎖読みのため、
 * `buildRequest`（request.ts）が未指定のクエリキーを条件付き展開で生やさない結果、`dcql_query` も
 * `presentation_definition` も持たない要求では own プロパティとして存在せず、
 * `Object.prototype.dcqlQuery` / `Object.prototype.presentationDefinition` の汚染値が読まれてしまう。
 *
 * `matchCredentialsAgainstRequest` は `createPresentation` の候補集合検証
 * （開示制御のゲート）としても使われるようになったため、この迂回は「本来 3080 で拒否されるべき要求が
 * 任意の保有 VC を含む VP の候補集合を持ってしまう」という開示制御バイパスに直結する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import type { VerifiableCredential } from '../../../credential/index.js';
import { parsePresentationRequest } from '../../jar/index.js';
import { matchCredentialsAgainstRequest } from '../../match-credentials/index.js';

const CLIENT_ID = 'https://verifier.example.com';
const RESPONSE_URI = 'https://verifier.example.com/callback';
const NONCE = 'n-0S6_WzA2Mj-0123456789';
const STATE = 'af0ifjsldkj';

/** `dcql_query` / `presentation_definition` のいずれも持たない直接形式の requestURI を組み立てる。 */
function buildRequestUriWithoutQuery(): string {
  const search = new URLSearchParams({
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: NONCE,
    state: STATE,
  });
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

describe('matchCredentialsAgainstRequest — Object.prototype 汚染下での own-property 規律', () => {
  it('dcql_query も presentation_definition も own に持たない要求は、Object.prototype.dcqlQuery 汚染下でも空集合のまま扱われる', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const request = await parsePresentationRequest(buildRequestUriWithoutQuery());
    expect(Object.hasOwn(request, 'dcqlQuery')).toBe(false);

    // 汚染は await をまたいで保たれている必要がある（`matchCredentialsAgainstRequest` は
    // presentation_definition 分岐を動的 import するため async）。
    const result = await withPollutedPrototypeAsync(
      { dcqlQuery: { credentials: [{ id: 'degree', format: 'jwt_vc_json' }] } },
      () => matchCredentialsAgainstRequest(request, [bob]),
    );

    expect(result).toEqual([]);
  });

  it('dcql_query も presentation_definition も own に持たない要求は、Object.prototype.presentationDefinition 汚染下でも空集合のまま扱われる', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const request = await parsePresentationRequest(buildRequestUriWithoutQuery());
    expect(Object.hasOwn(request, 'presentationDefinition')).toBe(false);

    const pollutedPd = {
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

    const result = await withPollutedPrototypeAsync({ presentationDefinition: pollutedPd }, () =>
      matchCredentialsAgainstRequest(request, [bob]),
    );

    expect(result).toEqual([]);
  });
});
