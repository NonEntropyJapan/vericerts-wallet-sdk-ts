/**
 * `createPresentation` の単体テスト（実鍵・モック禁止）。
 *
 * `__tests__/` 直下ではなくサブディレクトリへ切り出すのは 1 ディレクトリ行数上限（.linterly.yml）
 * 対応（`match-credentials/` と同じ理由）。
 *
 * 検証内容:
 * - 要求の候補集合（`matchCredentialsAgainstRequest` が返す VC）に含まれる VC を選択した場合、VP を
 *   構築し JWT-VP として署名する（`verifyPresentation` で往復検証できる。aud/nonce も配線される）。
 * - 候補に含まれない VC を選択した場合は `VC_REQUIREMENT_MISMATCH`(3080) を投げる。
 * - `presentation_definition` 単独要求でも候補集合を経由して VP を作成できる（
 *   選定ロジックを再利用していることの確認）。
 * - `opts.checkLoa`が VC 選択の検証後・VP 構築前に、選択済み VC を引数として
 *   呼ばれる。
 * - `selectedVCs` が空の場合は `VC_REQUIREMENT_MISMATCH`(3080) で拒否する（空 VP を署名してしまう
 *   「署名オラクル」化の防止）。
 * - 要求が `dcql_query` / `presentation_definition` のいずれも持たない（候補集合が空になる）場合も
 *   同様に 3080 で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../credential/index.js';
import { createPrivateKeySigner, verifyPresentation } from '../../../credential/index.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { createPresentation } from '../../create-presentation/index.js';
import { parsePresentationRequest } from '../../jar/index.js';

const CLIENT_ID = 'https://verifier.example.com';
const RESPONSE_URI = 'https://verifier.example.com/callback';
const NONCE = 'n-0S6_WzA2Mj-0123456789';
const STATE = 'af0ifjsldkj';
const HOLDER_DID = 'did:example:holder';

const PRIVATE_KEY = new Uint8Array(32).fill(11);
const SIGNER = createPrivateKeySigner(PRIVATE_KEY, 'ES256');
const PUBLIC_KEY_JWK = {
  kty: 'EC' as const,
  crv: 'P-256',
  x: Buffer.from(getP256PublicKey(PRIVATE_KEY, false).subarray(1, 33)).toString('base64url'),
  y: Buffer.from(getP256PublicKey(PRIVATE_KEY, false).subarray(33, 65)).toString('base64url'),
};

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

/**
 * `VerifiableCredential` を `VerifiablePresentation.verifiableCredential` の要素型（object 表現）
 * として比較するための型変換のみのキャスト（値は変換しない。実装側の埋め込みと同じ理由、
 * `create-presentation.ts` のコメント参照）。
 */
function asEmbedded(vc: VerifiableCredential): Readonly<Record<string, unknown>> {
  return vc as unknown as Readonly<Record<string, unknown>>;
}

describe('createPresentation', () => {
  it('候補に含まれる VC を選択した場合、JWT-VP として署名し往復検証できる', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const alice = makeVc('urn:vc:alice', 'Alice');
    const request = await parsePresentationRequest(buildRequestUri());

    const result = await createPresentation(request, [bob], [alice, bob], SIGNER, HOLDER_DID);

    expect(result.holder).toBe(HOLDER_DID);
    expect(result.verifiableCredential).toEqual([asEmbedded(bob)]);
    expect(result.jwt.split('.').length).toBe(3);

    const verified = verifyPresentation(result.jwt, {
      key: { publicKeyJwk: PUBLIC_KEY_JWK },
      expectedAudience: CLIENT_ID,
      expectedNonce: NONCE,
    });
    expect(verified.payload.iss).toBe(HOLDER_DID);
    expect(verified.presentation.holder).toBe(HOLDER_DID);
  });

  it('候補に含まれない VC を選択した場合は VC_REQUIREMENT_MISMATCH(3080)', async () => {
    const alice = makeVc('urn:vc:alice', 'Alice');
    const request = await parsePresentationRequest(buildRequestUri());

    await expect(createPresentation(request, [alice], [alice], SIGNER, HOLDER_DID)).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_REQUIREMENT_MISMATCH),
    );
  });

  it('presentation_definition 単独要求でも候補集合を経由して VP を作成できる', async () => {
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
    const request = await parsePresentationRequest(requestURI);

    const result = await createPresentation(request, [bob], [alice, bob], SIGNER, HOLDER_DID);

    expect(result.verifiableCredential).toEqual([asEmbedded(bob)]);
  });

  it('opts.checkLoa は VC 選択の検証後・VP 構築前に選択済み VC を引数として呼ばれる', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const request = await parsePresentationRequest(buildRequestUri());
    const calls: Array<readonly VerifiableCredential[]> = [];

    await createPresentation(request, [bob], [bob], SIGNER, HOLDER_DID, {
      checkLoa: (selectedVCs) => {
        calls.push(selectedVCs);
      },
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual([bob]);
  });

  it('selectedVCs が空の場合は VC_REQUIREMENT_MISMATCH(3080)（空 VP の署名オラクル化を防止）', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const request = await parsePresentationRequest(buildRequestUri());

    await expect(createPresentation(request, [], [bob], SIGNER, HOLDER_DID)).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_REQUIREMENT_MISMATCH),
    );
  });

  it('要求が dcql_query / presentation_definition のいずれも持たない場合は VC_REQUIREMENT_MISMATCH(3080)', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const requestURI = buildRequestUri({ dcql_query: undefined });
    const request = await parsePresentationRequest(requestURI);

    await expect(createPresentation(request, [bob], [bob], SIGNER, HOLDER_DID)).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_REQUIREMENT_MISMATCH),
    );
  });

  describe('opts.rawCredentials（JWT-VC は生の JWS 文字列で内包）', () => {
    it('対応づけのある VC は生の JWS、無い VC は object のまま載る', async () => {
      const bob = makeVc('urn:vc:bob', 'Bob');
      const request = await parsePresentationRequest(buildRequestUri());
      const rawCredentials = new Map([['urn:vc:bob', 'aGVhZGVy.cGF5bG9hZA.c2ln']]);

      const withRaw = await createPresentation(request, [bob], [bob], SIGNER, HOLDER_DID, {
        rawCredentials,
      });
      const withoutRaw = await createPresentation(request, [bob], [bob], SIGNER, HOLDER_DID, {
        rawCredentials: new Map(),
      });

      expect(withRaw.verifiableCredential).toEqual(['aGVhZGVy.cGF5bG9hZA.c2ln']);
      expect(withoutRaw.verifiableCredential).toEqual([asEmbedded(bob)]);
    });

    it.each<[string, unknown]>([
      ['Map 以外', { 'urn:vc:bob': 'a.b.c' }],
      ['文字列以外の値', new Map([['urn:vc:bob', { alg: 'none' }]])],
      ['空文字列', new Map([['urn:vc:bob', '']])],
    ])('%s は VC_SCHEMA_INVALID(3002)（署名の無い VC へ黙って落とさない）', async (_label, rawCredentials) => {
      const bob = makeVc('urn:vc:bob', 'Bob');
      const request = await parsePresentationRequest(buildRequestUri());

      await expect(
        createPresentation(request, [bob], [bob], SIGNER, HOLDER_DID, {
          rawCredentials: rawCredentials as ReadonlyMap<string, string>,
        }),
      ).rejects.toThrow(new VericertsError(ErrorCodes.VC_SCHEMA_INVALID));
    });
  });
});
