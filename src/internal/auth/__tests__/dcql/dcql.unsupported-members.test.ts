/**
 * DCQL の評価未対応条件を黙って捨てず fail-closed で扱うことの回帰テスト。
 *
 * Verifier が `meta.type_values` 等で絞り込んだ要求を Wallet が評価できないのに、無制約として
 * 無関係な VC を候補・開示ゲートに通してはならない。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../credential/index.js';
import { createPrivateKeySigner } from '../../../credential/index.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createPresentation } from '../../create-presentation/index.js';
import {
  type DcqlQuery,
  evaluateDcql,
  parseDcqlQuery,
  type QueryableCredential,
} from '../../dcql/dcql.js';
import type { PresentationRequest } from '../../request.js';

/** 構造不正（`unsupported_dcql_member` ではない 8030）を期待する。 */
function expectParseError(raw: Record<string, unknown>): void {
  try {
    parseDcqlQuery(raw);
    throw new Error('should have thrown');
  } catch (err) {
    expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
}

function expectUnsupported(raw: Record<string, unknown>): void {
  try {
    parseDcqlQuery(raw);
    throw new Error('should have thrown');
  } catch (err) {
    expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect((err as VericertsError).context).toMatchObject({ reason: 'unsupported_dcql_member' });
  }
}

describe('parseDcqlQuery: 評価できない条件は 8030（unsupported_dcql_member）', () => {
  it.each([
    ['doctype_values', { doctype_values: ['org.iso.18013.5.1.mDL'] }],
    ['doctype_value', { doctype_value: 'org.iso.18013.5.1.mDL' }],
    ['vct_values と併記の未知メンバ', { vct_values: ['https://example.com/pid'], x: 1 }],
  ])('meta.%s', (_label, meta) => {
    expectUnsupported({ credentials: [{ id: 'q', format: 'jwt_vc_json', meta }] });
  });

  it.each(['claim_sets', 'trusted_authorities'])('要件の %s', (member) => {
    expectUnsupported({ credentials: [{ id: 'q', format: 'jwt_vc_json', [member]: [] }] });
  });

  // `multiple: true`（複数提示の要求）は評価できないので拒否する。boolean 以外も意味を決められない
  // 以上は拒否する。いっぽう `false` は既定値と同じで要求を緩めないので受理する。
  it.each([true, 'yes', 1])('要件の multiple: %p は拒否する', (multiple) => {
    expectUnsupported({ credentials: [{ id: 'q', format: 'jwt_vc_json', multiple }] });
  });

  it('要件の multiple: false は受理して無視する（既定値と同じで要求を緩めない）', () => {
    const query = parseDcqlQuery({
      credentials: [{ id: 'q', format: 'dc+sd-jwt', multiple: false, meta: { vct_values: ['x'] } }],
    });
    expect(query.credentials).toHaveLength(1);
  });

  // OID4VP 1.0 では jwt_vc_json の meta.type_values が必須メンバなので、拒否すると仕様どおりの
  // 要求を 1 件も受理できない。
  it('meta.type_values を受理する（jwt_vc_json の必須メタ）', () => {
    const query = parseDcqlQuery({
      credentials: [
        {
          id: 'q',
          format: 'jwt_vc_json',
          meta: { type_values: [['VerifiableCredential', 'UniversityDegree']] },
        },
      ],
    });
    expect(query.credentials[0]?.meta?.type_values).toEqual([
      ['VerifiableCredential', 'UniversityDegree'],
    ]);
  });

  it.each([
    [[]],
    [[[]]],
    [['VerifiableCredential']],
    [[[1]]],
  ])('meta.type_values: %p は構造不正として 8030', (typeValues) => {
    expectParseError({
      credentials: [{ id: 'q', format: 'jwt_vc_json', meta: { type_values: typeValues } }],
    });
  });

  it('クエリの credential_sets', () => {
    expectUnsupported({
      credential_sets: [{ options: [['q']] }],
      credentials: [{ id: 'q', format: 'jwt_vc_json' }],
    });
  });

  it('vct_values: [] は「制約なし」ではなく 8030', () => {
    try {
      parseDcqlQuery({ credentials: [{ id: 'q', format: 'vc+sd-jwt', meta: { vct_values: [] } }] });
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('対応済みの条件だけなら従来どおり受理する（対照）', () => {
    const query = parseDcqlQuery({
      credentials: [
        {
          id: 'q',
          format: 'vc+sd-jwt',
          meta: { vct_values: ['https://example.com/pid'] },
          claims: [{ path: ['a'] }],
        },
      ],
    });
    expect(query.credentials).toHaveLength(1);
  });
});

describe('evaluateDcql: パースを経ない手組みクエリでも fail-closed', () => {
  const sdJwtCred: QueryableCredential = {
    id: 'urn:cred:1',
    format: 'vc+sd-jwt',
    vct: 'https://example.com/pid',
    claims: { a: 1 },
  };
  const jwtVcCred: QueryableCredential = {
    id: 'urn:cred:2',
    format: 'jwt_vc_json',
    claims: { credentialSubject: { name: 'Bob' } },
  };

  const query = (format: string, meta: unknown): DcqlQuery => ({
    credentials: [{ id: 'q', format, meta: meta as never }],
  });

  // type を包含しない VC は従来どおりマッチしない。
  it('meta.type_values を包含しない VC はマッチしない', () => {
    const q = query('jwt_vc_json', { type_values: [['VerifiableCredential', 'UniversityDegree']] });
    expect(evaluateDcql(q, [jwtVcCred])).toEqual([]);
  });

  it('meta.type_values を包含する VC はマッチする', () => {
    const degree: QueryableCredential = {
      id: 'urn:cred:3',
      format: 'jwt_vc_json',
      claims: { type: ['VerifiableCredential', 'UniversityDegree'], credentialSubject: {} },
    };
    const q = query('jwt_vc_json', { type_values: [['VerifiableCredential', 'UniversityDegree']] });
    expect(evaluateDcql(q, [degree])).toHaveLength(1);
  });

  // 外側は OR（いずれか 1 つの内側配列を満たせばよい）。
  it('meta.type_values は内側配列のいずれか 1 つを満たせばマッチする', () => {
    const mdl: QueryableCredential = {
      id: 'urn:cred:4',
      format: 'jwt_vc_json',
      claims: { type: ['VerifiableCredential', 'MobileDrivingLicence'] },
    };
    const q = query('jwt_vc_json', {
      type_values: [['VerifiableCredential', 'UniversityDegree'], ['MobileDrivingLicence']],
    });
    expect(evaluateDcql(q, [mdl])).toHaveLength(1);
  });

  it('type を持たない VC（SD-JWT 等）は type_values にマッチしない', () => {
    const q = query('vc+sd-jwt', { type_values: [['VerifiableCredential']] });
    expect(evaluateDcql(q, [sdJwtCred])).toEqual([]);
  });

  it('meta.doctype_values はマッチさせない', () => {
    expect(evaluateDcql(query('vc+sd-jwt', { doctype_values: ['x'] }), [sdJwtCred])).toEqual([]);
  });

  it('vct_values: [] は全件通さずマッチさせない', () => {
    expect(evaluateDcql(query('vc+sd-jwt', { vct_values: [] }), [sdJwtCred])).toEqual([]);
  });

  it('meta なし / 空 meta は従来どおり制約なし（対照）', () => {
    expect(evaluateDcql(query('vc+sd-jwt', undefined), [sdJwtCred])).toHaveLength(1);
    expect(evaluateDcql(query('vc+sd-jwt', {}), [sdJwtCred])).toHaveLength(1);
  });
});

describe('createPresentation: 評価できない要求で無関係な VC を提示しない', () => {
  const signer = createPrivateKeySigner(new Uint8Array(32).fill(11), 'ES256');
  const passport: VerifiableCredential = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'Passport'],
    issuer: 'did:example:issuer',
    credentialSubject: { name: 'Bob' },
    issuanceDate: '2025-01-01T00:00:00Z',
    id: 'urn:vc:passport',
  };

  it('type_values 付き要求では Passport の選択が 3080 で拒否される', async () => {
    const request = {
      responseType: 'vp_token',
      clientId: 'https://verifier.example.com',
      responseMode: 'direct_post',
      responseUri: 'https://verifier.example.com/callback',
      nonce: 'n-0S6_WzA2Mj-0123456789',
      state: 's',
      dcqlQuery: {
        credentials: [
          {
            id: 'degree',
            format: 'jwt_vc_json',
            meta: { type_values: [['VerifiableCredential', 'UniversityDegree']] },
          },
        ],
      },
    } as unknown as PresentationRequest;

    await expect(
      createPresentation(request, [passport], [passport], signer, 'did:example:holder'),
    ).rejects.toThrow(new VericertsError(ErrorCodes.VC_REQUIREMENT_MISMATCH));
  });
});
