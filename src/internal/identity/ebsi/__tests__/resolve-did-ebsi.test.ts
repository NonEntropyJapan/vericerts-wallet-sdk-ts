/**
 * resolveDidEbsi の Core API 解決の検証。
 *
 * 取得は `fetchFn` 注入のモックで行い、実ネットワークには触れない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import {
  ed25519Jwk,
  expectRejects,
  jsonReply,
  recordingFetch,
} from '../../__tests__/network-method.fixtures.js';
import {
  createResolutionWorkBudget,
  DEFAULT_MAX_SCOPE_BODY_LENGTH,
} from '../../resolution-budget.js';
import { resolveDidEbsi } from '../method-ebsi.js';
import { API_URL, DID, ebsiDocument } from './ebsi.fixtures.js';

describe('resolveDidEbsi', () => {
  it('Core API を GET し DID Document を返す（valid-at なし）', async () => {
    const { fetchFn, calls } = recordingFetch(() =>
      jsonReply(ebsiDocument(), 'application/did+ld+json'),
    );
    const document = await resolveDidEbsi(DID, { apiUrl: `${API_URL}/`, fetchFn });
    expect(document.id).toBe(DID);
    expect(calls).toEqual([
      { url: `${API_URL}/v1/did-registry/identifiers/${DID}`, accept: 'application/did+ld+json' },
    ]);
  });

  it('validAt を valid-at クエリに載せる（`+` オフセットはエンコードする）', async () => {
    const { fetchFn, calls } = recordingFetch(() => jsonReply(ebsiDocument()));
    await resolveDidEbsi(DID, { apiUrl: API_URL, validAt: '2026-01-02T03:04:05+09:00', fetchFn });
    expect(calls[0]?.url).toBe(
      `${API_URL}/v1/did-registry/identifiers/${DID}?valid-at=2026-01-02T03%3A04%3A05%2B09%3A00`,
    );
  });

  it('validAt がオフセットなし・日付のみ・不正な暦は 2001 で、取得しない', async () => {
    const { fetchFn, calls } = recordingFetch(() => jsonReply(ebsiDocument()));
    for (const validAt of [
      '2026-01-02T03:04:05',
      '2026-01-02',
      '2026-13-40T00:00:00Z',
      'yesterday',
    ]) {
      await expectRejects(
        resolveDidEbsi(DID, { apiUrl: API_URL, validAt, fetchFn }),
        ErrorCodes.INVALID_DID,
        'ebsi_invalid_valid_at',
      );
    }
    expect(calls).toHaveLength(0);
  });

  it('形式不正の DID は 2001 で、取得しない', async () => {
    const { fetchFn, calls } = recordingFetch(() => jsonReply(ebsiDocument()));
    await expectRejects(
      resolveDidEbsi('did:ebsi:test:zabc', { apiUrl: API_URL, fetchFn }),
      ErrorCodes.INVALID_DID,
      'ebsi_unsupported_form',
    );
    expect(calls).toHaveLength(0);
  });

  it('404 / ネットワークエラーは 2003', async () => {
    const notFound = recordingFetch(() => ({
      status: 404,
      contentType: 'application/problem+json',
      body: '{"status":404}',
    }));
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn: notFound.fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
    );
    const broken = recordingFetch(() => {
      throw new Error('connect ECONNREFUSED');
    });
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn: broken.fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
    );
  });

  it('apiUrl が https でない / 資格情報・クエリ付き / 未設定は 2003 で、取得しない', async () => {
    const { fetchFn, calls } = recordingFetch(() => jsonReply(ebsiDocument()));
    for (const apiUrl of [
      'http://api.example.org',
      'https://user:pw@api.example.org',
      'https://api.example.org/?x=1',
      'not a url',
      '',
    ]) {
      await expectRejects(
        resolveDidEbsi(DID, { apiUrl, fetchFn }),
        ErrorCodes.DID_NOT_FOUND,
        'insecure_endpoint_url',
      );
    }
    expect(calls).toHaveLength(0);
  });

  it('非公開ホスト宛への取得・リダイレクトは 2003', async () => {
    const privateHost = recordingFetch(() => jsonReply(ebsiDocument()));
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: 'https://10.0.0.5', fetchFn: privateHost.fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
    );
    expect(privateHost.calls).toHaveLength(0);
    const redirecting = recordingFetch(() => ({ status: 302, body: '' }));
    const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
      const response = await redirecting.fetchFn(input, init);
      return new Response(null, {
        status: 302,
        headers: { location: 'https://10.0.0.5/x' },
        ...{ statusText: response.statusText },
      });
    }) as unknown as typeof fetch;
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
    );
  });

  it('id が要求した DID と一致しなければ 2010 ebsi_id_mismatch', async () => {
    const other = 'did:ebsi:zaaaaaaaaaaaaaaaaaaaaaa';
    const { fetchFn } = recordingFetch(() => jsonReply(ebsiDocument(other)));
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
      'ebsi_id_mismatch',
    );
  });

  it('Ed25519 など P-256 / secp256k1 以外の鍵は 2010 ebsi_key_unsupported', async () => {
    const withEd25519 = ebsiDocument(DID, {
      verificationMethod: [
        { id: `${DID}#ed`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: ed25519Jwk() },
      ],
    });
    const { fetchFn } = recordingFetch(() => jsonReply(withEd25519));
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
      'ebsi_key_unsupported',
    );
    const multibaseOnly = ebsiDocument(DID, {
      verificationMethod: [
        {
          id: `${DID}#mb`,
          type: 'Ed25519VerificationKey2020',
          controller: DID,
          publicKeyMultibase: 'z6Mk',
        },
      ],
    });
    const second = recordingFetch(() => jsonReply(multibaseOnly));
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn: second.fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
      'ebsi_key_unsupported',
    );
  });

  it('Content-Type 不一致・JSON 不正・配列形状の不正は 2010', async () => {
    const html = recordingFetch(() => ({ contentType: 'text/html', body: '<html></html>' }));
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn: html.fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
    );
    const broken = recordingFetch(() => ({ body: '{not json' }));
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn: broken.fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
    );
    const notObject = recordingFetch(() => jsonReply([ebsiDocument()]));
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn: notObject.fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
    );
    const badShape = recordingFetch(() =>
      jsonReply(ebsiDocument(DID, { verificationMethod: 'oops' })),
    );
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn: badShape.fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
    );
  });

  it('鍵が失効して空になった文書もそのまま返し、controller 先の DID は辿らない', async () => {
    const delegated = 'did:ebsi:zbbbbbbbbbbbbbbbbbbbbbb';
    const revoked = ebsiDocument(DID, {
      controller: [delegated],
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
      capabilityInvocation: [],
    });
    const { fetchFn, calls } = recordingFetch(() => jsonReply(revoked));
    const document = await resolveDidEbsi(DID, {
      apiUrl: API_URL,
      validAt: '2030-01-01T00:00:00Z',
      fetchFn,
    });
    expect(document.verificationMethod).toEqual([]);
    expect(calls).toHaveLength(1);
  });

  it('ResolutionWorkBudget に取得した本文量を計上し、尽きたスコープでは取得しない', async () => {
    const body = JSON.stringify(ebsiDocument());
    const { fetchFn, calls } = recordingFetch(() => ({ body }));
    const scope = createResolutionWorkBudget();
    await resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn }, scope);
    expect(scope.remainingBodyLength).toBe(DEFAULT_MAX_SCOPE_BODY_LENGTH - body.length);

    const tight = createResolutionWorkBudget(undefined, body.length - 1);
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn }, tight),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(tight.remainingBodyLength).toBe(0);
    const callsBefore = calls.length;
    await expectRejects(
      resolveDidEbsi(DID, { apiUrl: API_URL, fetchFn }, tight),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(calls).toHaveLength(callsBefore);
  });
});
