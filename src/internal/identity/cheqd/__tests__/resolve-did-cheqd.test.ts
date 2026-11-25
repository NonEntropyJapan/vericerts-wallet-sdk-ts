/**
 * resolveDidCheqd のリゾルバー解決の検証。
 *
 * 取得は `fetchFn` 注入のモックで行い、実ネットワークには触れない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { expectRejects, recordingFetch } from '../../__tests__/network-method.fixtures.js';
import {
  createResolutionWorkBudget,
  DEFAULT_MAX_SCOPE_BODY_LENGTH,
  DEFAULT_MAX_SCOPE_WORK_UNITS,
} from '../../resolution-budget.js';
import { resolveDidCheqd } from '../method-cheqd.js';
import {
  key2018,
  key2020,
  keyJwk,
  LIVE_DID,
  LIVE_VERSION_ID,
  RESOLUTION_CONTENT_TYPE,
  RESOLVER_URL,
  resolutionResult,
} from './cheqd.fixtures.js';

const reply = (value: unknown, status = 200) => ({
  status,
  contentType: RESOLUTION_CONTENT_TYPE,
  body: JSON.stringify(value),
});

describe('resolveDidCheqd', () => {
  it('GET <resolverUrl>/1.0/identifiers/<did> で解決し、deactivated / versionId を返す', async () => {
    const { fetchFn, calls } = recordingFetch(() => reply(resolutionResult(LIVE_DID)));
    const { document, metadata } = await resolveDidCheqd(LIVE_DID, {
      resolverUrl: `${RESOLVER_URL}/`,
      fetchFn,
    });
    expect(calls).toEqual([
      {
        url: `${RESOLVER_URL}/1.0/identifiers/${LIVE_DID}`,
        accept: 'application/ld+json;profile="https://w3id.org/did-resolution"',
      },
    ]);
    expect(document.id).toBe(LIVE_DID);
    expect(metadata).toEqual({ deactivated: false, versionId: LIVE_VERSION_ID });
  });

  it('resolverUrl の既定は https://resolver.cheqd.net', async () => {
    const { fetchFn, calls } = recordingFetch(() => reply(resolutionResult(LIVE_DID)));
    await resolveDidCheqd(LIVE_DID, { fetchFn });
    await resolveDidCheqd(LIVE_DID, { resolverUrl: undefined, fetchFn });
    expect(calls.map((call) => call.url)).toEqual([
      `https://resolver.cheqd.net/1.0/identifiers/${LIVE_DID}`,
      `https://resolver.cheqd.net/1.0/identifiers/${LIVE_DID}`,
    ]);
  });

  it('deactivated が無ければ false 扱い。検証関係を持たない文書は空配列で埋める（実機の応答と同じ形）', async () => {
    const { fetchFn } = recordingFetch(() =>
      reply(
        resolutionResult(LIVE_DID, {
          document: { authentication: undefined, assertionMethod: undefined },
          metadata: { versionId: undefined },
        }),
      ),
    );
    const { document, metadata } = await resolveDidCheqd(LIVE_DID, { fetchFn });
    expect(metadata).toEqual({ deactivated: false });
    expect(document.authentication).toEqual([]);
    expect(document.assertionMethod).toEqual([]);
    expect(document.verificationMethod).toHaveLength(1);
  });

  it('versionId / versionTime をクエリに載せ、別の版が返ったら 2010', async () => {
    const { fetchFn, calls } = recordingFetch(() => reply(resolutionResult(LIVE_DID)));
    await resolveDidCheqd(LIVE_DID, {
      resolverUrl: RESOLVER_URL,
      versionId: LIVE_VERSION_ID,
      versionTime: '2023-01-01T00:00:00+09:00',
      fetchFn,
    });
    expect(calls[0]?.url).toBe(
      `${RESOLVER_URL}/1.0/identifiers/${LIVE_DID}?versionId=${LIVE_VERSION_ID}&versionTime=2023-01-01T00%3A00%3A00%2B09%3A00`,
    );
    await expectRejects(
      resolveDidCheqd(LIVE_DID, {
        resolverUrl: RESOLVER_URL,
        versionId: '00000000-0000-0000-0000-000000000000',
        fetchFn,
      }),
      ErrorCodes.DID_DOC_INVALID,
      'cheqd_version_mismatch',
    );
  });

  it('versionId が UUID でない / versionTime がオフセットなし・不正は 2001 で、取得しない', async () => {
    const { fetchFn, calls } = recordingFetch(() => reply(resolutionResult(LIVE_DID)));
    await expectRejects(
      resolveDidCheqd(LIVE_DID, { versionId: 'latest', fetchFn }),
      ErrorCodes.INVALID_DID,
      'cheqd_invalid_version_id',
    );
    for (const versionTime of ['2023-01-01T00:00:00', '2023-01-01', 'nope']) {
      await expectRejects(
        resolveDidCheqd(LIVE_DID, { versionTime, fetchFn }),
        ErrorCodes.INVALID_DID,
        'cheqd_invalid_version_time',
      );
    }
    expect(calls).toHaveLength(0);
  });

  it('形式不正の DID（名前空間なしを含む）は 2001 で、取得しない', async () => {
    const { fetchFn, calls } = recordingFetch(() => reply(resolutionResult(LIVE_DID)));
    await expectRejects(
      resolveDidCheqd('did:cheqd:Ps1ysXP2Ae6GBfxNhNQNKN', { fetchFn }),
      ErrorCodes.INVALID_DID,
      'cheqd_namespace_required',
    );
    expect(calls).toHaveLength(0);
  });

  it('404（実機の notFound）/ 200 + notFound / ネットワークエラーは 2003', async () => {
    const notFoundBody = {
      didResolutionMetadata: { contentType: 'application/ld+json', error: 'notFound' },
    };
    const http404 = recordingFetch(() => ({
      status: 404,
      contentType: 'application/ld+json',
      body: JSON.stringify(notFoundBody),
    }));
    await expectRejects(
      resolveDidCheqd(LIVE_DID, { fetchFn: http404.fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
    );
    const ok = recordingFetch(() => reply(notFoundBody));
    await expectRejects(
      resolveDidCheqd(LIVE_DID, { fetchFn: ok.fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
    );
    const broken = recordingFetch(() => {
      throw new Error('ECONNREFUSED');
    });
    await expectRejects(
      resolveDidCheqd(LIVE_DID, { fetchFn: broken.fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
    );
  });

  it('resolverUrl が https でない / 資格情報付きは 2003 で、取得しない', async () => {
    const { fetchFn, calls } = recordingFetch(() => reply(resolutionResult(LIVE_DID)));
    for (const resolverUrl of ['http://resolver.cheqd.net', 'https://u:p@resolver.cheqd.net']) {
      await expectRejects(
        resolveDidCheqd(LIVE_DID, { resolverUrl, fetchFn }),
        ErrorCodes.DID_NOT_FOUND,
        'insecure_endpoint_url',
      );
    }
    expect(calls).toHaveLength(0);
  });

  it('notFound 以外の解決エラーは 2010 cheqd_resolution_error', async () => {
    const { fetchFn } = recordingFetch(() =>
      reply(resolutionResult(LIVE_DID, { resolutionMetadata: { error: 'invalidDid' } })),
    );
    await expectRejects(
      resolveDidCheqd(LIVE_DID, { fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
      'cheqd_resolution_error',
    );
  });

  it('id が要求した DID と違えば 2010 cheqd_id_mismatch（別 DID の文書を返すリゾルバーを採らない）', async () => {
    const other = 'did:cheqd:mainnet:Ps1ysXP2Ae6GBfxNhNQNKM';
    const { fetchFn } = recordingFetch(() => reply(resolutionResult(LIVE_DID)));
    await expectRejects(
      resolveDidCheqd(other, { fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
      'cheqd_id_mismatch',
    );
  });

  it('deactivated: true は 2001（HTTP 200 でも 410 でも）。失効と読めない 410 は 2003', async () => {
    const body = resolutionResult(LIVE_DID, { metadata: { deactivated: true } });
    for (const status of [200, 410]) {
      const { fetchFn } = recordingFetch(() => reply(body, status));
      await expectRejects(
        resolveDidCheqd(LIVE_DID, { fetchFn }),
        ErrorCodes.INVALID_DID,
        'cheqd_deactivated',
      );
    }
    const gone = recordingFetch(() => reply(resolutionResult(LIVE_DID), 410));
    await expectRejects(
      resolveDidCheqd(LIVE_DID, { fetchFn: gone.fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
    );
    // 500 など他の非 2xx は本文を読まず 2003。
    const server = recordingFetch(() => reply(body, 500));
    await expectRejects(
      resolveDidCheqd(LIVE_DID, { fetchFn: server.fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
    );
  });

  it('メタデータの型不正は 2010 cheqd_metadata_invalid', async () => {
    for (const metadata of [{ deactivated: 'false' }, { versionId: 7 }]) {
      const { fetchFn } = recordingFetch(() => reply(resolutionResult(LIVE_DID, { metadata })));
      await expectRejects(
        resolveDidCheqd(LIVE_DID, { fetchFn }),
        ErrorCodes.DID_DOC_INVALID,
        'cheqd_metadata_invalid',
      );
    }
    const array = recordingFetch(() =>
      reply({ ...resolutionResult(LIVE_DID), didDocumentMetadata: [] }),
    );
    await expectRejects(
      resolveDidCheqd(LIVE_DID, { fetchFn: array.fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
      'cheqd_metadata_invalid',
    );
  });

  it('Ed25519 以外の鍵は 2010 cheqd_key_unsupported。Ed25519 の 3 表現は受理する', async () => {
    const did = LIVE_DID;
    const mixed = resolutionResult(did, {
      document: { verificationMethod: [key2018(did), key2020(did), keyJwk(did)] },
    });
    const accepted = recordingFetch(() => reply(mixed));
    expect(
      (await resolveDidCheqd(did, { fetchFn: accepted.fetchFn })).document.verificationMethod,
    ).toHaveLength(3);
    const secp = resolutionResult(did, {
      document: {
        verificationMethod: [
          {
            id: `${did}#k`,
            type: 'EcdsaSecp256k1VerificationKey2019',
            controller: did,
            publicKeyBase58: 'x',
          },
        ],
      },
    });
    const rejected = recordingFetch(() => reply(secp));
    await expectRejects(
      resolveDidCheqd(did, { fetchFn: rejected.fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
      'cheqd_key_unsupported',
    );
  });

  it('Content-Type 不一致・JSON 不正・本文が配列・文書の配列形状不正は 2010', async () => {
    const html = recordingFetch(() => ({ contentType: 'text/html', body: '<html></html>' }));
    const broken = recordingFetch(() => ({ contentType: RESOLUTION_CONTENT_TYPE, body: '{nope' }));
    const array = recordingFetch(() => reply([]));
    const badShape = recordingFetch(() =>
      reply(resolutionResult(LIVE_DID, { document: { service: 'x' } })),
    );
    const missingDocument = recordingFetch(() => reply({ didDocumentMetadata: {} }));
    for (const { fetchFn } of [html, broken, array, badShape, missingDocument]) {
      await expectRejects(resolveDidCheqd(LIVE_DID, { fetchFn }), ErrorCodes.DID_DOC_INVALID);
    }
  });

  it('ResolutionWorkBudget に本文量を計上し（仕事量は使わない）、尽きたスコープでは取得しない', async () => {
    const body = JSON.stringify(resolutionResult(LIVE_DID));
    const { fetchFn, calls } = recordingFetch(() => ({
      contentType: RESOLUTION_CONTENT_TYPE,
      body,
    }));
    const scope = createResolutionWorkBudget();
    await resolveDidCheqd(LIVE_DID, { fetchFn }, scope);
    expect(scope.remainingBodyLength).toBe(DEFAULT_MAX_SCOPE_BODY_LENGTH - body.length);
    expect(scope.remaining).toBe(DEFAULT_MAX_SCOPE_WORK_UNITS);

    const tight = createResolutionWorkBudget(undefined, body.length - 1);
    await expectRejects(
      resolveDidCheqd(LIVE_DID, { fetchFn }, tight),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(tight.remainingBodyLength).toBe(0);
    const before = calls.length;
    await expectRejects(
      resolveDidCheqd(LIVE_DID, { fetchFn }, tight),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(calls).toHaveLength(before);
  });
});
