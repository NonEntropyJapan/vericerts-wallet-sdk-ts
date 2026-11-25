/**
 * `Resolver.resolveUncached`（取り込んだ DID のペルソナの署名・取り込み用）の検証。
 *
 * 解決結果を記憶する 4 メソッド（did:web / did:ebsi / did:ion / did:cheqd）は、通常の解決（`resolve`）が TTL の間
 * 古い DID Document を返すのに対し、`resolveUncached` は鍵のローテーション・削除を次の解決で反映する。
 * 接続先はグローバル `fetch` を差し替えて返し分ける。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../internal/errors.js';
import { p256Jwk } from '../../../internal/identity/__tests__/network-method.fixtures.js';
import {
  RESOLUTION_CONTENT_TYPE,
  resolutionResult,
} from '../../../internal/identity/cheqd/__tests__/cheqd.fixtures.js';
import type { DIDDocument } from '../../../internal/identity/did.js';
import {
  API_URL,
  DID as EBSI_DID,
  ebsiDocument,
} from '../../../internal/identity/ebsi/__tests__/ebsi.fixtures.js';
import {
  ionResponse,
  makeIonCreate,
  NODE_URL,
} from '../../../internal/identity/ion/__tests__/ion.fixtures.js';
import type { Resolver } from '../../../internal/identity/resolver.js';
import { createDidResolver } from '../../did/did-resolver.js';
import { createPersonaSigningResolver } from '../../setup.js';

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

const CHEQD_URL = 'https://resolver.cheqd.example.org';
const CHEQD_DID = 'did:cheqd:mainnet:Ps1ysXP2Ae6GBfxNhNQNKN';
const WEB_DID = 'did:web:rotate.example.com';
const ION = makeIonCreate();

/** ローテーション前（`before`）・後（`after`）で、`assertionMethod` の有無だけが変わる配信。`state.rotated` で切り替える。 */
function serve(state: { rotated: boolean }): void {
  const json = (value: unknown, url: string, contentType = 'application/json'): Response => {
    const response = new Response(JSON.stringify(value), {
      status: 200,
      headers: { 'content-type': contentType },
    });
    // did:web の取得シームは最終 URL の HTTPS を検査する。
    Object.defineProperty(response, 'url', { value: url });
    return response;
  };
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const dropped = state.rotated ? { assertionMethod: undefined } : {};
    if (url.startsWith(API_URL)) {
      return json(ebsiDocument(EBSI_DID, dropped), url);
    }
    if (url.startsWith(NODE_URL)) {
      return json(ionResponse(ION.shortForm, ION, { document: dropped }), url);
    }
    if (url.startsWith(CHEQD_URL)) {
      return json(resolutionResult(CHEQD_DID, { document: dropped }), url, RESOLUTION_CONTENT_TYPE);
    }
    if (url.startsWith('https://rotate.example.com/')) {
      return json(
        {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: WEB_DID,
          verificationMethod: [
            {
              id: `${WEB_DID}#k`,
              type: 'JsonWebKey2020',
              controller: WEB_DID,
              publicKeyJwk: p256Jwk(),
            },
          ],
          ...(state.rotated ? {} : { assertionMethod: [`${WEB_DID}#k`] }),
        },
        url,
        'application/did+json',
      );
    }
    return new Response('', { status: 404 });
  }) as typeof fetch;
}

function newResolver(): Resolver {
  return createDidResolver({
    didNodeUrls: { ebsi: API_URL, ion: NODE_URL, cheqd: CHEQD_URL },
  });
}

const CASES: ReadonlyArray<readonly [string, string]> = [
  ['did:web', WEB_DID],
  ['did:ebsi', EBSI_DID],
  ['did:ion', ION.shortForm],
  ['did:cheqd', CHEQD_DID],
];

function hasAssertionMethod(document: DIDDocument): boolean {
  return (document.assertionMethod?.length ?? 0) > 0;
}

describe('Resolver.resolveUncached: 解決結果を記憶するメソッドもキャッシュしない', () => {
  it.each(
    CASES,
  )('%s: 文書が替わったら次の解決へ直ちに反映される（resolve は古い文書を返す）', async (_name, did) => {
    const state = { rotated: false };
    serve(state);
    const resolver = newResolver();

    expect(hasAssertionMethod(await resolver.resolveUncached(did))).toBe(true);
    expect(hasAssertionMethod(await resolver.resolve(did))).toBe(true);
    state.rotated = true;
    serve(state);

    expect(hasAssertionMethod(await resolver.resolveUncached(did))).toBe(false);
    // 対照: 通常の解決はキャッシュした古い文書を返す（キャッシュなしの経路を分ける理由）。
    expect(hasAssertionMethod(await resolver.resolve(did))).toBe(true);
  });

  it('キャッシュを持たない・決定的なメソッドは通常の登録プラグインで解決する', async () => {
    serve({ rotated: false });
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    expect((await newResolver().resolveUncached(did)).id).toBe(did);
  });

  it('接続先を渡さない did:ebsi / ion / cheqd は resolveUncached も 2002（未登録）', async () => {
    const resolver = createDidResolver();
    for (const did of [EBSI_DID, ION.shortForm, CHEQD_DID]) {
      await expect(resolver.resolveUncached(did)).rejects.toMatchObject({
        code: ErrorCodes.METHOD_NOT_SUPPORTED,
      });
    }
  });

  it('register で同名メソッドを差し替えると、キャッシュなし版ではなく差し替えたプラグインが解決する', async () => {
    serve({ rotated: false });
    const resolver = newResolver();
    const custom = {
      method: () => 'web',
      resolve: async () => ({ id: WEB_DID, replaced: true }) as unknown as DIDDocument,
    };
    resolver.register(custom as unknown as Parameters<Resolver['register']>[0]);
    expect((await resolver.resolveUncached(WEB_DID)) as unknown as { replaced: boolean }).toEqual(
      expect.objectContaining({ replaced: true }),
    );
  });
});

describe('createPersonaSigningResolver: 取り込んだ DID のペルソナの署名・照合用', () => {
  it.each(
    CASES,
  )('%s: 文書が替わったら次の署名・照合の解決へ直ちに反映される', async (_name, did) => {
    const state = { rotated: false };
    serve(state);
    const signing = createPersonaSigningResolver(newResolver());

    expect(hasAssertionMethod(await signing.resolve(did))).toBe(true);
    state.rotated = true;
    expect(hasAssertionMethod(await signing.resolve(did))).toBe(false);
  });
});
