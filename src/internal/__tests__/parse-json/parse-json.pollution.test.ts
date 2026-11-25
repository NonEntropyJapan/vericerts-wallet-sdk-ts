/**
 * `JSON.parse` 境界での prototype 除去の回帰テスト。
 *
 * 代表的な応答パーサ 4 経路について、`Object.prototype` を**データ汚染・アクセサ汚染の両形式**で
 * 汚した状態で「当該メンバを持たない応答」を流し、汚染値が採用されず fail-closed になることを
 * 固定する。いずれも `parseJsonWithoutPrototype` を素の `JSON.parse` に戻すと失敗する
 * （経路ごとに mutation check 済み）。
 *
 * 対象経路:
 * 1. OID4VCI Credential Offer JSON（`auth/oid4vci/offer/oid4vci-offer.ts`、3003）
 * 2. DIF Credential Manifest 応答（`credential/manifest/parse.ts`、3031）
 * 3. did:web の DID Document 応答（`identity/web/did-web-fetch.ts`、2010）
 * 4. VP JSON のパース（`credential/presentation/vp.ts`、3002）
 *
 * これらのパーサは応答メンバを**プロトタイプ鎖で読む**（かつ検査と採用で 2 度読む）ため、
 * 読み取り側を変更せずともパース境界の対策だけで塞がることを示す位置づけでもある。
 * 非同期経路には必ず `*Async` 版フィクスチャを使う（同期版は `fn` が返す Promise の解決前に
 * 汚染を戻すためテストがトートロジーになる）。
 */

import { describe, expect, it } from 'bun:test';
import { parseCredentialOffer } from '../../auth/oid4vci/offer/oid4vci-offer.js';
import type { FetchLike } from '../../auth/oid4vci/oid4vci.js';
import { fetchCredentialManifest } from '../../credential/manifest/parse.js';
import { parseVerifiablePresentation } from '../../credential/presentation/vp.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../errors.js';
import { fetchDidWebDocument } from '../../identity/web/did-web-fetch.js';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../prototype-pollution.fixtures.js';

/** 同期処理が指定コードの `VericertsError` で失敗することを確認する。 */
function expectCode(fn: () => unknown, code: ErrorCode): void {
  let thrown: unknown;
  try {
    fn();
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(VericertsError);
  expect((thrown as VericertsError).code).toBe(code);
}

/** 非同期処理が指定コードの `VericertsError` で失敗することを確認する。 */
async function expectCodeAsync(fn: () => Promise<unknown>, code: ErrorCode): Promise<void> {
  let thrown: unknown;
  try {
    await fn();
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(VericertsError);
  expect((thrown as VericertsError).code).toBe(code);
}

// --- 1. OID4VCI Credential Offer -------------------------------------------------------------

/** `credential_issuer` を**持たない** Offer（汚染が実際に効く形）。 */
const OFFER_WITHOUT_ISSUER = JSON.stringify({ credential_configuration_ids: ['cfg-1'] });

function offerUri(json: string): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(json)}`;
}

describe('OID4VCI Credential Offer: credential_issuer の汚染', () => {
  it('データ汚染下で credential_issuer 欠落の Offer が 3003 に倒れる', async () => {
    await withPollutedPrototypeAsync(
      { credential_issuer: 'https://attacker.example' },
      async () => {
        await expectCodeAsync(
          () => parseCredentialOffer(offerUri(OFFER_WITHOUT_ISSUER)),
          ErrorCodes.OFFER_URI_PARSE_FAILED,
        );
      },
    );
  });

  it('アクセサ汚染下でも 3003 に倒れる（検査と採用の 2 度読みが食い違わない）', async () => {
    await withPollutedPrototypeAccessorAsync(
      { credential_issuer: () => 'https://attacker.example' },
      async () => {
        await expectCodeAsync(
          () => parseCredentialOffer(offerUri(OFFER_WITHOUT_ISSUER)),
          ErrorCodes.OFFER_URI_PARSE_FAILED,
        );
      },
    );
  });

  it('汚染下でも正当な Offer は従来どおりパースできる', async () => {
    const valid = JSON.stringify({
      credential_issuer: 'https://issuer.example',
      credential_configuration_ids: ['cfg-1'],
    });
    const offer = await withPollutedPrototypeAsync(
      { credential_issuer: 'https://attacker.example' },
      () => parseCredentialOffer(offerUri(valid)),
    );
    expect(offer.credential_issuer).toBe('https://issuer.example');
  });
});

// --- 2. DIF Credential Manifest ---------------------------------------------------------------

const MANIFEST_SPEC_VERSION = 'https://identity.foundation/credential-manifest/spec/v1.0.0/';
const MANIFEST_URL = 'https://issuer.example/manifest.json';

/** `issuer.id` を**持たない** Manifest（汚染が実際に効く形）。 */
const MANIFEST_WITHOUT_ISSUER_ID = JSON.stringify({
  id: 'manifest-1',
  spec_version: MANIFEST_SPEC_VERSION,
  issuer: {},
  output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
});

function manifestFetch(body: string): FetchLike {
  return () => Promise.resolve(new Response(body, { status: 200 }));
}

describe('Credential Manifest 応答: issuer.id の汚染', () => {
  it('データ汚染下で issuer.id 欠落の Manifest が 3031 に倒れる', async () => {
    await withPollutedPrototypeAsync({ id: 'https://attacker.example' }, async () => {
      await expectCodeAsync(
        () =>
          fetchCredentialManifest(MANIFEST_URL, {
            fetchImpl: manifestFetch(MANIFEST_WITHOUT_ISSUER_ID),
          }),
        ErrorCodes.MANIFEST_SCHEMA_INVALID,
      );
    });
  });

  it('アクセサ汚染下でも 3031 に倒れ、汚染値が own プロパティへ repack されない', async () => {
    await withPollutedPrototypeAccessorAsync({ id: () => 'https://attacker.example' }, async () => {
      await expectCodeAsync(
        () =>
          fetchCredentialManifest(MANIFEST_URL, {
            fetchImpl: manifestFetch(MANIFEST_WITHOUT_ISSUER_ID),
          }),
        ErrorCodes.MANIFEST_SCHEMA_INVALID,
      );
    });
  });

  it('汚染下でも正当な Manifest は従来どおり issuer.id を採用する', async () => {
    const valid = JSON.stringify({
      id: 'manifest-1',
      spec_version: MANIFEST_SPEC_VERSION,
      issuer: { id: 'https://issuer.example' },
      output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
    });
    const manifest = await withPollutedPrototypeAsync({ id: 'https://attacker.example' }, () =>
      fetchCredentialManifest(MANIFEST_URL, { fetchImpl: manifestFetch(valid) }),
    );
    expect(manifest.issuer.id).toBe('https://issuer.example');
  });
});

// --- 3. did:web の DID Document ----------------------------------------------------------------

const DID_WEB = 'did:web:issuer.example';
const DID_WEB_URL = 'https://issuer.example/.well-known/did.json';

function didWebFetch(body: string): typeof fetch {
  return (() =>
    Promise.resolve(
      new Response(body, { status: 200, headers: { 'content-type': 'application/json' } }),
    )) as unknown as typeof fetch;
}

describe('did:web の DID Document 応答: id の汚染', () => {
  it('データ汚染下で id を持たない did.json が 2010 に倒れる', async () => {
    await withPollutedPrototypeAsync({ id: DID_WEB }, async () => {
      await expectCodeAsync(
        () => fetchDidWebDocument(DID_WEB_URL, DID_WEB, didWebFetch('{}')),
        ErrorCodes.DID_DOC_INVALID,
      );
    });
  });

  it('アクセサ汚染下でも 2010 に倒れる（id の 3 度読みが食い違わない）', async () => {
    await withPollutedPrototypeAccessorAsync({ id: () => DID_WEB }, async () => {
      await expectCodeAsync(
        () => fetchDidWebDocument(DID_WEB_URL, DID_WEB, didWebFetch('{}')),
        ErrorCodes.DID_DOC_INVALID,
      );
    });
  });

  it('汚染下でも正当な did.json は従来どおり解決できる', async () => {
    const valid = JSON.stringify({
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: DID_WEB,
    });
    const result = await withPollutedPrototypeAsync({ id: 'did:web:attacker.example' }, () =>
      fetchDidWebDocument(DID_WEB_URL, DID_WEB, didWebFetch(valid)),
    );
    expect(result.document.id).toBe(DID_WEB);
  });
});

// --- 4. VP JSON ---------------------------------------------------------------------------------

/** `holder` を**持たない** VP（汚染が実際に効く形）。 */
const VP_WITHOUT_HOLDER = JSON.stringify({
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiablePresentation'],
  verifiableCredential: [],
});

describe('VP JSON のパース: holder の汚染', () => {
  it('データ汚染下で holder を持たない VP が 3002 に倒れる', () => {
    withPollutedPrototype({ holder: 'did:example:attacker' }, () => {
      expectCode(
        () => parseVerifiablePresentation(VP_WITHOUT_HOLDER),
        ErrorCodes.VC_SCHEMA_INVALID,
      );
    });
  });

  it('アクセサ汚染下でも 3002 に倒れる', () => {
    withPollutedPrototypeAccessor({ holder: () => 'did:example:attacker' }, () => {
      expectCode(
        () => parseVerifiablePresentation(VP_WITHOUT_HOLDER),
        ErrorCodes.VC_SCHEMA_INVALID,
      );
    });
  });

  it('汚染下でも正当な VP は従来どおり holder を採用する', () => {
    const valid = JSON.stringify({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: 'did:example:holder',
      verifiableCredential: [],
    });
    const vp = withPollutedPrototype({ holder: 'did:example:attacker' }, () =>
      parseVerifiablePresentation(valid),
    );
    expect(vp.holder).toBe('did:example:holder');
  });
});
