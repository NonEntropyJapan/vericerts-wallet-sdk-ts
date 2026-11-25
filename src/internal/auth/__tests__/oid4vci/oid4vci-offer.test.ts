/**
 * parseCredentialOffer の OID4VCI Credential Offer 解析検証。
 *
 * 値渡し（credential_offer）・参照渡し（credential_offer_uri、fetch モック）・不正 URI /
 * JSON / 構造の拒否・取得失敗のエラーコード粒度（3003 / 3004）を確認する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import {
  type CredentialOffer,
  PRE_AUTHORIZED_CODE_GRANT,
  parseCredentialOffer,
} from '../../oid4vci/offer/oid4vci-offer.js';

/** parseCredentialOffer の reject が指定コードの VericertsError であることを検証する。 */
async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
}

const SAMPLE_OFFER: CredentialOffer = {
  credential_issuer: 'https://issuer.example.com',
  credential_configuration_ids: ['UniversityDegree_jwt'],
  grants: {
    [PRE_AUTHORIZED_CODE_GRANT]: {
      'pre-authorized_code': 'abc123',
      tx_code: { length: 6, input_mode: 'numeric' },
    },
  },
};

/** Offer JSON を値渡し URI に組み立てる。 */
function inlineUri(offer: unknown): string {
  const json = encodeURIComponent(JSON.stringify(offer));
  return `openid-credential-offer://?credential_offer=${json}`;
}

/** fetch をモックに差し替えるヘルパー。 */
function mockFetch(handler: (input: URL | string) => Response | Promise<Response>): void {
  // biome-ignore lint/suspicious/noExplicitAny: テスト用に globalThis.fetch を差し替える。
  (globalThis as any).fetch = (input: URL | string) => Promise.resolve(handler(input));
}

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('parseCredentialOffer — 値渡し（credential_offer）', () => {
  it('完全な Offer をパースして正規化する', async () => {
    const offer = await parseCredentialOffer(inlineUri(SAMPLE_OFFER));
    expect(offer.credential_issuer).toBe('https://issuer.example.com');
    expect(offer.credential_configuration_ids).toEqual(['UniversityDegree_jwt']);
    expect(offer.grants?.[PRE_AUTHORIZED_CODE_GRANT]?.['pre-authorized_code']).toBe('abc123');
    expect(offer.grants?.[PRE_AUTHORIZED_CODE_GRANT]?.tx_code).toEqual({
      length: 6,
      input_mode: 'numeric',
    });
  });

  it('grants 省略でもパースできる', async () => {
    const offer = await parseCredentialOffer(
      inlineUri({
        credential_issuer: 'https://issuer.example.com',
        credential_configuration_ids: ['a', 'b'],
      }),
    );
    expect(offer.credential_configuration_ids).toEqual(['a', 'b']);
    expect(offer.grants).toBeUndefined();
  });

  it('tx_code 省略の pre-authorized_code grant をパースできる', async () => {
    const offer = await parseCredentialOffer(
      inlineUri({
        credential_issuer: 'https://issuer.example.com',
        credential_configuration_ids: ['a'],
        grants: { [PRE_AUTHORIZED_CODE_GRANT]: { 'pre-authorized_code': 'code-1' } },
      }),
    );
    expect(offer.grants?.[PRE_AUTHORIZED_CODE_GRANT]?.['pre-authorized_code']).toBe('code-1');
    expect(offer.grants?.[PRE_AUTHORIZED_CODE_GRANT]?.tx_code).toBeUndefined();
  });
});

describe('parseCredentialOffer — 参照渡し（credential_offer_uri）', () => {
  it('HTTPS 取得して JSON をパースする', async () => {
    let requested: string | undefined;
    mockFetch((input) => {
      requested = input.toString();
      return new Response(JSON.stringify(SAMPLE_OFFER), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    const uri =
      'openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/123';
    const offer = await parseCredentialOffer(uri);
    expect(requested).toBe('https://issuer.example.com/offers/123');
    expect(offer.credential_issuer).toBe('https://issuer.example.com');
  });

  it('非 HTTPS の offer_uri は通信失敗（3004）で拒否する', async () => {
    const uri =
      'openid-credential-offer://?credential_offer_uri=http://issuer.example.com/offers/123';
    await expectRejectCode(parseCredentialOffer(uri), ErrorCodes.ISSUER_COMMUNICATION_FAILED);
  });

  it('HTTP 4xx は通信失敗（3004）で拒否する', async () => {
    mockFetch(() => new Response('not found', { status: 404 }));
    const uri =
      'openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/x';
    await expectRejectCode(parseCredentialOffer(uri), ErrorCodes.ISSUER_COMMUNICATION_FAILED);
  });

  it('Content-Type 不一致は通信失敗（3004）で拒否する', async () => {
    mockFetch(
      () =>
        new Response(JSON.stringify(SAMPLE_OFFER), {
          status: 200,
          headers: { 'content-type': 'text/html' },
        }),
    );
    const uri =
      'openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/x';
    await expectRejectCode(parseCredentialOffer(uri), ErrorCodes.ISSUER_COMMUNICATION_FAILED);
  });

  it('Content-Type ヘッダ欠落は通信失敗（3004）で拒否する', async () => {
    // 共有述語（`http/body-limit.ts`）の既定は fail-closed で、欠落を許容するのは
    // `allowMissing` を明示する OpenID Federation 経路だけである。
    mockFetch(() => new Response(JSON.stringify(SAMPLE_OFFER), { status: 200 }));
    const uri =
      'openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/x';
    await expectRejectCode(parseCredentialOffer(uri), ErrorCodes.ISSUER_COMMUNICATION_FAILED);
  });

  it('credential_offer_uri が内部 / ループバックホストなら取得前に拒否する', async () => {
    let called = false;
    mockFetch(() => {
      called = true;
      return new Response(JSON.stringify(SAMPLE_OFFER), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    for (const host of ['10.0.0.5', '169.254.169.254', 'localhost', '[::1]']) {
      const uri = `openid-credential-offer://?credential_offer_uri=https://${host}/offers/x`;
      await expectRejectCode(parseCredentialOffer(uri), ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    expect(called).toBe(false);
  });

  it('公開ホストから内部ホストへのリダイレクトは追従せず、内部ホストへ GET しない', async () => {
    const requested: string[] = [];
    mockFetch((input) => {
      requested.push(String(input));
      return new Response(null, { status: 302, headers: { Location: 'https://10.0.0.5/offer' } });
    });
    const uri =
      'openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/x';
    await expectRejectCode(parseCredentialOffer(uri), ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    expect(requested).toEqual(['https://issuer.example.com/offers/x']);
  });

  it('非 HTTPS へのリダイレクト後は通信失敗（3004）で拒否する', async () => {
    mockFetch(() => {
      const res = new Response(JSON.stringify(SAMPLE_OFFER), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
      Object.defineProperty(res, 'url', { value: 'http://evil.example.com/offer' });
      return res;
    });
    const uri =
      'openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/x';
    await expectRejectCode(parseCredentialOffer(uri), ErrorCodes.ISSUER_COMMUNICATION_FAILED);
  });

  it('ネットワークエラーは通信失敗（3004）で拒否する', async () => {
    // biome-ignore lint/suspicious/noExplicitAny: テスト用に reject する fetch を差し替える。
    (globalThis as any).fetch = () => Promise.reject(new Error('network down'));
    const uri =
      'openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/x';
    await expectRejectCode(parseCredentialOffer(uri), ErrorCodes.ISSUER_COMMUNICATION_FAILED);
  });

  it('取得本文が不正 JSON ならパース失敗（3003）で拒否する', async () => {
    mockFetch(
      () =>
        new Response('{not json', {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    const uri =
      'openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/x';
    await expectRejectCode(parseCredentialOffer(uri), ErrorCodes.OFFER_URI_PARSE_FAILED);
  });
});

// スキーム検査・inline/uri 排他検査・`credential_issuer` 空文字の検査は、検査単独で落ちる入力（有効な Offer）で
// `offer-uri/oid4vci-offer-uri.test.ts` に固定している。
describe('parseCredentialOffer — 不正 URI の拒否（3003）', () => {
  it('URL として解析不能なら拒否する', async () => {
    await expectRejectCode(parseCredentialOffer('not a uri'), ErrorCodes.OFFER_URI_PARSE_FAILED);
  });

  it('credential_offer / credential_offer_uri がどちらも無ければ拒否する', async () => {
    await expectRejectCode(
      parseCredentialOffer('openid-credential-offer://?foo=bar'),
      ErrorCodes.OFFER_URI_PARSE_FAILED,
    );
  });
});

describe('parseCredentialOffer — 不正な Offer 構造の拒否（3003）', () => {
  it('credential_offer が不正 JSON なら拒否する', async () => {
    const uri = `openid-credential-offer://?credential_offer=${encodeURIComponent('{bad')}`;
    await expectRejectCode(parseCredentialOffer(uri), ErrorCodes.OFFER_URI_PARSE_FAILED);
  });

  it('credential_issuer 欠落を拒否する', async () => {
    await expectRejectCode(
      parseCredentialOffer(inlineUri({ credential_configuration_ids: ['a'] })),
      ErrorCodes.OFFER_URI_PARSE_FAILED,
    );
  });

  it('credential_configuration_ids 空配列を拒否する', async () => {
    await expectRejectCode(
      parseCredentialOffer(
        inlineUri({ credential_issuer: 'https://i.example.com', credential_configuration_ids: [] }),
      ),
      ErrorCodes.OFFER_URI_PARSE_FAILED,
    );
  });

  it('credential_configuration_ids に非文字列要素があれば拒否する', async () => {
    await expectRejectCode(
      parseCredentialOffer(
        inlineUri({
          credential_issuer: 'https://i.example.com',
          credential_configuration_ids: ['a', 1],
        }),
      ),
      ErrorCodes.OFFER_URI_PARSE_FAILED,
    );
  });

  it('配列やプリミティブの Offer を拒否する', async () => {
    await expectRejectCode(
      parseCredentialOffer(inlineUri([1, 2, 3])),
      ErrorCodes.OFFER_URI_PARSE_FAILED,
    );
  });

  it('pre-authorized_code が空文字なら拒否する', async () => {
    await expectRejectCode(
      parseCredentialOffer(
        inlineUri({
          credential_issuer: 'https://i.example.com',
          credential_configuration_ids: ['a'],
          grants: { [PRE_AUTHORIZED_CODE_GRANT]: { 'pre-authorized_code': '' } },
        }),
      ),
      ErrorCodes.OFFER_URI_PARSE_FAILED,
    );
  });

  it('tx_code.length が非正なら拒否する', async () => {
    await expectRejectCode(
      parseCredentialOffer(
        inlineUri({
          credential_issuer: 'https://i.example.com',
          credential_configuration_ids: ['a'],
          grants: {
            [PRE_AUTHORIZED_CODE_GRANT]: {
              'pre-authorized_code': 'c',
              tx_code: { length: 0, input_mode: 'numeric' },
            },
          },
        }),
      ),
      ErrorCodes.OFFER_URI_PARSE_FAILED,
    );
  });
});
