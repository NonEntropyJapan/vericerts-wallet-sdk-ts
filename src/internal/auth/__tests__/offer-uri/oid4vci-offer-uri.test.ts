/**
 * parseCredentialOffer の URI 検査を、その検査単独で落ちる入力で固定する。
 *
 * 入力を `{}` にすると、スキーム検査・排他検査を外しても「Offer として構造不正」という別理由で
 * 同じ 3003 になり検査自体を pin できない。ここでは常に**有効な Offer** を使い、検査対象の
 * 1 点だけを壊す。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { parseCredentialOffer } from '../../oid4vci/offer/oid4vci-offer.js';

const originalFetch = globalThis.fetch;
const VALID_OFFER = {
  credential_issuer: 'https://issuer.example.com',
  credential_configuration_ids: ['UniversityDegree'],
};
const VALID_OFFER_JSON = encodeURIComponent(JSON.stringify(VALID_OFFER));

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function stubFetchCounting(): { calls: () => number } {
  let calls = 0;
  globalThis.fetch = (async () => {
    calls += 1;
    return new Response(JSON.stringify(VALID_OFFER), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as unknown as typeof fetch;
  return { calls: () => calls };
}

describe('parseCredentialOffer — URI 検査（有効な Offer での 3003）', () => {
  it('有効な Offer でも、スキームが openid-credential-offer 以外なら拒否する', async () => {
    for (const scheme of ['https', 'http', 'javascript', 'data']) {
      await expect(
        parseCredentialOffer(
          `${scheme}://issuer.example.com/?credential_offer=${VALID_OFFER_JSON}`,
        ),
      ).rejects.toMatchObject({ code: ErrorCodes.OFFER_URI_PARSE_FAILED });
    }
  });

  it('有効な credential_offer と credential_offer_uri の併記は取得せず拒否する', async () => {
    const fetched = stubFetchCounting();
    const uri = `openid-credential-offer://?credential_offer=${VALID_OFFER_JSON}&credential_offer_uri=https://issuer.example.com/offers/1`;
    await expect(parseCredentialOffer(uri)).rejects.toMatchObject({
      code: ErrorCodes.OFFER_URI_PARSE_FAILED,
    });
    expect(fetched.calls()).toBe(0);
  });

  it('credential_issuer が空文字の Offer は拒否する', async () => {
    const offer = encodeURIComponent(JSON.stringify({ ...VALID_OFFER, credential_issuer: '' }));
    await expect(
      parseCredentialOffer(`openid-credential-offer://?credential_offer=${offer}`),
    ).rejects.toMatchObject({ code: ErrorCodes.OFFER_URI_PARSE_FAILED });
  });

  it('有効な Offer 単独（スキーム正・併記なし）は受理する（対照）', async () => {
    const offer = await parseCredentialOffer(
      `openid-credential-offer://?credential_offer=${VALID_OFFER_JSON}`,
    );
    expect(offer.credential_issuer).toBe('https://issuer.example.com');
  });
});
