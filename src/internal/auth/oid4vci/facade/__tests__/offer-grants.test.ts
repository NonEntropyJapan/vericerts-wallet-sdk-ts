/**
 * Credential Offer の `authorization_code` grant のパース。
 *
 * ファサード `receiveCredential` が grant を振り分ける前提として、`CredentialGrants` が
 * `authorization_code` を**モデル化していること**を固定する（従来は pre-authorized_code だけを
 * 持ち、authorization_code の Offer は grant を告知していても `{}` にしか見えなかった）。
 * 本テストは facade の入力側の検証なので facade の `__tests__` に置く。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import {
  AUTHORIZATION_CODE_GRANT,
  PRE_AUTHORIZED_CODE_GRANT,
  parseCredentialOffer,
} from '../../offer/oid4vci-offer.js';
import { buildOfferURI, CONFIGURATION_ID, ISSUER } from './facade-fixtures.js';

/** grants だけを差し替えた Offer URI。 */
function offerWithGrants(grants: unknown): string {
  return buildOfferURI({
    credential_issuer: ISSUER,
    credential_configuration_ids: [CONFIGURATION_ID],
    grants,
  });
}

describe('authorization_code grant のパース', () => {
  it('メンバが無くても grant として認識される（必須メンバは無い）', async () => {
    const offer = await parseCredentialOffer(offerWithGrants({ authorization_code: {} }));
    expect(Object.hasOwn(offer.grants ?? {}, AUTHORIZATION_CODE_GRANT)).toBe(true);
  });

  it('issuer_state / authorization_server を読み出す', async () => {
    const offer = await parseCredentialOffer(
      offerWithGrants({
        authorization_code: {
          issuer_state: 'issuer-state-abc',
          authorization_server: 'https://as.example.eu',
        },
      }),
    );
    expect(offer.grants?.[AUTHORIZATION_CODE_GRANT]).toEqual({
      issuer_state: 'issuer-state-abc',
      authorization_server: 'https://as.example.eu',
    });
  });

  it('告知されていないメンバはキーを生やさない（Object.hasOwn の判定と食い違わせない）', async () => {
    const offer = await parseCredentialOffer(
      offerWithGrants({ authorization_code: { issuer_state: 'abc' } }),
    );
    const grant = offer.grants?.[AUTHORIZATION_CODE_GRANT];
    expect(Object.hasOwn(grant ?? {}, 'authorization_server')).toBe(false);
  });

  it('空文字の issuer_state は 3003 で拒否する', async () => {
    await expect(
      parseCredentialOffer(offerWithGrants({ authorization_code: { issuer_state: '' } })),
    ).rejects.toMatchObject({ code: ErrorCodes.OFFER_URI_PARSE_FAILED });
  });

  it('空文字の authorization_server は 3003 で拒否する（well-known URL が相対パスに化ける）', async () => {
    await expect(
      parseCredentialOffer(offerWithGrants({ authorization_code: { authorization_server: '' } })),
    ).rejects.toMatchObject({ code: ErrorCodes.OFFER_URI_PARSE_FAILED });
  });

  it('配列の authorization_code は 3003 で拒否する', async () => {
    await expect(
      parseCredentialOffer(offerWithGrants({ authorization_code: [] })),
    ).rejects.toMatchObject({ code: ErrorCodes.OFFER_URI_PARSE_FAILED });
  });

  it('両方の grant を告知する Offer は両方のキーを持つ', async () => {
    const offer = await parseCredentialOffer(
      offerWithGrants({
        authorization_code: { issuer_state: 'abc' },
        [PRE_AUTHORIZED_CODE_GRANT]: { 'pre-authorized_code': 'code-1' },
      }),
    );
    expect(Object.hasOwn(offer.grants ?? {}, AUTHORIZATION_CODE_GRANT)).toBe(true);
    expect(Object.hasOwn(offer.grants ?? {}, PRE_AUTHORIZED_CODE_GRANT)).toBe(true);
  });

  it('pre-authorized_code だけの Offer に authorization_code のキーは生えない', async () => {
    const offer = await parseCredentialOffer(
      offerWithGrants({ [PRE_AUTHORIZED_CODE_GRANT]: { 'pre-authorized_code': 'code-1' } }),
    );
    expect(Object.hasOwn(offer.grants ?? {}, AUTHORIZATION_CODE_GRANT)).toBe(false);
  });
});
