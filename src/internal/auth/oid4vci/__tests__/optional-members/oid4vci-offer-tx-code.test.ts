/**
 * Credential Offer の `tx_code` 検証（OID4VCI 1.0 §4.1.1）。
 *
 * `tx_code` オブジェクトは**存在すること自体**が「PIN 必須」の印で、`length` / `input_mode` /
 * `description` はいずれも OPTIONAL。省略形の `tx_code` を出す Issuer の Offer も受領できる一方、
 * 告知された値は型を検査し、不正なら 3003 で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { PRE_AUTHORIZED_CODE_GRANT, parseCredentialOffer } from '../../offer/oid4vci-offer.js';

/** `tx_code` を持つ pre-authorized_code Offer を値渡し URI にする。 */
function offerUriWithTxCode(txCode: unknown): string {
  const offer = {
    credential_issuer: 'https://issuer.example.com',
    credential_configuration_ids: ['a'],
    grants: { [PRE_AUTHORIZED_CODE_GRANT]: { 'pre-authorized_code': 'code-1', tx_code: txCode } },
  };
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

async function parseTxCode(txCode: unknown) {
  const offer = await parseCredentialOffer(offerUriWithTxCode(txCode));
  const grant = offer.grants?.[PRE_AUTHORIZED_CODE_GRANT];
  return { grant, txCode: grant?.tx_code };
}

describe('parseCredentialOffer — tx_code のメンバはすべて任意', () => {
  it('空オブジェクトを受理し、tx_code の存在（PIN 必須の印）を保つ', async () => {
    const { grant, txCode } = await parseTxCode({});
    expect(Object.hasOwn(grant as object, 'tx_code')).toBe(true);
    expect(txCode).toEqual({ input_mode: 'numeric' });
  });

  it('length だけの tx_code を受理し input_mode は既定の numeric になる', async () => {
    expect((await parseTxCode({ length: 6 })).txCode).toEqual({ length: 6, input_mode: 'numeric' });
  });

  it('input_mode だけの tx_code を受理する', async () => {
    expect((await parseTxCode({ input_mode: 'text' })).txCode).toEqual({ input_mode: 'text' });
  });

  it('description を保持して返す（300 文字ちょうどまで）', async () => {
    const max = 'あ'.repeat(300);
    expect((await parseTxCode({ description: 'PIN sent by SMS' })).txCode).toEqual({
      input_mode: 'numeric',
      description: 'PIN sent by SMS',
    });
    expect((await parseTxCode({ description: max })).txCode?.description).toBe(max);
  });

  it.each([
    ['length が文字列', { length: '6' }],
    ['length が 0', { length: 0 }],
    ['length が小数', { length: 6.5 }],
    ['length が null', { length: null }],
    ['input_mode が既知値以外', { input_mode: 'bogus' }],
    ['input_mode が空文字', { input_mode: '' }],
    ['input_mode が null', { input_mode: null }],
    ['description が 301 文字', { description: 'a'.repeat(301) }],
    ['description が非文字列', { description: 1 }],
    ['tx_code が配列', []],
    ['tx_code が null', null],
  ])('告知された値が不正（%s）なら 3003 で拒否する', async (_label, txCode) => {
    await expect(parseCredentialOffer(offerUriWithTxCode(txCode))).rejects.toMatchObject({
      code: ErrorCodes.OFFER_URI_PARSE_FAILED,
    });
  });
});
