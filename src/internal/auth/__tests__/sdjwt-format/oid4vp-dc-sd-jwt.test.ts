/**
 * OID4VP VP Token 構成の `dc+sd-jwt` 提示テスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - `buildVPToken` が `format: 'dc+sd-jwt'` の `SdJwtPresentationInput` を受け付け、選択的開示 +
 *   KB-JWT を構成し `verifySdJwt`（`requireKeyBinding: true`）で検証できる。
 * - 旧 `vc+sd-jwt` 提示も引き続き受理する（既存ケースは `../oid4vp.test.ts` が維持）。
 */

import { describe, expect, it } from 'bun:test';
import { createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY } from '../../../credential/sdjwt/typ.js';
import { verifySdJwt } from '../../../credential/sdjwt/verify.js';
import type { CredentialAlg } from '../../../credential/vc/jws.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { buildVPToken } from '../../oid4vp/oid4vp.js';
import type { PresentationRequest } from '../../request.js';

const HOLDER_KEY = new Uint8Array(32).fill(11);
const ISSUER_KEY = new Uint8Array(32).fill(7);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const HOLDER_SECP_JWK = toJwk(getSecp256k1PublicKey(HOLDER_KEY, false), 'secp256k1');
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const HOLDER_SECP_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256K' as CredentialAlg);
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

const CLIENT_ID = 'https://verifier.example.com';
const NONCE = 'n-0S6_WzA2Mj';
const VCT = 'https://example.com/credentials/identity';
const IAT = 1_700_000_000;

const REQUEST: PresentationRequest = {
  responseType: 'vp_token',
  clientId: CLIENT_ID,
  responseMode: 'direct_post',
  responseUri: `${CLIENT_ID}/callback`,
  nonce: NONCE,
  state: 'af0ifjsldkj',
};

/** cnf / 開示クレームを持つ SD-JWT VC を発行する（`typ` 未指定なら既定 `dc+sd-jwt`）。 */
function issueSdJwt(typ?: typeof SD_JWT_VC_TYP_LEGACY): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    issuer: 'did:example:issuer',
    cnf: { jwk: HOLDER_SECP_JWK },
    disclosureClaims: ['name', 'email'],
    claims: { name: 'Alice', email: 'alice@example.com', sub: 'did:example:holder' },
    salts: { name: 'salt-name', email: 'salt-email' },
    nowSeconds: IAT,
    ...(typ !== undefined ? { typ } : {}),
  });
}

describe('buildVPToken — dc+sd-jwt', () => {
  it('format=dc+sd-jwt の提示入力から KB-JWT 付き提示を構成し verifySdJwt で成功', () => {
    const token = buildVPToken(REQUEST, [
      {
        format: SD_JWT_VC_TYP,
        sdJwt: issueSdJwt(),
        disclosedClaims: ['name'],
        signer: HOLDER_SECP_SIGNER,
        iatSeconds: IAT,
      },
    ]) as string;

    const verified = verifySdJwt(token, {
      issuerKey: ISSUER_JWK,
      expectedVct: VCT,
      requireKeyBinding: true,
      audience: CLIENT_ID,
      nonce: NONCE,
      nowSeconds: IAT,
    });
    expect(verified.keyBindingVerified).toBe(true);
    // 開示した name のみ復元され、未開示の email は復元されない。
    expect(verified.claims.name).toBe('Alice');
    expect(verified.claims.email).toBeUndefined();
  });

  it('新旧 typ の SD-JWT を混在提示でき、どちらも SD-JWT VC 提示として構成される', () => {
    const tokens = buildVPToken(REQUEST, [
      {
        format: SD_JWT_VC_TYP,
        sdJwt: issueSdJwt(),
        disclosedClaims: ['name'],
        signer: HOLDER_SECP_SIGNER,
        iatSeconds: IAT,
      },
      {
        format: SD_JWT_VC_TYP_LEGACY,
        sdJwt: issueSdJwt(SD_JWT_VC_TYP_LEGACY),
        disclosedClaims: ['name'],
        signer: HOLDER_SECP_SIGNER,
        iatSeconds: IAT,
      },
    ]) as string[];

    expect(tokens).toHaveLength(2);
    for (const token of tokens) {
      // KB-JWT が付与されている（末尾 `~` 終端ではない）。
      expect(token.endsWith('~')).toBe(false);
      const verified = verifySdJwt(token, {
        issuerKey: ISSUER_JWK,
        expectedVct: VCT,
        requireKeyBinding: true,
        audience: CLIENT_ID,
        nonce: NONCE,
        nowSeconds: IAT,
      });
      expect(verified.keyBindingVerified).toBe(true);
      expect(verified.claims.name).toBe('Alice');
    }
  });
});
