/**
 * `buildVPTokenTemplate` が prototype 継承の `kid` を KB-JWT ヘッダへ載せないことの回帰テスト
 * （`remote-signer.ts` / `addKeyBinding` と同一のバグ）。
 *
 * `SdJwtTemplateInput.kid` は任意プロパティのため、`input.kid !== undefined` はプロトタイプ鎖を
 * 辿る。`kid` を省略した正当な呼び出しでも `Object.prototype.kid` の汚染値を拾い、それを
 * `KeyBindingTemplateOptions` の**自身のプロパティ**として引き渡すため、下流 `buildJwsHeader`
 * （`vc/signer.ts`）の `Object.hasOwn` ガードが素通りして攻撃者の鍵 ID が KB-JWT ヘッダに載る。
 */

import { describe, expect, it } from 'bun:test';
import { createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import type { CredentialAlg } from '../../../credential/vc/jws.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../../credential/vc/signer.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { buildVPTokenTemplate } from '../../oid4vp/oid4vp.js';
import type { PresentationRequest } from '../../request.js';

/** 攻撃者が `Object.prototype` 経由で載せようとする鍵 ID。 */
const ATTACKER_KID = 'did:web:attacker.example#key-1';

const SESSION_KEY = new Uint8Array(32).fill(11);
const ISSUER_KEY = new Uint8Array(32).fill(7);
const CLIENT_ID = 'https://verifier.example';
const NONCE = 'nonce-proto-1';
const IAT = 1_767_225_600;
const VCT = 'https://example.com/vct/person';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const SESSION_ALG = 'ES256K' as CredentialAlg;
const SESSION_JWK = toJwk(getSecp256k1PublicKey(SESSION_KEY, false), 'secp256k1');
const ISSUER_SIGNER: CredentialSigner = createPrivateKeySigner(ISSUER_KEY, 'ES256');

/** パース済み OID4VP Authorization Request。 */
const REQUEST: PresentationRequest = {
  clientId: CLIENT_ID,
  responseType: 'vp_token',
  responseMode: 'direct_post',
  responseUri: `${CLIENT_ID}/callback`,
  nonce: NONCE,
  state: 'state-1',
};

/** Holder Service に保管される SD-JWT VC（cnf = Agent Session 公開鍵）。 */
function issueSdJwt(): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    issuer: 'did:example:issuer',
    cnf: { jwk: SESSION_JWK },
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
  });
}

describe('buildVPTokenTemplate: prototype 継承の kid を KB-JWT ヘッダへ載せない', () => {
  it('Object.prototype 汚染下でも kid 省略時のヘッダは alg / typ だけ', () => {
    const polluted = Object.prototype as unknown as Record<string, unknown>;
    polluted.kid = ATTACKER_KID;
    try {
      const template = buildVPTokenTemplate(REQUEST, {
        format: 'vc+sd-jwt',
        sdJwt: issueSdJwt(),
        disclosedClaims: ['name'],
        alg: SESSION_ALG,
        iatSeconds: IAT,
      });
      // 汚染が効くと header に kid: did:web:attacker.example#key-1 が入る。
      expect(template.header).toEqual({ alg: SESSION_ALG, typ: 'kb+jwt' });
      expect(Object.hasOwn(template.header, 'kid')).toBe(false);
    } finally {
      delete polluted.kid;
    }
  });

  it('自身のプロパティの kid は従来どおりヘッダへ載る（後方互換）', () => {
    const kid = 'did:example:agent#session-1';
    const template = buildVPTokenTemplate(REQUEST, {
      format: 'vc+sd-jwt',
      sdJwt: issueSdJwt(),
      disclosedClaims: ['name'],
      alg: SESSION_ALG,
      kid,
      iatSeconds: IAT,
    });
    expect(template.header).toEqual({ alg: SESSION_ALG, kid, typ: 'kb+jwt' });
  });
});
