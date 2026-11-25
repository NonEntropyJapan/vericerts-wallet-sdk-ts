/**
 * `buildVPToken` / `buildVPTokenTemplate` が提示入力（`input`）の `format` / `sdJwt` / `signer` を
 * プロトタイプ鎖から読まないことの回帰テスト。
 *
 * これら 3 つは **署名済み KB-JWT / JWT-VP** の中身と署名鍵そのものを決める。鎖読みだと、その
 * フィールドを持たない不正・省略入力でも `Object.prototype` の汚染値が採用され、攻撃者の
 * SD-JWT VC が提示部に載る / 攻撃者の鍵で署名される（`format` 汚染は提示経路の選択自体を奪う）。
 */

import { describe, expect, it } from 'bun:test';
import { verifyPresentation } from '../../../credential/presentation/presentation.js';
import { createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { verifySdJwt } from '../../../credential/sdjwt/verify.js';
import type { CredentialAlg } from '../../../credential/vc/jws.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  buildVPToken,
  buildVPTokenTemplate,
  type PresentationInput,
  type SdJwtTemplateInput,
} from '../../oid4vp/oid4vp.js';
import type { PresentationRequest } from '../../request.js';

const HOLDER_KEY = new Uint8Array(32).fill(11);
const ISSUER_KEY = new Uint8Array(32).fill(7);
const ATTACKER_KEY = new Uint8Array(32).fill(9);

const CLIENT_ID = 'https://verifier.example.com';
const NONCE = 'n-0S6_WzA2Mj';
const HOLDER_DID = 'did:example:holder';
const VCT = 'https://example.com/credentials/identity';
const IAT = 1_700_000_000;
const KB_ALG = 'ES256K' as CredentialAlg;

const HOLDER_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256');
const HOLDER_KB_SIGNER = createPrivateKeySigner(HOLDER_KEY, KB_ALG);
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

const REQUEST: PresentationRequest = {
  responseType: 'vp_token',
  clientId: CLIENT_ID,
  responseMode: 'direct_post',
  responseUri: `${CLIENT_ID}/callback`,
  nonce: NONCE,
  state: 'af0ifjsldkj',
};

/** cnf = Holder 公開鍵の SD-JWT VC を発行する（正規 Issuer / 攻撃者を撃ち分ける）。 */
function issueSdJwt(issuer: CredentialSigner, name: string): string {
  return createSdJwt(issuer, {
    vct: VCT,
    issuer: 'did:example:issuer',
    cnf: { jwk: HOLDER_KB_SIGNER.publicKeyJwk },
    disclosureClaims: ['name'],
    claims: { name },
    salts: { name: 'salt-name' },
    nowSeconds: IAT,
  });
}

const HOLDER_SD_JWT = issueSdJwt(ISSUER_SIGNER, 'Alice');
const ATTACKER_SD_JWT = issueSdJwt(createPrivateKeySigner(ATTACKER_KEY, 'ES256'), 'Mallory');

/** 攻撃者鍵の signer。汚染値で署名されていないことを確かめるため `sign` を数える。 */
function attackerSigner(alg: CredentialAlg): {
  signer: CredentialSigner;
  signCount: () => number;
} {
  const inner = createPrivateKeySigner(ATTACKER_KEY, alg);
  let count = 0;
  const signer: CredentialSigner = {
    alg: inner.alg,
    publicKeyJwk: inner.publicKeyJwk,
    sign: (signingInput: Uint8Array): Uint8Array => {
      count += 1;
      return inner.sign(signingInput);
    },
  };
  return { signer, signCount: () => count };
}

/** `Object.prototype` を汚染して `run` を実行し、必ず元へ戻す。 */
function withPollution(values: Readonly<Record<string, unknown>>, run: () => void): void {
  const polluted = Object.prototype as unknown as Record<string, unknown>;
  Object.assign(polluted, values);
  try {
    run();
  } finally {
    for (const key of Object.keys(values)) {
      delete polluted[key];
    }
  }
}

describe('buildVPToken / buildVPTokenTemplate — 提示入力を prototype 鎖から読まない', () => {
  it('format を自身に持たない入力は Object.prototype.format 汚染下でも SD-JWT 経路にならない', () => {
    // 鎖読みだと汚染値で SD-JWT 提示が成立する。own 限定なら jwt_vc_json 経路として
    // 構造検証（`holder` 不在）で 3002 になる。
    const input = {
      sdJwt: HOLDER_SD_JWT,
      disclosedClaims: ['name'],
      signer: HOLDER_KB_SIGNER,
    } as unknown as PresentationInput;

    withPollution({ format: 'dc+sd-jwt' }, () => {
      expect(() => buildVPToken(REQUEST, [input])).toThrow(
        new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
      );
    });
  });

  it('SD-JWT 経路は Object.prototype.sdJwt の汚染値を提示部に使わない', () => {
    const input = {
      format: 'dc+sd-jwt',
      disclosedClaims: ['name'],
      signer: HOLDER_KB_SIGNER,
    } as unknown as PresentationInput;

    withPollution({ sdJwt: ATTACKER_SD_JWT }, () => {
      expect(() => buildVPToken(REQUEST, [input])).toThrow();
    });
  });

  it('buildVPTokenTemplate は Object.prototype.sdJwt の汚染値を提示部に使わない', () => {
    const input = {
      format: 'dc+sd-jwt',
      disclosedClaims: ['name'],
      alg: KB_ALG,
      iatSeconds: IAT,
    } as unknown as SdJwtTemplateInput;

    withPollution({ sdJwt: ATTACKER_SD_JWT }, () => {
      expect(() => buildVPTokenTemplate(REQUEST, input)).toThrow();
    });
  });

  it('SD-JWT 経路は Object.prototype.signer の汚染鍵に KB-JWT を署名させない', () => {
    const attacker = attackerSigner(KB_ALG);
    const input = {
      format: 'dc+sd-jwt',
      sdJwt: HOLDER_SD_JWT,
      disclosedClaims: ['name'],
    } as unknown as PresentationInput;

    withPollution({ signer: attacker.signer }, () => {
      expect(() => buildVPToken(REQUEST, [input])).toThrow();
    });
    expect(attacker.signCount()).toBe(0);
  });

  it('jwt_vc_json 経路は Object.prototype.signer の汚染鍵に JWT-VP を署名させない', () => {
    const attacker = attackerSigner('ES256');
    const input = {
      format: 'jwt_vc_json',
      holder: HOLDER_DID,
      verifiableCredentials: ['eyJhbGciOiJFUzI1NiJ9.vc.sig'],
    } as unknown as PresentationInput;

    withPollution({ signer: attacker.signer }, () => {
      expect(() => buildVPToken(REQUEST, [input])).toThrow();
    });
    expect(attacker.signCount()).toBe(0);
  });
});

describe('buildVPToken / buildVPTokenTemplate — 汚染下でも自身のプロパティは従来どおり使う', () => {
  it('SD-JWT 経路: 明示した sdJwt / signer で KB-JWT を構成する（後方互換）', () => {
    const attacker = attackerSigner(KB_ALG);
    let token = '';
    withPollution(
      { format: 'jwt_vc_json', sdJwt: ATTACKER_SD_JWT, signer: attacker.signer },
      () => {
        token = buildVPToken(REQUEST, [
          {
            format: 'dc+sd-jwt',
            sdJwt: HOLDER_SD_JWT,
            disclosedClaims: ['name'],
            signer: HOLDER_KB_SIGNER,
            iatSeconds: IAT,
          },
        ]) as string;
      },
    );

    const verified = verifySdJwt(token, {
      issuerKey: ISSUER_SIGNER.publicKeyJwk,
      expectedVct: VCT,
      requireKeyBinding: true,
      audience: CLIENT_ID,
      nonce: NONCE,
      nowSeconds: IAT,
    });
    expect(verified.keyBindingVerified).toBe(true);
    expect(verified.claims.name).toBe('Alice');
    expect(attacker.signCount()).toBe(0);
  });

  it('jwt_vc_json 経路: 明示した signer で JWT-VP を署名する（後方互換）', () => {
    const attacker = attackerSigner('ES256');
    let token = '';
    // `format` は汚染しない。`@noble/curves` の `p256.sign` が署名オプションの `format` を鎖読み
    // するため、本経路と無関係な理由で署名が失敗する（`format` の own 判定は SD-JWT 経路の
    // ケースで検証済み）。
    withPollution({ sdJwt: ATTACKER_SD_JWT, signer: attacker.signer }, () => {
      token = buildVPToken(REQUEST, [
        {
          format: 'jwt_vc_json',
          holder: HOLDER_DID,
          verifiableCredentials: ['eyJhbGciOiJFUzI1NiJ9.vc.sig'],
          signer: HOLDER_SIGNER,
        },
      ]) as string;
    });

    const verified = verifyPresentation(token, {
      key: { publicKeyJwk: HOLDER_SIGNER.publicKeyJwk },
      expectedAudience: CLIENT_ID,
      expectedNonce: NONCE,
    });
    expect(verified.payload.iss).toBe(HOLDER_DID);
    expect(attacker.signCount()).toBe(0);
  });

  it('buildVPTokenTemplate: 明示した sdJwt の提示部でテンプレートを組む（後方互換）', () => {
    let presentation = '';
    withPollution({ sdJwt: ATTACKER_SD_JWT }, () => {
      presentation = buildVPTokenTemplate(REQUEST, {
        format: 'dc+sd-jwt',
        sdJwt: HOLDER_SD_JWT,
        disclosedClaims: ['name'],
        alg: KB_ALG,
        iatSeconds: IAT,
      }).presentation;
    });

    const issuerJwtOf = (sdJwt: string): string => sdJwt.split('~')[0] as string;
    expect(presentation.startsWith(issuerJwtOf(HOLDER_SD_JWT))).toBe(true);
    expect(presentation.startsWith(issuerJwtOf(ATTACKER_SD_JWT))).toBe(false);
  });
});
