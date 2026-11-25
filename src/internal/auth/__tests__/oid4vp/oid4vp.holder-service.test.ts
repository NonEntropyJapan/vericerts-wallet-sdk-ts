/**
 * 分離型 Holder Service（Agent Holder）向け `buildVPTokenTemplate` のユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - Holder Service は VC バイト列だけを保持し、Agent Session 秘密鍵を受け取らずにテンプレートを返せる。
 * - `nonce` / `aud` がパース済みリクエストから導出され、KB-JWT に束縛される。
 * - 外部署名を合成した結果が `buildVPToken`（統合構成）と同一の VP Token 要素になる。
 * - 別リクエスト向けテンプレートで署名された KB-JWT の流用を `sd_hash` 不一致で拒否する。
 * - `kid` 付き署名鍵でも統合構成と分離構成のバイト列同値が保たれる。
 */

import { describe, expect, it } from 'bun:test';
import {
  attachKeyBinding,
  attachKeyBindingSignature,
} from '../../../credential/sdjwt/key-binding.js';
import { createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { verifySdJwt } from '../../../credential/sdjwt/verify.js';
import type { CredentialAlg } from '../../../credential/vc/jws.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { buildVPToken, buildVPTokenTemplate } from '../../oid4vp/oid4vp.js';
import type { PresentationRequest } from '../../request.js';

/** Agent Session 鍵。Holder Service には渡らない前提。 */
const SESSION_KEY = new Uint8Array(32).fill(11);
const ISSUER_KEY = new Uint8Array(32).fill(7);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const SESSION_ALG = 'ES256K' as CredentialAlg;
const SESSION_JWK = toJwk(getSecp256k1PublicKey(SESSION_KEY, false), 'secp256k1');
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');

const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const SESSION_SIGNER = createPrivateKeySigner(SESSION_KEY, SESSION_ALG);

const AGENT_DID = 'did:example:agent';
const CLIENT_ID = 'https://verifier.example.com';
const NONCE = 'n-0S6_WzA2Mj';
const STATE = 'af0ifjsldkj';
const VCT = 'https://example.com/credentials/identity';
const IAT = 1_700_000_000;

/** テスト用の最小 PresentationRequest。 */
function sampleRequest(overrides: Partial<PresentationRequest> = {}): PresentationRequest {
  return {
    responseType: 'vp_token',
    clientId: CLIENT_ID,
    responseMode: 'direct_post',
    responseUri: `${CLIENT_ID}/callback`,
    nonce: NONCE,
    state: STATE,
    ...overrides,
  };
}

/** Holder Service に保管される SD-JWT VC（cnf = Agent Session 公開鍵）。 */
function issueSdJwt(): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    issuer: 'did:example:issuer',
    cnf: { jwk: SESSION_JWK },
    disclosureClaims: ['name', 'email'],
    claims: { name: 'Alice', email: 'alice@example.com', sub: AGENT_DID },
    salts: { name: 'salt-name', email: 'salt-email' },
  });
}

/** Agent Session 側の署名。`signingInput` だけを受け取り VC バイト列には触れない。 */
function signAsSession(signingInput: string): Uint8Array {
  return SESSION_SIGNER.sign(new TextEncoder().encode(signingInput));
}

describe('buildVPTokenTemplate — 分離型 Holder Service', () => {
  it('秘密鍵を渡さずにテンプレートを生成し、nonce / aud をリクエストから束縛する', () => {
    const request = sampleRequest();
    const template = buildVPTokenTemplate(request, {
      format: 'vc+sd-jwt',
      sdJwt: issueSdJwt(),
      disclosedClaims: ['name'],
      alg: SESSION_ALG,
      iatSeconds: IAT,
    });

    expect(template.header).toEqual({ alg: SESSION_ALG, typ: 'kb+jwt' });
    // nonce / aud はリクエストから導出される（呼び出し側が取り違えて渡す余地が無い）。
    expect(template.payload.nonce).toBe(NONCE);
    expect(template.payload.aud).toBe(CLIENT_ID);
    expect(template.payload.iat).toBe(IAT);
    expect(template.presentation.endsWith('~')).toBe(true);
    // 署名前なので 2 セグメントのみ。
    expect(template.signingInput.split('.')).toHaveLength(2);
  });

  it('外部署名を合成した VP Token が検証を通り、未開示クレームは漏れない', () => {
    const request = sampleRequest();
    // --- Holder Service 側 ---
    const template = buildVPTokenTemplate(request, {
      format: 'vc+sd-jwt',
      sdJwt: issueSdJwt(),
      disclosedClaims: ['name'],
      alg: SESSION_ALG,
      iatSeconds: IAT,
    });
    // --- Agent Session 側（秘密鍵はここだけ）---
    const signature = signAsSession(template.signingInput);
    // --- Holder Service 側: 合成 ---
    const vpTokenEntry = attachKeyBindingSignature(template, signature);

    const result = verifySdJwt(vpTokenEntry, {
      issuerKey: ISSUER_JWK,
      expectedVct: VCT,
      audience: CLIENT_ID,
      nonce: NONCE,
      requireKeyBinding: true,
    });
    expect(result.keyBindingVerified).toBe(true);
    expect(result.claims.name).toBe('Alice');
    expect(result.claims.email).toBeUndefined();
  });

  it('統合構成の buildVPToken と同一の VP Token 要素を生成する（整合性）', () => {
    const request = sampleRequest();
    const sdJwt = issueSdJwt();

    const integrated = buildVPToken(request, [
      {
        format: 'vc+sd-jwt',
        sdJwt,
        disclosedClaims: ['name'],
        signer: SESSION_SIGNER,
        iatSeconds: IAT,
      },
    ]);

    const template = buildVPTokenTemplate(request, {
      format: 'vc+sd-jwt',
      sdJwt,
      disclosedClaims: ['name'],
      alg: SESSION_ALG,
      iatSeconds: IAT,
    });
    const separated = attachKeyBindingSignature(template, signAsSession(template.signingInput));

    // 単一クレデンシャルなので `buildVPToken` は文字列を返す。
    expect(typeof integrated).toBe('string');
    expect(separated).toBe(integrated as string);
  });

  it('別リクエスト向けに署名された KB-JWT の流用を sd_hash 不一致で拒否する（3012）', () => {
    const sdJwt = issueSdJwt();
    const template = buildVPTokenTemplate(sampleRequest(), {
      format: 'vc+sd-jwt',
      sdJwt,
      disclosedClaims: ['name'],
      alg: SESSION_ALG,
      iatSeconds: IAT,
    });
    // 開示範囲が異なる（= 提示部が異なる）別リクエスト向けテンプレート。
    const other = buildVPTokenTemplate(sampleRequest({ nonce: 'other-nonce' }), {
      format: 'vc+sd-jwt',
      sdJwt,
      disclosedClaims: ['name', 'email'],
      alg: SESSION_ALG,
      iatSeconds: IAT,
    });
    const otherKbJwt = `${other.signingInput}.${Buffer.from(
      signAsSession(other.signingInput),
    ).toString('base64url')}`;

    expect(() => attachKeyBinding(template, otherKbJwt)).toThrow(
      new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH),
    );
  });
});

describe('buildVPTokenTemplate — kid 付き署名鍵の同値性', () => {
  /** KMS / HSM 運用で verification method ID を伝える Agent Session 鍵。 */
  const KID = 'did:example:agent#session-1';
  const KEYED_SESSION_SIGNER: CredentialSigner = { ...SESSION_SIGNER, kid: KID };

  it('kid を宣言したテンプレートの合成結果が buildVPToken と同一バイト列になる', () => {
    const request = sampleRequest();
    const sdJwt = issueSdJwt();

    // 統合構成: `buildVPToken` は `addKeyBinding` 経由で `signer.kid` をヘッダへ伝播する。
    const integrated = buildVPToken(request, [
      {
        format: 'vc+sd-jwt',
        sdJwt,
        disclosedClaims: ['name'],
        signer: KEYED_SESSION_SIGNER,
        iatSeconds: IAT,
      },
    ]);

    // 分離構成: 秘密鍵を渡さないため `kid` は `SdJwtTemplateInput.kid` で宣言する。
    const template = buildVPTokenTemplate(request, {
      format: 'vc+sd-jwt',
      sdJwt,
      disclosedClaims: ['name'],
      alg: SESSION_ALG,
      kid: KID,
      iatSeconds: IAT,
    });
    expect(template.header).toEqual({ alg: SESSION_ALG, kid: KID, typ: 'kb+jwt' });

    const separated = attachKeyBindingSignature(template, signAsSession(template.signingInput));
    expect(separated).toBe(integrated as string);
  });

  it('kid を宣言しないテンプレートは kid 付き buildVPToken と別バイト列になる（取り違えの検出）', () => {
    const request = sampleRequest();
    const sdJwt = issueSdJwt();

    const integrated = buildVPToken(request, [
      {
        format: 'vc+sd-jwt',
        sdJwt,
        disclosedClaims: ['name'],
        signer: KEYED_SESSION_SIGNER,
        iatSeconds: IAT,
      },
    ]);
    const template = buildVPTokenTemplate(request, {
      format: 'vc+sd-jwt',
      sdJwt,
      disclosedClaims: ['name'],
      alg: SESSION_ALG,
      iatSeconds: IAT,
    });
    const separated = attachKeyBindingSignature(template, signAsSession(template.signingInput));

    expect(separated).not.toBe(integrated as string);
  });

  it('kid 未宣言時の VP Token は従来どおり kid なし signer の結果と一致する（後方互換）', () => {
    const request = sampleRequest();
    const sdJwt = issueSdJwt();

    const integrated = buildVPToken(request, [
      {
        format: 'vc+sd-jwt',
        sdJwt,
        disclosedClaims: ['name'],
        signer: SESSION_SIGNER,
        iatSeconds: IAT,
      },
    ]);
    const template = buildVPTokenTemplate(request, {
      format: 'vc+sd-jwt',
      sdJwt,
      disclosedClaims: ['name'],
      alg: SESSION_ALG,
      iatSeconds: IAT,
    });
    expect(template.header).toEqual({ alg: SESSION_ALG, typ: 'kb+jwt' });
    expect(attachKeyBindingSignature(template, signAsSession(template.signingInput))).toBe(
      integrated as string,
    );
  });

  it('kid 付き KB-JWT も検証を通る（cnf.jwk による署名検証は kid に依存しない）', () => {
    const request = sampleRequest();
    const template = buildVPTokenTemplate(request, {
      format: 'vc+sd-jwt',
      sdJwt: issueSdJwt(),
      disclosedClaims: ['name'],
      alg: SESSION_ALG,
      kid: KID,
      iatSeconds: IAT,
    });
    const vpTokenEntry = attachKeyBindingSignature(template, signAsSession(template.signingInput));

    const result = verifySdJwt(vpTokenEntry, {
      issuerKey: ISSUER_JWK,
      expectedVct: VCT,
      audience: CLIENT_ID,
      nonce: NONCE,
      requireKeyBinding: true,
    });
    expect(result.keyBindingVerified).toBe(true);
  });
});
