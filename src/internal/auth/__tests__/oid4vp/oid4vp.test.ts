/**
 * OID4VP VP Token 構成・direct_post 送信のユニットテスト（実鍵・モック禁止の方針）。
 *
 * 検証内容:
 * - `buildVPToken`（jwt_vc_json）: JWT-VP を構成し、`verifyPresentation` でラウンドトリップ成功。
 *   リクエストの nonce / client_id が VP に束縛される（Holder Binding）。
 * - `buildVPToken`（vc+sd-jwt）: 選択的開示 + KB-JWT を構成し、`verifySdJwt`（requireKeyBinding）で成功。
 *   未開示クレームは復元されない。nonce / aud が KB-JWT に束縛される。
 * - 単一クレデンシャル → string、複数 → string[]。
 * - 入力空で PRESENTATION_SUBMIT_FAILED（8035）。
 * - `submitPresentation`: direct_post で vp_token + state を form-urlencoded POST する。
 *   未対応 response_mode・HTTP 非 2xx・ネットワーク失敗で 8035。
 *
 * fetch はネットワーク非依存のため `globalThis.fetch` を差し替える（HTTP 層のみ。署名・暗号は実鍵）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { verifyPresentation } from '../../../credential/presentation/presentation.js';
import { createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { verifySdJwt } from '../../../credential/sdjwt/verify.js';
import type { CredentialAlg } from '../../../credential/vc/jws.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { buildVPToken } from '../../oid4vp/oid4vp.js';
import { submitPresentation } from '../../oid4vp/oid4vp-submit.js';
import type { PresentationRequest } from '../../request.js';

const HOLDER_KEY = new Uint8Array(32).fill(11);
const ISSUER_KEY = new Uint8Array(32).fill(7);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const HOLDER_JWK = toJwk(getP256PublicKey(HOLDER_KEY, false), 'P-256');
const HOLDER_SECP_JWK = toJwk(getSecp256k1PublicKey(HOLDER_KEY, false), 'secp256k1');
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');

const HOLDER_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256');
const HOLDER_SECP_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256K' as CredentialAlg);
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

const HOLDER_DID = 'did:example:holder';
const CLIENT_ID = 'https://verifier.example.com';
const NONCE = 'n-0S6_WzA2Mj';
const STATE = 'af0ifjsldkj';
const VCT = 'https://example.com/credentials/identity';

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

/** 提示・検証で用いる固定の発行時刻（KB-JWT の `iat` / 検証時の `nowSeconds` と同一）。 */
const ISSUED_AT = 1_700_000_000;

/** cnf / 開示クレームを持つ SD-JWT VC を発行する。 */
function issueSdJwt(): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    issuer: 'did:example:issuer',
    cnf: { jwk: HOLDER_SECP_JWK },
    disclosureClaims: ['name', 'email'],
    claims: { name: 'Alice', email: 'alice@example.com', sub: HOLDER_DID },
    salts: { name: 'salt-name', email: 'salt-email' },
    nowSeconds: ISSUED_AT,
  });
}

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** 任意の fetch 実装をグローバルに差し込む（型は test 用に緩める）。 */
function setFetch(impl: (url: string, init?: RequestInit) => Promise<Response>): void {
  globalThis.fetch = impl as unknown as typeof fetch;
}

describe('buildVPToken — jwt_vc_json', () => {
  it('JWT-VP を構成し verifyPresentation でラウンドトリップ成功（nonce / aud 束縛）', () => {
    const request = sampleRequest();
    const token = buildVPToken(request, [
      {
        format: 'jwt_vc_json',
        holder: HOLDER_DID,
        verifiableCredentials: ['eyJhbGciOiJFUzI1NiJ9.vc-payload.sig'],
        presentationId: 'urn:uuid:vp-1',
        signer: HOLDER_SIGNER,
      },
    ]);

    // 単一クレデンシャルは文字列で返る。
    expect(typeof token).toBe('string');

    const verified = verifyPresentation(token as string, {
      key: { publicKeyJwk: HOLDER_JWK },
      expectedAudience: CLIENT_ID,
      expectedNonce: NONCE,
    });
    expect(verified.payload.iss).toBe(HOLDER_DID);
    expect(verified.payload.aud).toBe(CLIENT_ID);
    expect(verified.payload.nonce).toBe(NONCE);
    expect(verified.presentation.holder).toBe(HOLDER_DID);
  });

  it('nonce 不一致を検証側が拒否する（Holder Binding、3012）', () => {
    const token = buildVPToken(sampleRequest(), [
      {
        format: 'jwt_vc_json',
        holder: HOLDER_DID,
        verifiableCredentials: ['eyJhbGciOiJFUzI1NiJ9.vc.sig'],
        signer: HOLDER_SIGNER,
      },
    ]) as string;

    expect(() =>
      verifyPresentation(token, {
        key: { publicKeyJwk: HOLDER_JWK },
        expectedAudience: CLIENT_ID,
        expectedNonce: 'wrong-nonce',
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });
});

describe('buildVPToken — vc+sd-jwt', () => {
  it('選択的開示 + KB-JWT を構成し verifySdJwt（requireKeyBinding）で成功', () => {
    const request = sampleRequest();
    const sdJwt = issueSdJwt();
    const token = buildVPToken(request, [
      {
        format: 'vc+sd-jwt',
        sdJwt,
        disclosedClaims: ['name'],
        signer: HOLDER_SECP_SIGNER,
        iatSeconds: 1_700_000_000,
      },
    ]) as string;

    const verified = verifySdJwt(token, {
      issuerKey: ISSUER_JWK,
      expectedVct: VCT,
      requireKeyBinding: true,
      audience: CLIENT_ID,
      nonce: NONCE,
      nowSeconds: 1_700_000_000,
    });
    expect(verified.keyBindingVerified).toBe(true);
    // 開示した name のみ復元され、未開示の email は復元されない。
    expect(verified.claims.name).toBe('Alice');
    expect(verified.claims.email).toBeUndefined();
  });

  it('KB-JWT の nonce 不一致を検証側が拒否する（3012）', () => {
    const token = buildVPToken(sampleRequest({ nonce: 'other-nonce' }), [
      {
        format: 'vc+sd-jwt',
        sdJwt: issueSdJwt(),
        disclosedClaims: ['name'],
        signer: HOLDER_SECP_SIGNER,
      },
    ]) as string;

    expect(() =>
      verifySdJwt(token, {
        issuerKey: ISSUER_JWK,
        expectedVct: VCT,
        requireKeyBinding: true,
        audience: CLIENT_ID,
        nonce: NONCE,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });
});

describe('buildVPToken — 複数 / 空', () => {
  it('複数クレデンシャルは string[] で返る', () => {
    const token = buildVPToken(sampleRequest(), [
      {
        format: 'jwt_vc_json',
        holder: HOLDER_DID,
        verifiableCredentials: ['a.b.c'],
        signer: HOLDER_SIGNER,
      },
      {
        format: 'vc+sd-jwt',
        sdJwt: issueSdJwt(),
        disclosedClaims: ['name'],
        signer: HOLDER_SECP_SIGNER,
      },
    ]);
    expect(Array.isArray(token)).toBe(true);
    expect((token as string[]).length).toBe(2);
  });

  it('入力が空なら PRESENTATION_SUBMIT_FAILED（8035）', () => {
    expect(() => buildVPToken(sampleRequest(), [])).toThrow(
      new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED),
    );
  });
});

describe('submitPresentation — direct_post', () => {
  it('vp_token + state を form-urlencoded で POST する', async () => {
    let captured: { url: string; body: string; contentType: string | null } | undefined;
    setFetch(async (url, init) => {
      captured = {
        url: String(url),
        body: String(init?.body ?? ''),
        contentType: new Headers(init?.headers).get('Content-Type'),
      };
      return new Response(null, { status: 200 });
    });

    const request = sampleRequest();
    await submitPresentation(request, 'vp-token-string');

    expect(captured?.url).toBe(`${CLIENT_ID}/callback`);
    expect(captured?.contentType).toBe('application/x-www-form-urlencoded');
    const params = new URLSearchParams(captured?.body);
    expect(params.get('vp_token')).toBe('vp-token-string');
    expect(params.get('state')).toBe(STATE);
  });

  it('複数 VP Token は JSON 配列文字列として送る', async () => {
    let body = '';
    setFetch(async (_url, init) => {
      body = String(init?.body ?? '');
      return new Response(null, { status: 200 });
    });

    await submitPresentation(sampleRequest(), ['tok-a', 'tok-b']);
    const params = new URLSearchParams(body);
    expect(JSON.parse(params.get('vp_token') as string)).toEqual(['tok-a', 'tok-b']);
  });

  it('未対応 response_mode（fragment.jwt）は 8035 で拒否し fetch しない', async () => {
    let called = false;
    setFetch(async () => {
      called = true;
      return new Response(null, { status: 200 });
    });

    await expect(
      submitPresentation(sampleRequest({ responseMode: 'fragment.jwt' }), 'tok'),
    ).rejects.toThrow(new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED));
    expect(called).toBe(false);
  });

  it('HTTP 非 2xx は 8035 に正規化する', async () => {
    setFetch(async () => new Response(null, { status: 400 }));
    await expect(submitPresentation(sampleRequest(), 'tok')).rejects.toThrow(
      new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED),
    );
  });

  it('ネットワーク失敗は 8035 に正規化する', async () => {
    setFetch(async () => {
      throw new Error('network down');
    });
    await expect(submitPresentation(sampleRequest(), 'tok')).rejects.toThrow(
      new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED),
    );
  });
});
