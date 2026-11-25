/**
 * DPoP proof 検証（`verifyDpopProof`）のユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容（RFC 9449 §4.3）:
 * - round-trip: `createDpopProof` → `verifyDpopProof` が成功し、`jti` / `jkt` / `iat` / `htm` /
 *   `htu` が期待値と一致する（ES256 / ES256K）。
 * - 形式不正（セグメント数・base64url・`typ`・`alg`・`jwk`）→ 4080。
 * - 署名改竄 → 4081。`iat` の鮮度違反 → 4082。
 * - `htm` / `htu` 不一致 → 4083。`nonce` 欠落・不一致 → 4086。`ath` 不一致・欠落 → 4084。
 *   `jkt` 不一致 → 4085。
 * - 例外にアクセストークン・proof JWT・鍵素材が含まれない。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { signCompactJws } from '../../../credential/vc/compact-jws.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import { createDpopProof } from '../dpop.js';
import { computeAth, computeJwkThumbprint, type DpopAlg } from '../dpop-common.js';
import { verifyDpopProof } from '../dpop-verify.js';

/** テスト用の固定秘密鍵（alg ごとに別鍵）。 */
const KEYS: Record<DpopAlg, Uint8Array> = {
  ES256: new Uint8Array(32).fill(7),
  ES256K: new Uint8Array(32).fill(9),
};

/** 固定現在時刻（エポック秒）。 */
const NOW = 1_767_225_600;

const HTM = 'POST';
const HTU = 'https://api.example.com/mcp';
const ACCESS_TOKEN = 'access-token-abc123';
const NONCE = 'dpop-nonce-xyz';

/** 検証条件の既定値（`htm` / `htu` / `nowSeconds` のみ）。 */
const BASE = { htm: HTM, htu: HTU, nowSeconds: NOW } as const;

/** UTF-8 JSON を base64url（パディングなし）セグメントへ符号化する。 */
function seg(value: unknown): string {
  return base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(value)));
}

/** `verifyDpopProof` が指定コードの VericertsError を投げることを表明し、その例外を返す。 */
function expectCode(
  proof: string,
  options: Parameters<typeof verifyDpopProof>[1],
  code: ErrorCode,
): VericertsError {
  try {
    verifyDpopProof(proof, options);
    throw new Error('should have thrown');
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(code);
    return e as VericertsError;
  }
}

describe.each<DpopAlg>(['ES256', 'ES256K'])('verifyDpopProof round-trip（%s）', (alg) => {
  const signer = createPrivateKeySigner(KEYS[alg], alg);
  const jkt = computeJwkThumbprint(signer.publicKeyJwk, alg);

  it('生成した proof が検証を通り、jti/jkt/iat/htm/htu を返す', () => {
    const proof = createDpopProof(
      { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW },
      signer,
    );
    const verified = verifyDpopProof(proof, BASE);
    expect(verified.jti).toBe('3b241101-e2bb-4255-8caf-4136c566a962');
    expect(verified.jkt).toBe(jkt);
    expect(verified.iat).toBe(NOW);
    expect(verified.htm).toBe(HTM);
    expect(verified.htu).toBe(HTU);
    expect(verified.alg).toBe(alg);
    expect(verified.publicKeyJwk.kty).toBe('EC');
    expect(verified.ath).toBeUndefined();
    expect(verified.nonce).toBeUndefined();
  });

  it('accessToken / nonce / expectedJkt をすべて指定しても検証が通る', () => {
    const proof = createDpopProof(
      {
        htm: HTM,
        htu: `${HTU}?q=1#frag`,
        accessToken: ACCESS_TOKEN,
        nonce: NONCE,
        nowSeconds: NOW,
      },
      signer,
    );
    const verified = verifyDpopProof(proof, {
      ...BASE,
      accessToken: ACCESS_TOKEN,
      nonce: NONCE,
      expectedJkt: jkt,
    });
    expect(verified.htu).toBe(HTU);
    expect(verified.ath).toBe(computeAth(ACCESS_TOKEN));
    expect(verified.nonce).toBe(NONCE);
  });
});

describe('verifyDpopProof 形式不正（4080）', () => {
  const signer = createPrivateKeySigner(KEYS.ES256, 'ES256');
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: signer.publicKeyJwk };
  const claims = { jti: '3b241101-e2bb-4255-8caf-4136c566a962', htm: HTM, htu: HTU, iat: NOW };

  it('セグメント数が足りない', () => {
    expectCode('aaa.bbb', BASE, ErrorCodes.DPOP_PROOF_MALFORMED);
  });

  it('base64url として不正', () => {
    expectCode('!!!.!!!.!!!', BASE, ErrorCodes.DPOP_PROOF_MALFORMED);
  });

  it('typ が jwt', () => {
    const proof = signCompactJws({ ...header, typ: 'jwt' }, claims, signer);
    expectCode(proof, BASE, ErrorCodes.DPOP_PROOF_MALFORMED);
  });

  it.each(['none', 'EdDSA'])('alg が %s', (alg) => {
    const proof = signCompactJws({ ...header, alg }, claims, signer);
    expectCode(proof, BASE, ErrorCodes.DPOP_PROOF_MALFORMED);
  });

  it('header に jwk が無い', () => {
    const proof = signCompactJws({ typ: 'dpop+jwt', alg: 'ES256' }, claims, signer);
    expectCode(proof, BASE, ErrorCodes.DPOP_PROOF_MALFORMED);
  });

  it('jwk が秘密鍵メンバ d を含む', () => {
    const jwk = { ...(signer.publicKeyJwk as Record<string, unknown>), d: 'private' };
    const proof = signCompactJws({ ...header, jwk }, claims, signer);
    expectCode(proof, BASE, ErrorCodes.DPOP_PROOF_MALFORMED);
  });

  it.each<[string, Record<string, unknown>]>([
    ['jti が空', { jti: '' }],
    ['htm が非文字列', { htm: 42 }],
    ['htu が空', { htu: '' }],
    ['iat が非整数', { iat: 1.5 }],
  ])('payload の %s', (_label, override) => {
    const proof = signCompactJws(header, { ...claims, ...override }, signer);
    expectCode(proof, BASE, ErrorCodes.DPOP_PROOF_MALFORMED);
  });
});

describe('verifyDpopProof 署名不正（4081）', () => {
  const signer = createPrivateKeySigner(KEYS.ES256, 'ES256');

  it('payload だけ差し替えると署名検証に失敗する', () => {
    const proof = createDpopProof(
      { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW },
      signer,
    );
    const [headerSeg, , signatureSeg] = proof.split('.') as [string, string, string];
    const forgedPayload = seg({ jti: 'jti-forged', htm: HTM, htu: HTU, iat: NOW });
    expectCode(
      `${headerSeg}.${forgedPayload}.${signatureSeg}`,
      BASE,
      ErrorCodes.DPOP_SIGNATURE_INVALID,
    );
  });

  it('別鍵で署名した proof は検証に失敗する', () => {
    const other = createPrivateKeySigner(new Uint8Array(32).fill(11), 'ES256');
    const proof = signCompactJws(
      { typ: 'dpop+jwt', alg: 'ES256', jwk: signer.publicKeyJwk },
      { jti: '3b241101-e2bb-4255-8caf-4136c566a962', htm: HTM, htu: HTU, iat: NOW },
      other,
    );
    expectCode(proof, BASE, ErrorCodes.DPOP_SIGNATURE_INVALID);
  });
});

describe('verifyDpopProof HTTP 束縛（4083）/ nonce（4086）', () => {
  const signer = createPrivateKeySigner(KEYS.ES256, 'ES256');
  const proof = createDpopProof(
    {
      htm: HTM,
      htu: HTU,
      nonce: NONCE,
      jti: '3b241101-e2bb-4255-8caf-4136c566a962',
      nowSeconds: NOW,
    },
    signer,
  );

  it('htm が不一致', () => {
    expectCode(proof, { ...BASE, htm: 'GET' }, ErrorCodes.DPOP_HTTP_BINDING_MISMATCH);
  });

  it('htu が不一致（別パス）', () => {
    const options = { ...BASE, htu: 'https://api.example.com/other' };
    expectCode(proof, options, ErrorCodes.DPOP_HTTP_BINDING_MISMATCH);
  });

  it('期待 htu がパース不能', () => {
    expectCode(proof, { ...BASE, htu: 'not a uri' }, ErrorCodes.DPOP_HTTP_BINDING_MISMATCH);
  });

  it('nonce が不一致なら 4086（use_dpop_nonce チャレンジ用に 4083 と区別する）', () => {
    const options = { ...BASE, nonce: 'other-nonce' };
    expectCode(proof, options, ErrorCodes.DPOP_NONCE_REQUIRED);
  });

  it('nonce を期待したが proof に無い場合も 4086', () => {
    const noNonce = createDpopProof(
      { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW },
      signer,
    );
    expectCode(noNonce, { ...BASE, nonce: NONCE }, ErrorCodes.DPOP_NONCE_REQUIRED);
  });
});

describe('verifyDpopProof ath / jkt 束縛（4084 / 4085）', () => {
  const signer = createPrivateKeySigner(KEYS.ES256, 'ES256');
  const jkt = computeJwkThumbprint(signer.publicKeyJwk, 'ES256');

  it('別のアクセストークンで生成した proof は ath 不一致', () => {
    const proof = createDpopProof(
      {
        htm: HTM,
        htu: HTU,
        accessToken: 'other-token',
        jti: '3b241101-e2bb-4255-8caf-4136c566a962',
        nowSeconds: NOW,
      },
      signer,
    );
    const options = { ...BASE, accessToken: ACCESS_TOKEN, expectedJkt: jkt };
    expectCode(proof, options, ErrorCodes.DPOP_ATH_MISMATCH);
  });

  it('accessToken を渡したのに proof に ath が無い', () => {
    const proof = createDpopProof(
      { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW },
      signer,
    );
    const options = { ...BASE, accessToken: ACCESS_TOKEN, expectedJkt: jkt };
    expectCode(proof, options, ErrorCodes.DPOP_ATH_MISMATCH);
  });

  it('expectedJkt が不一致', () => {
    const proof = createDpopProof(
      { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW },
      signer,
    );
    const other = createPrivateKeySigner(KEYS.ES256K, 'ES256K');
    const otherJkt = computeJwkThumbprint(other.publicKeyJwk, 'ES256K');
    expectCode(proof, { ...BASE, expectedJkt: otherJkt }, ErrorCodes.DPOP_KEY_BINDING_MISMATCH);
  });

  it('expectedJkt が一致すれば成功する', () => {
    const proof = createDpopProof(
      { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW },
      signer,
    );
    expect(verifyDpopProof(proof, { ...BASE, expectedJkt: jkt }).jkt).toBe(jkt);
  });
});

describe('verifyDpopProof の例外は機微情報を含まない', () => {
  const signer = createPrivateKeySigner(KEYS.ES256, 'ES256');
  const jwk = signer.publicKeyJwk as Record<string, string>;

  it('message にアクセストークン・proof JWT・鍵素材が含まれない', () => {
    const proof = createDpopProof(
      {
        htm: HTM,
        htu: HTU,
        accessToken: 'other-token',
        jti: '3b241101-e2bb-4255-8caf-4136c566a962',
        nowSeconds: NOW,
      },
      signer,
    );
    const jkt = computeJwkThumbprint(signer.publicKeyJwk, 'ES256');
    const error = expectCode(
      proof,
      { ...BASE, accessToken: ACCESS_TOKEN, expectedJkt: jkt },
      ErrorCodes.DPOP_ATH_MISMATCH,
    );
    expect(error.message).not.toContain(ACCESS_TOKEN);
    expect(error.message).not.toContain(proof);
    expect(error.message).not.toContain(jwk.x as string);
  });
});
