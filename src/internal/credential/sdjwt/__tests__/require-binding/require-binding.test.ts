/**
 * `requireKeyBinding: true` が `audience` / `nonce` の指定を要求することの回帰テスト。
 *
 * 修正前の `assertKeyBinding` は期待値が `undefined` の項目の照合を丸ごとスキップしていたため、
 * `verifySdJwt(sdJwt, { issuerKey, requireKeyBinding: true })` は KB-JWT について
 * 「`cnf` 鍵を保持しているか」しか見ておらず、**別 Verifier 宛（`aud` 違い）・別セッション
 * （`nonce` 違い）の KB-JWT を付けた提示を受理**していた。本テストはその受理が
 * `3012 HOLDER_BIND_MISMATCH` になることを固定する。
 *
 * 検証内容:
 * - `requireKeyBinding: true` で `audience` / `nonce` の双方または一方が欠けると `3012`。
 * - 空文字 / 非文字列 / 継承（own でない）値は「指定なし」として扱い `3012`。
 * - 双方を指定した正当な提示は従来どおり成功する。
 * - `requireKeyBinding` 未指定（既定 `false`）の経路は後方互換（照合スキップのまま成功）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../../keymanager/signer.js';
import type { CredentialAlg } from '../../../vc/jws.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { computeSdHash, KB_JWT_TYP } from '../../key-binding.js';
import { createSdJwt, selectDisclosures } from '../../sdjwt.js';
import { addKeyBinding, verifySdJwt } from '../../verify.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const HOLDER_KEY = new Uint8Array(32).fill(11);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const HOLDER_JWK = toJwk(getSecp256k1PublicKey(HOLDER_KEY, false), 'secp256k1');
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const HOLDER_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256K' as CredentialAlg);

const VCT = 'https://example.com/credentials/identity';
/** KB-JWT が実際に宛てている Verifier / セッション（＝ 攻撃者から見た「他所」）。 */
const OTHER_AUD = 'https://other-verifier.example';
const OTHER_NONCE = 'other-session-nonce-123';
const AUD = 'https://verifier.example';
const NONCE = 'verifier-nonce-123';
const IAT = 1_767_225_600;

/** `OTHER_AUD` / `OTHER_NONCE` に宛てた KB-JWT 付き提示を作る。 */
function presentToOtherVerifier(): string {
  const sdJwt = createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    issuer: 'did:example:issuer',
    cnf: { jwk: HOLDER_JWK },
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
  });
  return addKeyBinding(selectDisclosures(sdJwt, ['name']), HOLDER_SIGNER, {
    nonce: OTHER_NONCE,
    audience: OTHER_AUD,
    iatSeconds: IAT,
  });
}

/**
 * 任意の `aud` / `nonce` を載せた KB-JWT を手組みして提示に付ける。
 *
 * `addKeyBinding` は空文字の `audience` / `nonce` を 3012 で拒否するため、「空 `aud` / `nonce` の
 * KB-JWT」は正規 API では作れない。空文字を「未指定」と同じ扱いにするガードは、この
 * 手組み提示が無いと**修正前も修正後も 3012**（期待値と実測値が単に不一致）になり、分岐を固定
 * できないため、署名だけ正当な提示をここで組み立てる。
 */
function presentWithRawKeyBinding(aud: string, nonce: string): string {
  const sdJwt = createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    issuer: 'did:example:issuer',
    cnf: { jwk: HOLDER_JWK },
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
  });
  const presented = selectDisclosures(sdJwt, ['name']);
  const b64uText = (t: string): string => Buffer.from(t).toString('base64url');
  const header = b64uText(JSON.stringify({ alg: 'ES256K', typ: KB_JWT_TYP }));
  const payload = b64uText(
    JSON.stringify({ aud, nonce, sd_hash: computeSdHash(presented), iat: IAT }),
  );
  const signingInput = `${header}.${payload}`;
  const sig = HOLDER_SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${presented}${signingInput}.${Buffer.from(sig).toString('base64url')}`;
}

/** 送出された `VericertsError` のコードを取り出す（例外が出なければ `undefined`）。 */
function thrownCode(fn: () => unknown): string | undefined {
  try {
    fn();
    return undefined;
  } catch (error) {
    return error instanceof VericertsError ? error.code : String(error);
  }
}

describe('verifySdJwt — requireKeyBinding は audience / nonce を必須にする', () => {
  it('audience / nonce の双方が未指定なら 3012（他所宛の KB-JWT を受理しない）', () => {
    const presented = presentToOtherVerifier();
    // 修正前はここが成功し、keyBindingVerified: true で他 Verifier 宛の提示が通っていた。
    expect(
      thrownCode(() =>
        verifySdJwt(presented, {
          issuerKey: ISSUER_JWK,
          requireKeyBinding: true,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });

  it('nonce だけ指定して audience を欠くと 3012', () => {
    expect(
      thrownCode(() =>
        verifySdJwt(presentToOtherVerifier(), {
          issuerKey: ISSUER_JWK,
          requireKeyBinding: true,
          nonce: OTHER_NONCE,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });

  it('audience だけ指定して nonce を欠くと 3012', () => {
    expect(
      thrownCode(() =>
        verifySdJwt(presentToOtherVerifier(), {
          issuerKey: ISSUER_JWK,
          requireKeyBinding: true,
          audience: OTHER_AUD,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });

  it('空文字の audience / nonce は「指定なし」として 3012（空 aud / nonce の KB-JWT で迂回させない）', () => {
    // KB-JWT 側も aud / nonce が空文字なので、単純な値比較なら「一致」して通ってしまう。
    // 空文字を「未指定」として弾く分岐が無いと素通りするケース。
    const presented = presentWithRawKeyBinding('', '');
    // 前提: 署名・sd_hash は正当なので、空文字を許すなら KB 検証は成立してしまう。
    expect(verifySdJwt(presented, { issuerKey: ISSUER_JWK }).keyBindingVerified).toBe(true);
    expect(
      thrownCode(() =>
        verifySdJwt(presented, {
          issuerKey: ISSUER_JWK,
          requireKeyBinding: true,
          audience: '',
          nonce: '',
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });

  it('非文字列の audience / nonce は「指定なし」として 3012', () => {
    const opts = {
      issuerKey: ISSUER_JWK,
      requireKeyBinding: true,
      audience: 123 as unknown as string,
      nonce: {} as unknown as string,
    };
    expect(thrownCode(() => verifySdJwt(presentToOtherVerifier(), opts))).toBe(
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });

  it('KB-JWT が無い提示でも従来どおり 3012（必須要求そのものは維持）', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      issuer: 'did:example:issuer',
      cnf: { jwk: HOLDER_JWK },
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
      salts: { name: 'salt-name' },
    });
    expect(
      thrownCode(() =>
        verifySdJwt(selectDisclosures(sdJwt, ['name']), {
          issuerKey: ISSUER_JWK,
          requireKeyBinding: true,
          audience: AUD,
          nonce: NONCE,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });

  it('audience / nonce を両方指定した正当な提示は成功する', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      issuer: 'did:example:issuer',
      cnf: { jwk: HOLDER_JWK },
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
      salts: { name: 'salt-name' },
    });
    const bound = addKeyBinding(selectDisclosures(sdJwt, ['name']), HOLDER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    const verified = verifySdJwt(bound, {
      issuerKey: ISSUER_JWK,
      requireKeyBinding: true,
      audience: AUD,
      nonce: NONCE,
    });
    expect(verified.keyBindingVerified).toBe(true);
    expect(verified.claims.name).toBe('Alice');
  });

  it('requireKeyBinding 未指定（既定）は後方互換: 期待値なしでも KB-JWT を検証して成功する', () => {
    const verified = verifySdJwt(presentToOtherVerifier(), {
      issuerKey: ISSUER_JWK,
    });
    expect(verified.keyBindingVerified).toBe(true);
    expect(verified.claims.name).toBe('Alice');
  });

  it('requireKeyBinding: false を明示した場合も後方互換', () => {
    const verified = verifySdJwt(presentToOtherVerifier(), {
      issuerKey: ISSUER_JWK,
      requireKeyBinding: false,
    });
    expect(verified.keyBindingVerified).toBe(true);
  });
});

describe('verifySdJwt — 必須判定はプロトタイプ鎖を辿らない', () => {
  afterEach(() => {
    // biome-ignore lint/suspicious/noExplicitAny: プロトタイプ汚染の後始末。
    delete (Object.prototype as any).audience;
    // biome-ignore lint/suspicious/noExplicitAny: プロトタイプ汚染の後始末。
    delete (Object.prototype as any).nonce;
  });

  it('継承した audience / nonce は「指定なし」として 3012（汚染値で必須検査を満たさない）', () => {
    // biome-ignore lint/suspicious/noExplicitAny: プロトタイプ汚染の再現。
    (Object.prototype as any).audience = OTHER_AUD;
    // biome-ignore lint/suspicious/noExplicitAny: プロトタイプ汚染の再現。
    (Object.prototype as any).nonce = OTHER_NONCE;
    expect(
      thrownCode(() =>
        verifySdJwt(presentToOtherVerifier(), {
          issuerKey: ISSUER_JWK,
          requireKeyBinding: true,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });
});
