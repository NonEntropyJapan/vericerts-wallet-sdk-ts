/**
 * SD-JWT VC / KB-JWT の EdDSA（Ed25519）対応テストの共有フィクスチャ（実鍵・モック禁止）。
 *
 * `sdjwt.eddsa.test.ts` から分離した固定鍵・公開鍵 JWK・SD-JWT 組み立てヘルパ
 * （1 ファイル 300 行以下のため。`presentation.fixtures.ts` と同じ方針）。
 *
 * 鍵素材はすべて決定的な固定シード（`new Uint8Array(32).fill(n)`）から導出する。
 * 乱数は使わず、テスト間で同じ SD-JWT が再現できるように salt / iat も固定値を使う。
 */

import type { PublicKeyJwk } from '../../../identity/did.js';
import { getEd25519PublicKey } from '../../../keymanager/ed25519.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import type { CredentialAlg } from '../../vc/jws.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../vc/signer.js';
import { type ConfirmationClaim, createSdJwt } from '../sdjwt.js';

/** Issuer の Ed25519 シード（32B 固定）。 */
export const ED_ISSUER_SEED = new Uint8Array(32).fill(7);
/** Holder の Ed25519 シード（Issuer とは別鍵であることを保証するため別値）。 */
export const ED_HOLDER_SEED = new Uint8Array(32).fill(11);
/** cnf に載らない別 Holder の Ed25519 シード（HOLDER_BIND_MISMATCH 検証用）。 */
export const ED_OTHER_HOLDER_SEED = new Uint8Array(32).fill(13);
/** 別 Issuer の Ed25519 シード（署名不一致 = 3010 の検証用）。 */
export const ED_OTHER_ISSUER_SEED = new Uint8Array(32).fill(23);
/** Issuer の P-256 秘密鍵（ES256 側の既存挙動確認用）。 */
export const P256_ISSUER_KEY = new Uint8Array(32).fill(9);
/** Holder の P-256 秘密鍵（ES256 側の KB-JWT 用）。 */
export const P256_HOLDER_KEY = new Uint8Array(32).fill(17);
/** cnf に載らない別 Holder の P-256 秘密鍵。 */
export const P256_OTHER_HOLDER_KEY = new Uint8Array(32).fill(19);

/** Verifiable Credential Type（テスト共通）。 */
export const VCT = 'https://example.com/credentials/identity';
/** Verifier 発行 nonce（固定）。 */
export const NONCE = 'verifier-nonce-361';
/** Verifier 識別子（固定）。 */
export const AUD = 'https://verifier.example';
/** KB-JWT の iat（固定。時刻依存を排除する）。 */
export const IAT = 1_767_225_600;

/** バイト列を base64url（パディングなし）へ変換する。 */
export function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** 非圧縮 EC 公開鍵（`0x04 || x || y`）から EC 公開鍵 JWK を構築する。 */
export function toEcJwk(uncompressed: Uint8Array, crv: string): PublicKeyJwk {
  return {
    kty: 'EC',
    crv,
    x: b64u(uncompressed.subarray(1, 33)),
    y: b64u(uncompressed.subarray(33, 65)),
  };
}

/** Ed25519 公開鍵（32B）から OKP 公開鍵 JWK を構築する（RFC 8037: `y` を持たない）。 */
export function toOkpJwk(publicKey: Uint8Array): PublicKeyJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: b64u(publicKey) };
}

/** alg ごとの Issuer / Holder 鍵一式（`describe.each` の共有ハッピーパス用）。 */
export interface AlgFixture {
  /** Issuer 署名鍵。 */
  readonly issuerSigner: CredentialSigner;
  /** Issuer 検証鍵 JWK。 */
  readonly issuerJwk: PublicKeyJwk;
  /** cnf に載る Holder の署名鍵。 */
  readonly holderSigner: CredentialSigner;
  /** cnf に載る Holder の公開鍵 JWK。 */
  readonly holderJwk: PublicKeyJwk;
  /** cnf に載らない別 Holder の署名鍵。 */
  readonly otherHolderSigner: CredentialSigner;
}

/** ES256（EC/P-256）と EdDSA（OKP/Ed25519）のフィクスチャ。 */
export const ALG_FIXTURES: Readonly<Record<'ES256' | 'EdDSA', AlgFixture>> = {
  ES256: {
    issuerSigner: createPrivateKeySigner(P256_ISSUER_KEY, 'ES256'),
    issuerJwk: toEcJwk(getP256PublicKey(P256_ISSUER_KEY, false), 'P-256'),
    holderSigner: createPrivateKeySigner(P256_HOLDER_KEY, 'ES256'),
    holderJwk: toEcJwk(getP256PublicKey(P256_HOLDER_KEY, false), 'P-256'),
    otherHolderSigner: createPrivateKeySigner(P256_OTHER_HOLDER_KEY, 'ES256'),
  },
  EdDSA: {
    issuerSigner: createPrivateKeySigner(ED_ISSUER_SEED, 'EdDSA'),
    issuerJwk: toOkpJwk(getEd25519PublicKey(ED_ISSUER_SEED)),
    holderSigner: createPrivateKeySigner(ED_HOLDER_SEED, 'EdDSA'),
    holderJwk: toOkpJwk(getEd25519PublicKey(ED_HOLDER_SEED)),
    otherHolderSigner: createPrivateKeySigner(ED_OTHER_HOLDER_SEED, 'EdDSA'),
  },
};

/**
 * `vct` / `cnf` / 開示クレーム（name / age_over_18 / email）を持つ SD-JWT を発行する。
 *
 * salt は固定値を注入し、同じ入力からは常に同じ SD-JWT が得られるようにする。
 *
 * @param signer Issuer 署名鍵。
 * @param cnf Holder 公開鍵バインド（省略時は `cnf` なし）。
 * @returns SD-JWT 文字列（末尾 `~`）。
 */
export function issueSdJwt(signer: CredentialSigner, cnf?: ConfirmationClaim): string {
  return createSdJwt(signer, {
    vct: VCT,
    issuer: 'did:example:issuer',
    ...(cnf !== undefined ? { cnf } : {}),
    disclosureClaims: ['name', 'age_over_18', 'email'],
    claims: {
      name: 'Alice',
      age_over_18: true,
      email: 'alice@example.com',
      sub: 'did:example:holder',
    },
    salts: { name: 'salt-name', age_over_18: 'salt-age', email: 'salt-email' },
  });
}

/** SD-JWT の Issuer-signed JWT ヘッダをデコードする（`alg` / `typ` の実値確認用）。 */
export function decodeIssuerHeader(sdJwt: string): Record<string, unknown> {
  const headerSeg = sdJwt.split('~')[0]?.split('.')[0] ?? '';
  return JSON.parse(Buffer.from(headerSeg, 'base64url').toString());
}

/**
 * Issuer-signed JWT のヘッダだけを差し替えた SD-JWT を作る（署名・payload はそのまま）。
 *
 * `alg: 'none'` や alg confusion の偽造トークンを組み立てるために使う。
 *
 * @param sdJwt 元の SD-JWT。
 * @param header 差し替える JWS ヘッダ。
 * @returns ヘッダを偽造した SD-JWT。
 */
export function forgeIssuerHeader(sdJwt: string, header: Record<string, unknown>): string {
  const tildeIndex = sdJwt.indexOf('~');
  const [, payloadSeg, signatureSeg] = sdJwt.slice(0, tildeIndex).split('.');
  const forged = Buffer.from(JSON.stringify(header)).toString('base64url');
  return `${forged}.${payloadSeg}.${signatureSeg}${sdJwt.slice(tildeIndex)}`;
}

/**
 * 任意の payload を実鍵で署名して SD-JWT（Disclosure なし）を組み立てる。
 *
 * 不正形状の `cnf` を「署名は正しいが payload だけ攻撃者仕様」という形で検証面に届けるために使う
 * （`sdjwt.hardening.test.ts` の `reissueWithPayload` と同方針）。
 *
 * @param signer Issuer 署名鍵。
 * @param alg ヘッダに載せる `alg`。
 * @param payload Issuer payload。
 * @returns SD-JWT 文字列（末尾 `~`）。
 */
export function reissueWithPayload(
  signer: CredentialSigner,
  alg: CredentialAlg,
  payload: Record<string, unknown>,
): string {
  const headerSeg = Buffer.from(JSON.stringify({ alg, typ: 'vc+sd-jwt' })).toString('base64url');
  const payloadSeg = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${headerSeg}.${payloadSeg}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64u(signature)}~`;
}
