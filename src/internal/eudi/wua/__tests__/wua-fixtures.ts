/**
 * eudi/wua テスト用フィクスチャ。
 *
 * P-256 / Ed25519 鍵ペアと署名抽象（`CredentialSigner`）から、`cnf.jwk` バインド済みの
 * WUA JWT を実際に署名生成する。テストごとの重複を避けるため共通化する。
 */

import { base64urlnopad } from '@scure/base';
import { type CredentialSigner, createPrivateKeySigner } from '../../../credential/vc/signer.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getEd25519PublicKey } from '../../../keymanager/ed25519.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { WUA_VCT } from '../types.js';

/** 決定論的なテスト用 P-256 秘密鍵（32 バイト、値は任意の有効鍵）。 */
export const WSCD_PRIVATE_KEY = new Uint8Array(32).fill(7);

/** WSCD 鍵とは別の P-256 秘密鍵（バインド不一致テスト用）。 */
export const OTHER_PRIVATE_KEY = new Uint8Array(32).fill(9);

/** 決定論的なテスト用 Ed25519 シード（32 バイト）。 */
export const ED_WSCD_PRIVATE_KEY = new Uint8Array(32).fill(11);

/** Ed25519 の WSCD 鍵とは別のシード（バインド不一致テスト用）。 */
export const ED_OTHER_PRIVATE_KEY = new Uint8Array(32).fill(13);

/** UTF-8 文字列を base64url（パディングなし）エンコードする。 */
function b64url(text: string): string {
  return base64urlnopad.encode(new TextEncoder().encode(text));
}

/** P-256 秘密鍵から EC 公開鍵 JWK（`kty`/`crv`/`x`/`y`）を構築する。 */
export function toP256Jwk(privateKey: Uint8Array): PublicKeyJwk {
  const uncompressed = getP256PublicKey(privateKey, false);
  return {
    kty: 'EC',
    crv: 'P-256',
    x: base64urlnopad.encode(uncompressed.subarray(1, 33)),
    y: base64urlnopad.encode(uncompressed.subarray(33, 65)),
  };
}

/**
 * Ed25519 シードから OKP 公開鍵 JWK（`kty`/`crv`/`x`）を構築する。
 *
 * OKP 鍵は EC のような `y` を持たない（RFC 8037）。
 */
export function toEd25519Jwk(privateKey: Uint8Array): PublicKeyJwk {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: base64urlnopad.encode(getEd25519PublicKey(privateKey)),
  };
}

/** WSCD 鍵に対応する `CredentialSigner`（ES256）。 */
export function wscdSigner(): CredentialSigner {
  return createPrivateKeySigner(WSCD_PRIVATE_KEY, 'ES256');
}

/** WUA JWT の payload クレーム（テスト上書き用）。 */
export interface WuaJwtPayload {
  iss?: string;
  sub?: string;
  vct?: string;
  iat?: number;
  exp?: number;
  cnf?: unknown;
}

/** `makeWuaJwt` の署名アルゴリズム / バインド鍵の切り替え。 */
export interface MakeWuaJwtOptions {
  /** JWS 署名アルゴリズム（既定 `ES256`）。 */
  alg?: 'ES256' | 'EdDSA';
  /** `cnf.jwk` に載せる公開鍵 JWK（既定は P-256 の WSCD 公開鍵）。 */
  cnfJwk?: PublicKeyJwk;
}

/**
 * `cnf.jwk = WSCD 公開鍵` にバインドした WUA JWT を、指定鍵で署名して生成する。
 *
 * @param signPrivateKey 署名に使う秘密鍵（Wallet Provider 相当）。
 * @param overrides payload の上書き。
 * @param options 署名アルゴリズムと `cnf.jwk` の切り替え。
 * @returns コンパクト JWS 形式の WUA JWT。
 */
export function makeWuaJwt(
  signPrivateKey: Uint8Array,
  overrides: WuaJwtPayload = {},
  options: MakeWuaJwtOptions = {},
): string {
  const alg = options.alg ?? 'ES256';
  const signer = createPrivateKeySigner(signPrivateKey, alg);
  const payload = {
    iss: 'https://wallet-provider.example.eu',
    sub: 'urn:uuid:550e8400-e29b-41d4-a716-446655440000',
    vct: WUA_VCT,
    iat: 1_712_345_678,
    exp: 1_712_432_078,
    cnf: { jwk: options.cnfJwk ?? toP256Jwk(WSCD_PRIVATE_KEY) },
    ...overrides,
  };
  const header = { alg, typ: 'wua+jwt' };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64urlnopad.encode(signature)}`;
}
