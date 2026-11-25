/**
 * 別ベンダーコンテナ取り込みテストの共通フィクスチャ。
 *
 * SD-JWT VC は**実鍵で実際に署名**して組み立てる（モック検証器は使わない）。「署名検証失敗は
 * 全体拒否」を検証するテストが、検証器を差し替えた偽物では意味を持たないため。
 */

import { createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import type { ImportForeignBackupDependencies } from '../import-foreign.js';

/** テスト用の固定 Issuer 秘密鍵（決定論的なテストのため乱数は使わない）。 */
const ISSUER_KEY = new Uint8Array(32).fill(23);

/** 同じ ES256（P-256）の別鍵。crv 不一致ではなく純粋な署名不一致を作るため。 */
const OTHER_ISSUER_KEY = new Uint8Array(32).fill(29);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

/** 正しい Issuer 公開鍵 JWK。 */
export const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));

/** 署名不一致を作るための別 Issuer 公開鍵 JWK。 */
export const OTHER_ISSUER_JWK = toJwk(getP256PublicKey(OTHER_ISSUER_KEY, false));

/** 秘匿クレームに入れる値（警告文への漏洩がないことを確認するための目印）。 */
export const SECRET_CLAIM_VALUE = 'Alice Tanaka';

/** 秘匿クレームに入れるメールアドレス（同上）。 */
export const SECRET_EMAIL = 'alice@example.com';

const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

/**
 * 実鍵で署名した SD-JWT VC を発行する。
 *
 * @param vct Verifiable Credential Type。
 * @returns SD-JWT のコンパクト表現。
 */
export function issueSdJwt(vct = 'https://example.com/credentials/identity'): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct,
    issuer: 'did:example:foreign-issuer',
    disclosureClaims: ['name', 'email'],
    claims: { name: SECRET_CLAIM_VALUE, email: SECRET_EMAIL, sub: 'did:example:holder' },
    salts: { name: 'salt-name', email: 'salt-email' },
    nowSeconds: 1_700_000_000,
  });
}

/**
 * Disclosure を改竄した SD-JWT VC を作る（digest 照合に失敗させる）。
 *
 * 署名そのものは正しいままなので「コンテナが壊れている」のではなく「エントリの暗号検証が
 * 失敗する」状況を作れる。
 */
export function tamperDisclosure(sdJwt: string): string {
  const parts = sdJwt.split('~');
  const [issuerJwt, firstDisclosure, ...rest] = parts;
  if (issuerJwt === undefined || firstDisclosure === undefined) {
    throw new Error('unexpected SD-JWT shape in fixture');
  }
  const forged = Buffer.from(JSON.stringify(['salt-name', 'name', 'Mallory'])).toString(
    'base64url',
  );
  return [issuerJwt, forged, ...rest].join('~');
}

/** 常に正しい Issuer 鍵を返す DI。 */
export const RESOLVE_ISSUER_KEY: ImportForeignBackupDependencies = {
  resolveIssuerKey: () => ISSUER_JWK,
};

/** コンテナ JSON 文字列を組み立てる（`importForeignBackup` は文字列しか受け取らない）。 */
export function containerJson(
  credentials: readonly { format: string; data: string; id?: string }[],
): string {
  return JSON.stringify({ credentials });
}
