/**
 * 署名アルゴリズムのステータスを使った VC 検証ポリシーのテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - `applyAlgorithmStatusPolicy` の戻り値と例外を確認する（`recommended` / `acceptable` → 通常検証、
 *   `deprecated` / `sunset` → 警告フラグ `true`、`prohibited` → `VERIFY_ALGO_PROHIBITED`
 *   3019、未登録 `undefined` → 通常検証）。
 * - `verifyCredential` の配線: ES256 / ES256K / EdDSA（現行レジストリでは全て
 *   `recommended` / `acceptable`）で発行 → 検証すると `algorithmDeprecated: false` が返る
 *   （通常検証を壊していないことの回帰検知）。
 *
 * ES256 / ES256K / EdDSA のステータスはすべて `recommended` / `acceptable` のため、
 * 警告と拒否の分岐はポリシー関数に `AlgorithmStatus` を直接渡して検証する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getEd25519PublicKey } from '../../../keymanager/ed25519.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { applyAlgorithmStatusPolicy } from '../algorithm-policy.js';
import { issueCredential } from '../issue.js';
import type { CredentialAlg } from '../jws.js';
import { createPrivateKeySigner } from '../signer.js';
import type { VerifiableCredential } from '../vc.js';
import { verifyCredential } from '../verify.js';

describe('applyAlgorithmStatusPolicy はステータスに応じて検証を許可・警告・拒否する', () => {
  it.each([
    ['recommended', false],
    ['acceptable', false],
    ['deprecated', true],
    ['sunset', true],
  ] as const)('%s は algorithmDeprecated=%s を返す（拒否しない）', (status, expected) => {
    expect(applyAlgorithmStatusPolicy(status)).toBe(expected);
  });

  it('未登録（undefined）は通常検証として false を返す', () => {
    expect(applyAlgorithmStatusPolicy(undefined)).toBe(false);
  });

  it('prohibited は VERIFY_ALGO_PROHIBITED（3019）で拒否する', () => {
    expect(() => applyAlgorithmStatusPolicy('prohibited')).toThrow(VericertsError);
    try {
      applyAlgorithmStatusPolicy('prohibited');
      throw new Error('unreachable');
    } catch (error) {
      expect((error as VericertsError).code).toBe(ErrorCodes.VERIFY_ALGO_PROHIBITED);
      expect(ErrorCodes.VERIFY_ALGO_PROHIBITED).toBe('3019');
    }
  });
});

/** テスト用の固定秘密鍵。 */
const P256_KEY = new Uint8Array(32).fill(7);
const SECP_KEY = new Uint8Array(32).fill(9);
const ED_KEY = new Uint8Array(32).fill(5);

/** テスト用の固定現在時刻・発行/有効期限（2026-01-01T00:00:00Z 近傍）。 */
const NOW = 1_767_225_600;
const ISSUANCE = '2025-12-01T00:00:00Z';
const EXPIRATION = '2027-01-01T00:00:00Z';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toEcJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

/** Ed25519 公開鍵（32B）から OKP 公開鍵 JWK を構築する。 */
function toOkpJwk(pub: Uint8Array): PublicKeyJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(pub).toString('base64url') };
}

/** alg ごとの秘密鍵・公開鍵 JWK。 */
const FIXTURES: Record<CredentialAlg, { privateKey: Uint8Array; publicKeyJwk: PublicKeyJwk }> = {
  ES256: {
    privateKey: P256_KEY,
    publicKeyJwk: toEcJwk(getP256PublicKey(P256_KEY, false), 'P-256'),
  },
  ES256K: {
    privateKey: SECP_KEY,
    publicKeyJwk: toEcJwk(getSecp256k1PublicKey(SECP_KEY, false), 'secp256k1'),
  },
  EdDSA: { privateKey: ED_KEY, publicKeyJwk: toOkpJwk(getEd25519PublicKey(ED_KEY)) },
};

function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: ISSUANCE,
    expirationDate: EXPIRATION,
    id: 'urn:uuid:1234',
  };
}

describe.each<CredentialAlg>([
  'ES256',
  'ES256K',
  'EdDSA',
])('verifyCredential の配線（%s、現行レジストリは recommended / acceptable）', (alg) => {
  it('algorithmDeprecated: false で検証成功する', () => {
    const fx = FIXTURES[alg];
    const jwt = issueCredential(sampleVc(), createPrivateKeySigner(fx.privateKey, alg), {
      nowSeconds: NOW,
    });
    const result = verifyCredential(jwt, {
      key: { publicKeyJwk: fx.publicKeyJwk },
      nowSeconds: NOW,
    });
    expect(result.algorithmDeprecated).toBe(false);
  });
});
