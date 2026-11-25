/**
 * vc-verify カテゴリのコンフォーマンスベクタ（SD-JWT VC 部分）。
 * 開示クレーム用の salt は固定値を使い、検証では生成済みの token を再利用する。
 */

import { createSdJwt } from '../../src/internal/credential/sdjwt/sdjwt.js';
import { verifySdJwt } from '../../src/internal/credential/sdjwt/verify.js';
import { createPrivateKeySigner } from '../../src/internal/credential/vc/signer.js';
import type { Case } from './shared.js';
import { errorCodeOf } from './shared.js';

const NOW = 1_767_225_600; // 2026-01-01T00:00:00Z
const PAST_EXPIRATION = '2025-12-15T00:00:00Z'; // before NOW -> expired

export function getSdJwtCases(): Case[] {
  const cases: Case[] = [];
  const edPriv = new Uint8Array(32).fill(13);
  const signer = createPrivateKeySigner(edPriv, 'EdDSA');

  const validSdJwt = createSdJwt(signer, {
    vct: 'https://example.com/credentials/conformance',
    disclosureClaims: ['name', 'email'],
    claims: { name: 'Conformance Test', email: 'test@example.com', role: 'tester' },
    nowSeconds: NOW - 1000,
    salts: { name: 'AAAAAAAAAAAAAAAAAAAAAA', email: 'BBBBBBBBBBBBBBBBBBBBBB' },
  });
  cases.push({
    id: 'sd-jwt-vc-verify-valid-with-disclosures',
    category: 'vc-verify',
    description: 'SD-JWT VC (EdDSA) verifies successfully and recovers disclosed claims',
    input: {
      format: 'sd-jwt-vc',
      token: validSdJwt,
      issuerPublicKeyJwk: signer.publicKeyJwk,
      nowSeconds: NOW,
    },
    expected: {
      ok: true,
      claims: { name: 'Conformance Test', email: 'test@example.com', role: 'tester' },
    },
  });

  const expiredSdJwt = createSdJwt(signer, {
    vct: 'https://example.com/credentials/conformance',
    disclosureClaims: ['name'],
    claims: {
      name: 'Conformance Test',
      exp: Math.floor(new Date(PAST_EXPIRATION).getTime() / 1000),
    },
    nowSeconds: NOW - 2000,
    salts: { name: 'CCCCCCCCCCCCCCCCCCCCCC' },
  });
  cases.push({
    id: 'sd-jwt-vc-verify-expired',
    category: 'vc-verify',
    description: 'SD-JWT VC rejects a credential past its exp',
    input: {
      format: 'sd-jwt-vc',
      token: expiredSdJwt,
      issuerPublicKeyJwk: signer.publicKeyJwk,
      nowSeconds: NOW,
    },
    expected: {
      ok: false,
      errorCode: errorCodeOf(() =>
        verifySdJwt(expiredSdJwt, { issuerKey: signer.publicKeyJwk, nowSeconds: NOW }),
      ),
    },
  });

  return cases;
}
