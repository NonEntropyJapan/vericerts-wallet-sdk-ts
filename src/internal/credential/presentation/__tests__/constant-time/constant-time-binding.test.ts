/**
 * JWT-VP の `aud` / `nonce` 照合と DPoP proof の `nonce` 照合が共有の定数時間比較
 * （`internal/timing-safe.ts` の `timingSafeEqualString`）を経由することの回帰テスト。
 *
 * `nonce`、`aud`、`client_id` の照合にはいずれも定数時間比較を使う。
 * 素の `!==` は最初の不一致で早期 return するため、経路ごとに保護水準が割れていた。実時間差は
 * テストで安定して測れないので、共有実装への委譲回数（比較対象の組）を観測して固定する。
 */

import { beforeEach, describe, expect, it, mock } from 'bun:test';

// `mock.module` は対象モジュールを読み込む前に登録する必要があるため、被テスト側は動的 import で読む。
// `mock.module` は名前空間オブジェクトを書き換えるため、差し替え前に実体をコピーして保持する。
const realTimingSafe = { ...(await import('../../../../timing-safe.js')) };
const comparisons: Array<[string, string]> = [];

mock.module('../../../../timing-safe.js', () => ({
  ...realTimingSafe,
  timingSafeEqualString: (a: string, b: string): boolean => {
    comparisons.push([a, b]);
    return realTimingSafe.timingSafeEqualString(a, b);
  },
}));

const { createDpopProof } = await import('../../../../auth/dpop/dpop.js');
const { verifyDpopProof } = await import('../../../../auth/dpop/dpop-verify.js');
const { createPrivateKeySigner } = await import('../../../../credential/vc/signer.js');
const { ErrorCodes, VericertsError } = await import('../../../../errors.js');
const { issuePresentation } = await import('../../issue.js');
const { verifyPresentation } = await import('../../presentation.js');
const { FIXTURES, sampleVp, signerFor } = await import('../presentation.fixtures.js');

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const AUDIENCE = 'https://verifier.example.com';
const NONCE = 'n-0S6_WzA2Mj';
const key = { publicKeyJwk: FIXTURES.ES256.jwk };

beforeEach(() => {
  comparisons.length = 0;
});

describe('verifyPresentation の aud / nonce は定数時間比較を経由する', () => {
  const jwt = issuePresentation(sampleVp(), signerFor('ES256'), {
    nowSeconds: NOW,
    audience: AUDIENCE,
    nonce: NONCE,
  });

  it('既定（束縛必須）: aud と nonce の両方が共有実装で比較される', () => {
    verifyPresentation(jwt, {
      key,
      expectedAudience: AUDIENCE,
      expectedNonce: NONCE,
      nowSeconds: NOW,
    });
    expect(comparisons).toContainEqual([AUDIENCE, AUDIENCE]);
    expect(comparisons).toContainEqual([NONCE, NONCE]);
  });

  it('allowUnbound でも指定した期待値は共有実装で比較され、不一致は 3012', () => {
    expect(() =>
      verifyPresentation(jwt, {
        key,
        allowUnbound: true,
        expectedAudience: AUDIENCE,
        expectedNonce: 'n-0S6_WzA2MX',
        nowSeconds: NOW,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
    expect(comparisons).toContainEqual([NONCE, 'n-0S6_WzA2MX']);
  });
});

describe('verifyDpopProof の nonce は定数時間比較を経由する', () => {
  const signer = createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256');
  const base = { htm: 'POST', htu: 'https://api.example.com/mcp', nowSeconds: NOW } as const;

  it('nonce が共有実装で比較され、先頭 / 末尾いずれの不一致も同じ 4086', () => {
    const proof = createDpopProof(
      { ...base, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nonce: 'dpop-nonce-xyz' },
      signer,
    );
    verifyDpopProof(proof, { ...base, nonce: 'dpop-nonce-xyz' });
    expect(comparisons).toContainEqual(['dpop-nonce-xyz', 'dpop-nonce-xyz']);

    for (const expected of ['Xpop-nonce-xyz', 'dpop-nonce-xyX']) {
      expect(() => verifyDpopProof(proof, { ...base, nonce: expected })).toThrow(
        new VericertsError(ErrorCodes.DPOP_NONCE_REQUIRED),
      );
    }
  });
});
