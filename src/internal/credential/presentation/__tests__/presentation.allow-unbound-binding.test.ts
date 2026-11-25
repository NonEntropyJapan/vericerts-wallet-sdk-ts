/**
 * `verifyPresentation` の未バインドモード（`allowUnbound: true`）でも、呼び出し側が指定した
 * `expectedAudience` / `expectedNonce` は照合されることの回帰テスト。
 *
 * `vp-claims.ts` の unbound 分岐の `aud` 照合を外しても既存テストが通っていた（リプレイ対策の
 * `aud` 拘束が検出されずに壊せる）。不一致 → 3012、一致 → valid、未指定 → 照合しない、を固定する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { issuePresentation } from '../issue.js';
import { verifyPresentation } from '../presentation.js';
import { FIXTURES, sampleVp, signerFor } from './presentation.fixtures.js';

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const AUDIENCE = 'https://verifier.example.com';
const NONCE = 'n-0S6_WzA2Mj';
const key = { publicKeyJwk: FIXTURES.ES256.jwk };

const jwt = issuePresentation(sampleVp(), signerFor('ES256'), {
  nowSeconds: NOW,
  audience: AUDIENCE,
  nonce: NONCE,
});

const mismatch = new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);

describe('verifyPresentation allowUnbound: 指定された期待値は照合する', () => {
  it('expectedAudience 不一致は 3012', () => {
    expect(() =>
      verifyPresentation(jwt, {
        key,
        allowUnbound: true,
        expectedAudience: 'https://attacker.example.com',
        nowSeconds: NOW,
      }),
    ).toThrow(mismatch);
  });

  it('expectedNonce 不一致は 3012', () => {
    expect(() =>
      verifyPresentation(jwt, {
        key,
        allowUnbound: true,
        expectedNonce: 'wrong-nonce',
        nowSeconds: NOW,
      }),
    ).toThrow(mismatch);
  });

  it('expectedAudience / expectedNonce が一致すれば受理される', () => {
    const verified = verifyPresentation(jwt, {
      key,
      allowUnbound: true,
      expectedAudience: AUDIENCE,
      expectedNonce: NONCE,
      nowSeconds: NOW,
    });
    expect(verified.payload.aud).toBe(AUDIENCE);
  });

  it('期待値を指定しなければ照合しない（unbound の既定）', () => {
    expect(() =>
      verifyPresentation(jwt, { key, allowUnbound: true, nowSeconds: NOW }),
    ).not.toThrow();
  });
});
