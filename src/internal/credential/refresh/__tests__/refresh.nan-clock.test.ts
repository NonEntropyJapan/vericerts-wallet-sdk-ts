/**
 * `shouldRefresh` が非有限の `nowMs` で「更新不要」へ倒れないことの回帰テスト。
 *
 * `nowMs >= exp - threshold` は NaN で常に `false` になり、期限切れ間近・期限切れの VC を更新対象から
 * 外す（`refreshCredential` の `nowMs < …` 側は NaN で更新へ進むため、判定が食い違う）。
 * 判定不能は更新対象に倒す。修正前はこのテストが落ちる。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../vc/vc.js';
import { shouldRefresh } from '../refresh.js';

const NOW = Date.parse('2026-07-01T00:00:00Z');
const DAY = 86_400_000;
const vc = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'IdentityCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:holder' },
  issuanceDate: '2026-01-01T00:00:00Z',
  expirationDate: new Date(NOW - DAY).toISOString(), // 既に期限切れ
  id: 'urn:vc:old',
} as unknown as VerifiableCredential;
const policy = { vcType: 'IdentityCredential', autoRefresh: true };

describe('shouldRefresh: 非有限の nowMs', () => {
  it('有限時刻では期限切れ VC を更新対象にする', () => {
    expect(shouldRefresh(vc, policy, NOW)).toBe(true);
  });

  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    it(`nowMs = ${bad}: 更新対象（true）に倒す`, () => {
      expect(shouldRefresh(vc, policy, bad)).toBe(true);
    });
  }
});
