/**
 * evaluateTrust の Stale-If-Error の grace 検査が非有限値・境界で fail-closed であることの
 * 回帰テスト。
 */

import { describe, expect, it } from 'bun:test';
import { evaluateTrust } from '../evaluate.js';
import type { CachedTrustDecision, LayerVerdict } from '../trust-decision-types.js';

const SUBJECT = 'https://issuer.example.eu';
const DECIDED_AT = 1000;
const GRACE_72H = 72 * 60 * 60 * 1000;
const cached: CachedTrustDecision = {
  code: 'tsl-qualified',
  layer: 'tsl',
  decidedAtMs: DECIDED_AT,
};
const tslError: LayerVerdict[] = [{ layer: 'tsl', status: 'error' }];

describe('evaluateTrust: stale フォールバックの grace 検査', () => {
  it('nowMs が NaN / Infinity なら stale を採らず unknown', () => {
    for (const nowMs of [Number.NaN, Number.POSITIVE_INFINITY]) {
      const d = evaluateTrust({ subjectId: SUBJECT, verdicts: tslError, cached, nowMs });
      expect(d.code).toBe('unknown');
    }
  });

  it('gracePeriodMs が NaN / Infinity なら期限を大きく超えていても stale を採らず unknown', () => {
    for (const gracePeriodMs of [Number.NaN, Number.POSITIVE_INFINITY]) {
      const d = evaluateTrust({
        subjectId: SUBJECT,
        verdicts: tslError,
        cached,
        nowMs: DECIDED_AT + 999 * 60 * 60 * 1000,
        gracePeriodMs,
      });
      expect(d.code).toBe('unknown');
    }
  });

  it('cached.decidedAtMs が NaN / Infinity なら unknown', () => {
    for (const decidedAtMs of [Number.NaN, Number.POSITIVE_INFINITY]) {
      const d = evaluateTrust({
        subjectId: SUBJECT,
        verdicts: tslError,
        cached: { ...cached, decidedAtMs },
        nowMs: DECIDED_AT + 1000,
      });
      expect(d.code).toBe('unknown');
    }
  });

  it('grace ちょうどは stale、1ms 超過は unknown（境界）', () => {
    const at = (nowMs: number) =>
      evaluateTrust({ subjectId: SUBJECT, verdicts: tslError, cached, nowMs }).code;
    expect(at(DECIDED_AT + GRACE_72H)).toBe('stale');
    expect(at(DECIDED_AT + GRACE_72H + 1)).toBe('unknown');
  });

  it('判定時刻ちょうど（age 0）は stale、1ms 未来のキャッシュは unknown', () => {
    const at = (nowMs: number) =>
      evaluateTrust({ subjectId: SUBJECT, verdicts: tslError, cached, nowMs }).code;
    expect(at(DECIDED_AT)).toBe('stale');
    expect(at(DECIDED_AT - 1)).toBe('unknown');
  });

  it('[tsl:error, oidf:not-found] のように確定状態が混在すれば stale にしない', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: [
        { layer: 'tsl', status: 'error' },
        { layer: 'oidf', status: 'not-found' },
      ],
      cached,
      nowMs: DECIDED_AT + 1000,
    });
    expect(d.code).toBe('unknown');
  });
});
