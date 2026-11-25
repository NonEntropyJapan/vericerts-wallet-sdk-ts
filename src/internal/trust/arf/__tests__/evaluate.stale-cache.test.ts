/**
 * evaluateTrust の Stale-If-Error がキャッシュ済み判定の種別を保つことの回帰テスト。
 */

import { describe, expect, it } from 'bun:test';
import { evaluateTrust } from '../evaluate.js';
import type { CachedTrustDecision, LayerVerdict, TrustLayer } from '../trust-decision-types.js';

const SUBJECT = 'https://issuer.example.eu';
const NOW = 1_700_000_000_000;

function verdicts(...vs: LayerVerdict[]): LayerVerdict[] {
  return vs;
}

const cached: CachedTrustDecision = {
  code: 'tsl-qualified',
  layer: 'tsl',
  decidedAtMs: NOW - 60 * 60 * 1000, // 1h 前
};

describe('evaluateTrust: Stale-If-Error はキャッシュ済み判定の種別を保つ', () => {
  const allError = verdicts(
    { layer: 'tsl', status: 'error' },
    { layer: 'oidf', status: 'error' },
    { layer: 'arf', status: 'error' },
  );
  const decide = (c: CachedTrustDecision) =>
    evaluateTrust({ subjectId: SUBJECT, verdicts: allError, cached: c, nowMs: NOW });

  it('cached.rejected は stale に化けず rejected のまま（layer も保つ）', () => {
    const d = decide({ ...cached, code: 'rejected' });
    expect(d.code).toBe('rejected');
    expect(d.layer).toBe('tsl');
    expect(d.warnings).not.toContain('stale-fallback');
  });

  it('cached.rejected は grace period を超えても unknown へ緩めない', () => {
    const d = decide({ code: 'rejected', layer: 'tsl', decidedAtMs: NOW - 100 * 60 * 60 * 1000 });
    expect(d.code).toBe('rejected');
  });

  it.each(['unknown', 'stale'] as const)('cached.%s は stale にせず unknown', (code) => {
    const d = decide({ code, layer: 'tsl', decidedAtMs: cached.decidedAtMs });
    expect(d.code).toBe('unknown');
    expect(d.layer).toBeUndefined();
  });

  it('layer の無い PASS・層と食い違う PASS・未知のコードは unknown', () => {
    expect(decide({ code: 'tsl-qualified', decidedAtMs: cached.decidedAtMs }).code).toBe('unknown');
    expect(decide({ code: 'arf-listed', layer: 'tsl', decidedAtMs: cached.decidedAtMs }).code).toBe(
      'unknown',
    );
    expect(
      decide({ code: 'bogus' as never, layer: 'tsl', decidedAtMs: cached.decidedAtMs }).code,
    ).toBe('unknown');
  });

  it('PASS 系 3 種はそれぞれ stale になり、元の判定時刻を staleSinceMs に保つ', () => {
    for (const [code, layer] of [
      ['tsl-qualified', 'tsl'],
      ['oidf-federated', 'oidf'],
      ['arf-listed', 'arf'],
    ] as const) {
      const d = decide({ code, layer, decidedAtMs: cached.decidedAtMs });
      expect(d.code).toBe('stale');
      expect(d.layer).toBe(layer);
      expect(d.staleSinceMs).toBe(cached.decidedAtMs);
      expect(d.decidedAtMs).toBe(NOW);
    }
  });

  it('stale を再キャッシュして渡しても grace は延びない（unknown に落ちる）', () => {
    const first = decide(cached);
    expect(first.code).toBe('stale');
    const second = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: allError,
      cached: {
        code: first.code,
        layer: first.layer as TrustLayer,
        decidedAtMs: first.decidedAtMs,
      },
      nowMs: NOW + 1000,
    });
    expect(second.code).toBe('unknown');
  });
});
