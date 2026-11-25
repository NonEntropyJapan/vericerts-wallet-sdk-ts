/**
 * evaluateTrust の 3 層統合信頼判定ユニットテスト。
 */

import { describe, expect, it } from 'bun:test';
import { evaluateTrust } from '../evaluate.js';
import type { CachedTrustDecision, LayerVerdict } from '../trust-decision-types.js';

const SUBJECT = 'https://issuer.example.eu';
const NOW = 1_700_000_000_000;

function verdicts(...vs: LayerVerdict[]): LayerVerdict[] {
  return vs;
}

describe('evaluateTrust: 優先順位（複数 Layer で一致）', () => {
  it('TSL PASS を最優先で採用する（TSL > OIDF > ARF）', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts(
        { layer: 'tsl', status: 'pass' },
        { layer: 'oidf', status: 'pass' },
        { layer: 'arf', status: 'pass' },
      ),
      nowMs: NOW,
    });
    expect(d.code).toBe('tsl-qualified');
    expect(d.layer).toBe('tsl');
    expect(d.warnings).toEqual([]);
    expect(d.requiresRevalidation).toBe(false);
  });

  it('TSL 該当なし・OIDF/ARF PASS なら OIDF を採用する', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts(
        { layer: 'tsl', status: 'not-found' },
        { layer: 'oidf', status: 'pass' },
        { layer: 'arf', status: 'pass' },
      ),
      nowMs: NOW,
    });
    expect(d.code).toBe('oidf-federated');
    expect(d.layer).toBe('oidf');
  });
});

describe('evaluateTrust: 上位で該当なし・下位で PASS', () => {
  it('TSL/OIDF 該当なし・ARF PASS なら ARF を採用する', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts(
        { layer: 'tsl', status: 'not-found' },
        { layer: 'oidf', status: 'not-found' },
        { layer: 'arf', status: 'pass' },
      ),
      nowMs: NOW,
    });
    expect(d.code).toBe('arf-listed');
    expect(d.layer).toBe('arf');
  });

  it('未指定の上位層は該当なしとして扱い、指定された下位 PASS を採用する', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'arf', status: 'pass' }),
      nowMs: NOW,
    });
    expect(d.code).toBe('arf-listed');
    expect(d.layer).toBe('arf');
  });
});

describe('evaluateTrust: 上位で PASS・下位で REVOKED', () => {
  it('上位を優先しつつ警告と再検証フラグを立てる', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'tsl', status: 'pass' }, { layer: 'arf', status: 'revoked' }),
      nowMs: NOW,
    });
    expect(d.code).toBe('tsl-qualified');
    expect(d.layer).toBe('tsl');
    expect(d.warnings).toContain('lower-layer-revoked');
    expect(d.requiresRevalidation).toBe(true);
  });
});

describe('evaluateTrust: 上位 REVOKED による明示的拒否（fail-closed）', () => {
  it('上位権威層 REVOKED・下位 PASS では下位を採用せず明示的に拒否する', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'tsl', status: 'revoked' }, { layer: 'oidf', status: 'pass' }),
      nowMs: NOW,
    });
    // fail-closed（選択肢B）: 下位 PASS を採用しない。旧挙動（下位 PASS を警告付きで採用）からの
    // 回帰防止テスト。
    expect(d.code).toBe('rejected');
    expect(d.layer).toBe('tsl');
    expect(d.warnings).toContain('higher-layer-revoked');
  });

  it('上位 REVOKED・さらに下位（2 段下）の PASS も採用せず拒否する', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'tsl', status: 'revoked' }, { layer: 'arf', status: 'pass' }),
      nowMs: NOW,
    });
    expect(d.code).toBe('rejected');
    expect(d.layer).toBe('tsl');
    expect(d.warnings).toContain('higher-layer-revoked');
  });

  it('採用され得た層より上位に REVOKED があれば、さらに下位が REVOKED でも拒否（最上位の REVOKED 層を報告）', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts(
        { layer: 'tsl', status: 'revoked' },
        { layer: 'oidf', status: 'pass' },
        { layer: 'arf', status: 'revoked' },
      ),
      nowMs: NOW,
    });
    expect(d.code).toBe('rejected');
    expect(d.layer).toBe('tsl');
    expect(d.warnings).toContain('higher-layer-revoked');
  });

  it('PASS が 1 つも無くても REVOKED があれば UNKNOWN ではなく明示的に拒否する', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'tsl', status: 'revoked' }),
      cached: { code: 'tsl-qualified', layer: 'tsl', decidedAtMs: NOW - 1000 },
      nowMs: NOW,
    });
    // 全層 error ではない（revoked が確定）ので stale へ倒さず、かつ UNKNOWN でもなく rejected。
    expect(d.code).toBe('rejected');
    expect(d.layer).toBe('tsl');
    expect(d.requiresRevalidation).toBe(false);
  });

  it('REVOKED が最下位（ARF）のみで、より上位に PASS も REVOKED も無ければ拒否する', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'arf', status: 'revoked' }),
      nowMs: NOW,
    });
    expect(d.code).toBe('rejected');
    expect(d.layer).toBe('arf');
  });
});

describe('evaluateTrust: 全 Layer で該当なし → UNKNOWN', () => {
  it('全層 not-found なら UNKNOWN + ユーザー同意警告', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts(
        { layer: 'tsl', status: 'not-found' },
        { layer: 'oidf', status: 'not-found' },
        { layer: 'arf', status: 'not-found' },
      ),
      nowMs: NOW,
    });
    expect(d.code).toBe('unknown');
    expect(d.layer).toBeUndefined();
    expect(d.warnings).toContain('unknown-requires-consent');
    expect(d.requiresRevalidation).toBe(false);
  });

  it('verdicts が空でも UNKNOWN', () => {
    const d = evaluateTrust({ subjectId: SUBJECT, verdicts: [], nowMs: NOW });
    expect(d.code).toBe('unknown');
  });

  // REVOKED が 1 つでもある場合は UNKNOWN ではなく `rejected` になる
  // （「evaluateTrust: 上位 REVOKED による明示的拒否」ブロック参照）。
});

describe('evaluateTrust: オフライン（Stale-If-Error）', () => {
  const cached: CachedTrustDecision = {
    code: 'tsl-qualified',
    layer: 'tsl',
    decidedAtMs: NOW - 60 * 60 * 1000, // 1h 前
  };

  it('全層 error かつ grace period 内ならキャッシュ判定を stale として採用', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts(
        { layer: 'tsl', status: 'error' },
        { layer: 'oidf', status: 'error' },
        { layer: 'arf', status: 'error' },
      ),
      cached,
      nowMs: NOW,
    });
    expect(d.code).toBe('stale');
    expect(d.layer).toBe('tsl');
    expect(d.warnings).toContain('stale-fallback');
    expect(d.requiresRevalidation).toBe(true);
  });

  it('全層未指定（取得すら試みていない）でもキャッシュがあれば stale', () => {
    const d = evaluateTrust({ subjectId: SUBJECT, verdicts: [], cached, nowMs: NOW });
    expect(d.code).toBe('stale');
  });

  it('grace period 超過のキャッシュは採用せず UNKNOWN', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'tsl', status: 'error' }),
      cached: { ...cached, decidedAtMs: NOW - 73 * 60 * 60 * 1000 },
      nowMs: NOW,
    });
    expect(d.code).toBe('unknown');
  });

  it('未来時刻のキャッシュ（時計不整合）は信頼せず UNKNOWN', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'tsl', status: 'error' }),
      cached: { ...cached, decidedAtMs: NOW + 1000 },
      nowMs: NOW,
    });
    expect(d.code).toBe('unknown');
  });

  it('キャッシュがなければ全層 error でも UNKNOWN', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'tsl', status: 'error' }),
      nowMs: NOW,
    });
    expect(d.code).toBe('unknown');
  });

  it('offline でも 1 層でも PASS があればそれを採用（error より PASS 優先）', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'tsl', status: 'error' }, { layer: 'oidf', status: 'pass' }),
      cached,
      nowMs: NOW,
    });
    expect(d.code).toBe('oidf-federated');
  });

  it('カスタム grace period を尊重する', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'tsl', status: 'error' }),
      cached: { ...cached, decidedAtMs: NOW - 2 * 60 * 60 * 1000 },
      gracePeriodMs: 60 * 60 * 1000, // 1h
      nowMs: NOW,
    });
    expect(d.code).toBe('unknown');
  });
});

describe('evaluateTrust: 決定性・入力正規化', () => {
  it('同一層の重複指定は最初の要素を採用する', () => {
    const d = evaluateTrust({
      subjectId: SUBJECT,
      verdicts: verdicts({ layer: 'tsl', status: 'not-found' }, { layer: 'tsl', status: 'pass' }),
      nowMs: NOW,
    });
    // 最初の not-found を採用 → TSL は PASS 扱いにならない。
    expect(d.code).toBe('unknown');
  });

  it('nowMs を省略しても decidedAtMs が設定される', () => {
    const before = Date.now();
    const d = evaluateTrust({ subjectId: SUBJECT, verdicts: [] });
    expect(d.decidedAtMs).toBeGreaterThanOrEqual(before);
  });
});
