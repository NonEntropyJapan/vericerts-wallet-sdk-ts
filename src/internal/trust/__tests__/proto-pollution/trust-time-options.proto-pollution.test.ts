/**
 * Trust 層の時刻・TTL オプションの `Object.prototype` 汚染耐性テスト。
 *
 * `now` / `nowMs` / `maxDepth` / `maxTtlSeconds` / `maxAgeSeconds` / `gracePeriodMs` を
 * プロトタイプ鎖で読むと、これらを**省略した**正当な評価でも汚染値が採用され、
 *
 * - 証明書チェーンの有効期間検証が攻撃者の選んだ時刻で行われる（期限切れ証明書の受理）、
 * - チェーン深さの上限が緩む、
 * - 失効ステータスのキャッシュ TTL が伸び、TTL 超過のキャッシュが「新鮮」と判定される、
 * - Stale-If-Error の grace period が伸び、期限切れのキャッシュ判定が採用される、
 *
 * といった形で有効期限・鮮度の検証が無効化される。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { evaluateCacheFreshness } from '../../../issuer/status-list-verifier.js';
import { evaluateTrust } from '../../arf/evaluate.js';
import type { CachedTrustDecision } from '../../arf/trust-decision-types.js';

const NOW = 1_767_225_600;

describe('Status List キャッシュ TTL の汚染耐性', () => {
  it('継承した maxTtlSeconds は TTL 上限を広げない', () => {
    // 既定上限は 60 秒。取得から 100 秒経過したキャッシュは期限切れ。
    const result = withPollutedPrototype({ maxTtlSeconds: 100_000 }, () =>
      evaluateCacheFreshness({ fetchedAtSeconds: NOW - 100, nowSeconds: NOW }),
    );
    expect(result.fresh).toBe(false);
    expect(result.remainingSeconds).toBe(0);
  });

  it('継承した maxAgeSeconds は実効 TTL を広げない', () => {
    const result = withPollutedPrototype({ maxAgeSeconds: 100_000 }, () =>
      evaluateCacheFreshness({ fetchedAtSeconds: NOW - 100, nowSeconds: NOW }),
    );
    expect(result.fresh).toBe(false);
  });

  it('継承した expSeconds は Token 失効による切り詰めを狂わせない', () => {
    // 取得直後・上限 60 秒 → 本来は fresh（残り 60 秒）。
    const result = withPollutedPrototype({ expSeconds: NOW - 1 }, () =>
      evaluateCacheFreshness({ fetchedAtSeconds: NOW, nowSeconds: NOW }),
    );
    expect(result.fresh).toBe(true);
    expect(result.effectiveTtlSeconds).toBe(60);
  });

  it('明示的に渡した maxTtlSeconds / maxAgeSeconds は従来どおり効く（正常系）', () => {
    const widened = evaluateCacheFreshness({
      fetchedAtSeconds: NOW - 100,
      nowSeconds: NOW,
      maxTtlSeconds: 600,
    });
    expect(widened.fresh).toBe(true);

    const capped = evaluateCacheFreshness({
      fetchedAtSeconds: NOW,
      nowSeconds: NOW,
      maxAgeSeconds: 10,
    });
    expect(capped.effectiveTtlSeconds).toBe(10);
  });
});

describe('ARF Stale-If-Error の汚染耐性', () => {
  const cached: CachedTrustDecision = {
    code: 'tsl-qualified',
    layer: 'tsl',
    decidedAtMs: NOW * 1000 - 100 * 60 * 60 * 1000, // 100 時間前（既定 grace 72h を超過）
  };

  it('継承した gracePeriodMs は grace period を伸ばさない', () => {
    const decision = withPollutedPrototype({ gracePeriodMs: 1_000 * 60 * 60 * 24 * 365 }, () =>
      evaluateTrust({
        subjectId: 'did:example:issuer',
        verdicts: [],
        cached,
        nowMs: NOW * 1000,
      }),
    );
    // grace period 超過のキャッシュは stale として採用しない（fail-closed）。
    expect(decision.code).not.toBe('stale');
  });

  it('継承した cached はキャッシュ判定として採用しない', () => {
    const fresh: CachedTrustDecision = {
      code: 'tsl-qualified',
      layer: 'tsl',
      decidedAtMs: NOW * 1000 - 1000,
    };
    const decision = withPollutedPrototype({ cached: fresh }, () =>
      // cached は渡していない。汚染値を拾えば攻撃者の判定が stale として採用される。
      evaluateTrust({ subjectId: 'did:example:issuer', verdicts: [], nowMs: NOW * 1000 }),
    );
    expect(decision.code).not.toBe('stale');
  });

  it('継承した nowMs は grace period の経過判定に使わない', () => {
    // 汚染値を拾えば「キャッシュ直後」に見えて stale 採用されてしまう。
    const decision = withPollutedPrototype({ nowMs: cached.decidedAtMs }, () =>
      evaluateTrust({ subjectId: 'did:example:issuer', verdicts: [], cached }),
    );
    expect(decision.code).not.toBe('stale');
  });

  it('grace period 内のキャッシュは従来どおり stale として採用される（正常系）', () => {
    const recent: CachedTrustDecision = {
      code: 'tsl-qualified',
      layer: 'tsl',
      decidedAtMs: NOW * 1000 - 1000,
    };
    const decision = evaluateTrust({
      subjectId: 'did:example:issuer',
      verdicts: [],
      cached: recent,
      nowMs: NOW * 1000,
    });
    expect(decision.code).toBe('stale');
  });
});
