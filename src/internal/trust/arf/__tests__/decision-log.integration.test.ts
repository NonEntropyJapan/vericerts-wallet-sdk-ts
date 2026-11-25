/**
 * 統合信頼判定のログ記録 統合テスト。
 *
 * evaluateTrustWithLogging が evaluateTrust の判定を DI シンクへ機微情報なしで記録し、シンク失敗時も
 * fail-safe に判定を返すことを検証する。シンクは実際に呼ばれた順序・内容を記録するスパイで代替する。
 */

import { describe, expect, it } from 'bun:test';
import type { SdkWarning } from '../../../observability/warning.js';
import {
  evaluateTrustWithLogging,
  type TrustDecisionLogRecord,
  type TrustDecisionLogSink,
} from '../decision-log.js';
import type { LayerVerdict } from '../trust-decision-types.js';

const SUBJECT = 'https://issuer.example.eu';
const NOW = 1_700_000_000_000;

/** 記録内容を蓄積するスパイシンク。 */
function makeSpySink(): {
  sink: TrustDecisionLogSink;
  records: TrustDecisionLogRecord[];
} {
  const records: TrustDecisionLogRecord[] = [];
  return {
    records,
    sink: (record) => {
      records.push(record);
    },
  };
}

function verdicts(...vs: LayerVerdict[]): LayerVerdict[] {
  return vs;
}

describe('evaluateTrustWithLogging: 判定結果のログ記録', () => {
  it('PASS 判定をシンクへ記録し、同じ判定を返す', async () => {
    const { sink, records } = makeSpySink();
    const decision = await evaluateTrustWithLogging(
      {
        subjectId: SUBJECT,
        verdicts: verdicts({ layer: 'tsl', status: 'pass' }),
        nowMs: NOW,
      },
      sink,
    );

    expect(decision.code).toBe('tsl-qualified');
    expect(records).toHaveLength(1);
    expect(records[0]).toEqual({
      subjectId: SUBJECT,
      code: 'tsl-qualified',
      layer: 'tsl',
      warnings: [],
      requiresRevalidation: false,
      decidedAtMs: NOW,
    });
  });

  it('上位 PASS・下位 REVOKED の強い警告をログレコードに含める', async () => {
    const { sink, records } = makeSpySink();
    await evaluateTrustWithLogging(
      {
        subjectId: SUBJECT,
        verdicts: verdicts({ layer: 'tsl', status: 'pass' }, { layer: 'arf', status: 'revoked' }),
        nowMs: NOW,
      },
      sink,
    );

    expect(records[0]?.warnings).toContain('lower-layer-revoked');
    expect(records[0]?.requiresRevalidation).toBe(true);
  });

  it('UNKNOWN 判定でも layer を省略して記録する', async () => {
    const { sink, records } = makeSpySink();
    await evaluateTrustWithLogging({ subjectId: SUBJECT, verdicts: [], nowMs: NOW }, sink);

    expect(records[0]?.code).toBe('unknown');
    expect(records[0]?.layer).toBeUndefined();
    expect(records[0]?.warnings).toContain('unknown-requires-consent');
  });

  it('stale フォールバックのログを記録する', async () => {
    const { sink, records } = makeSpySink();
    await evaluateTrustWithLogging(
      {
        subjectId: SUBJECT,
        verdicts: verdicts({ layer: 'tsl', status: 'error' }),
        cached: { code: 'tsl-qualified', layer: 'tsl', decidedAtMs: NOW - 1000 },
        nowMs: NOW,
      },
      sink,
    );

    expect(records[0]?.code).toBe('stale');
    expect(records[0]?.warnings).toContain('stale-fallback');
  });
});

describe('evaluateTrustWithLogging: fail-safe', () => {
  it('同期シンクが throw しても判定は返る', async () => {
    const sink: TrustDecisionLogSink = () => {
      throw new Error('sink boom');
    };
    const decision = await evaluateTrustWithLogging(
      { subjectId: SUBJECT, verdicts: verdicts({ layer: 'oidf', status: 'pass' }), nowMs: NOW },
      sink,
    );
    expect(decision.code).toBe('oidf-federated');
  });

  it('非同期シンクが reject しても判定は返る', async () => {
    const sink: TrustDecisionLogSink = () => Promise.reject(new Error('async boom'));
    const decision = await evaluateTrustWithLogging(
      { subjectId: SUBJECT, verdicts: verdicts({ layer: 'arf', status: 'pass' }), nowMs: NOW },
      sink,
    );
    expect(decision.code).toBe('arf-listed');
  });

  it('非同期シンクの完了を待ってから判定を返す（記録漏れがない）', async () => {
    const records: TrustDecisionLogRecord[] = [];
    const sink: TrustDecisionLogSink = async (record) => {
      await Promise.resolve();
      records.push(record);
    };
    await evaluateTrustWithLogging(
      { subjectId: SUBJECT, verdicts: verdicts({ layer: 'tsl', status: 'pass' }), nowMs: NOW },
      sink,
    );
    expect(records).toHaveLength(1);
  });
});

describe('evaluateTrustWithLogging: シンク失敗の onWarning', () => {
  const input = {
    subjectId: SUBJECT,
    verdicts: verdicts({ layer: 'tsl', status: 'pass' } as LayerVerdict),
    nowMs: NOW,
  };
  const failingSink: TrustDecisionLogSink = () => {
    throw new Error('sink write failed');
  };

  it('シンクが失敗しても判定は返り、onWarning に失敗が届く', async () => {
    const warnings: SdkWarning[] = [];

    const decision = await evaluateTrustWithLogging(input, failingSink, (w) => warnings.push(w));

    expect(decision.code).toBe('tsl-qualified');
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({ code: 'trust.decision_log_failed', component: 'sdk.vc' });
    expect(warnings[0]?.attributes.error_message).toBe('sink write failed');
  });

  it('記録に成功したときは onWarning を呼ばない', async () => {
    const warnings: SdkWarning[] = [];

    await evaluateTrustWithLogging(input, makeSpySink().sink, (w) => warnings.push(w));

    expect(warnings).toEqual([]);
  });

  it('onWarning を指定しなければ従来どおり（判定は返り、何も出ない）', async () => {
    await expect(evaluateTrustWithLogging(input, failingSink)).resolves.toMatchObject({
      code: 'tsl-qualified',
    });
  });
});
