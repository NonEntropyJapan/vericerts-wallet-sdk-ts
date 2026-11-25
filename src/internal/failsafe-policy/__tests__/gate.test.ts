/**
 * Fail-open ゲート（`resolveFailOpen`）の単体テスト。
 *
 * 同意・監査記録・時間上限が Fail-open の可否に反映されることを確認する。
 *
 * 検証内容:
 * - 同意コールバックが無ければ Fail-open しない（既定 fail-secure）。
 * - 監査ログの記録先が無ければ Fail-open しない。
 * - 同意 / 不同意のいずれも監査ログへ記録される。
 * - `escalate` / 未知 ID は Fail-open を拒否し、Fail-open を選択していないため記録しない。
 * - 時間上限を超えると許可が取り消され、以降は取得成功（`clear`）まで許可されない。
 * - 監査レコードに `auditContext` が透過され、キー（URI）が混入しない。
 */

import { describe, expect, it } from 'bun:test';
import { resolveFailOpen } from '../gate.js';
import { createFailOpenWindow } from '../policy.js';
import type { FailOpenId, FailSafeAuditRecord, FailSafeDecision } from '../types.js';

const KEY = 'https://issuer.example/status/1';

/** 記録された監査レコードを溜める sink を作る。 */
function auditSink(): {
  records: FailSafeAuditRecord[];
  onPolicyEvent: (r: FailSafeAuditRecord) => void;
} {
  const records: FailSafeAuditRecord[] = [];
  return { records, onPolicyEvent: (r) => records.push(r) };
}

describe('resolveFailOpen', () => {
  it('同意コールバックが無ければ許可せず、rejected として記録する', async () => {
    const sink = auditSink();
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      onPolicyEvent: sink.onPolicyEvent,
    });
    expect(warning).toBeUndefined();
    expect(sink.records).toEqual([
      {
        policy_event: 'FO-1',
        audit_event: 'status_check_unreachable',
        user_consent: 'rejected',
        override: {},
      },
    ]);
  });

  it('同意が得られたら警告を返し、accepted として記録する', async () => {
    const sink = auditSink();
    const seen: FailSafeDecision[] = [];
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      requestConsent: (decision) => {
        seen.push(decision);
        return true;
      },
      onPolicyEvent: sink.onPolicyEvent,
    });
    expect(warning).toEqual({ policyEvent: 'FO-1', auditEvent: 'status_check_unreachable' });
    expect(seen).toEqual([
      {
        policyEvent: 'FO-1',
        severity: 'warn',
        auditEvent: 'status_check_unreachable',
        promptRequired: true,
      },
    ]);
    expect(sink.records[0]?.user_consent).toBe('accepted');
  });

  it('同意コールバックが Promise を返す場合も待ち合わせる', async () => {
    const warning = await resolveFailOpen({
      policyEvent: 'FO-2',
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      requestConsent: async () => true,
      onPolicyEvent: auditSink().onPolicyEvent,
    });
    expect(warning).toEqual({ policyEvent: 'FO-2', auditEvent: 'status_list_stale' });
  });

  it('同意が拒否されたら許可せず、rejected として記録する', async () => {
    const sink = auditSink();
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      requestConsent: () => false,
      onPolicyEvent: sink.onPolicyEvent,
    });
    expect(warning).toBeUndefined();
    expect(sink.records[0]?.user_consent).toBe('rejected');
  });

  it('suppressPrompt なら同意コールバック無しでも許可する', async () => {
    const sink = auditSink();
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      policy: { suppressPrompt: ['FO-1'] },
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      onPolicyEvent: sink.onPolicyEvent,
    });
    expect(warning).toEqual({ policyEvent: 'FO-1', auditEvent: 'status_check_unreachable' });
    expect(sink.records[0]).toEqual({
      policy_event: 'FO-1',
      audit_event: 'status_check_unreachable',
      user_consent: 'accepted',
      override: { suppressPrompt: ['FO-1'] },
    });
  });

  it('escalate では許可せず、同意コールバックも監査記録も呼ばれない', async () => {
    const sink = auditSink();
    let consentCalls = 0;
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      policy: { escalate: ['FO-1'] },
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      requestConsent: () => {
        consentCalls += 1;
        return true;
      },
      onPolicyEvent: sink.onPolicyEvent,
    });
    expect(warning).toBeUndefined();
    expect(consentCalls).toBe(0);
    expect(sink.records).toEqual([]);
  });

  // 回帰: 上限超過の直後に新しいウィンドウが開いていたため、失敗が続く限り 60 秒ごとに 1 回
  // 拒否するだけで Fail-open が無期限に継続していた。
  it('時間上限を超えると同意済みでも許可しなくなり、取得成功まで許可されない', async () => {
    const window = createFailOpenWindow(60);
    const sink = auditSink();
    const params = {
      policyEvent: 'FO-1',
      policy: { suppressPrompt: ['FO-1'] },
      window,
      key: KEY,
      onPolicyEvent: sink.onPolicyEvent,
    } as const;
    expect(await resolveFailOpen({ ...params, nowSeconds: 1_000 })).toBeDefined();
    expect(await resolveFailOpen({ ...params, nowSeconds: 1_060 })).toBeDefined();
    expect(await resolveFailOpen({ ...params, nowSeconds: 1_061 })).toBeUndefined();
    // 超過後は再試行しても許可されない（新しいウィンドウを開かない）。
    expect(await resolveFailOpen({ ...params, nowSeconds: 1_061 })).toBeUndefined();
    expect(await resolveFailOpen({ ...params, nowSeconds: 2_000 })).toBeUndefined();
    // 取得成功（clear）で初めて次のウィンドウが開く。
    window.clear(KEY);
    expect(await resolveFailOpen({ ...params, nowSeconds: 2_000 })).toBeDefined();
  });

  it('監査レコードに auditContext がそのまま入り、キー（URI）は含まれない', async () => {
    const sink = auditSink();
    await resolveFailOpen({
      policyEvent: 'FO-1',
      policy: { suppressPrompt: ['FO-1'] },
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      onPolicyEvent: sink.onPolicyEvent,
      auditContext: { verifier: 'sha256:rp', vc_id: 'vc-1', trace_id: 'trace-1' },
    });
    const record = sink.records[0];
    expect(record?.verifier).toBe('sha256:rp');
    expect(record?.vc_id).toBe('vc-1');
    expect(record?.trace_id).toBe('trace-1');
    expect(JSON.stringify(record)).not.toContain(KEY);
  });

  // 回帰: 記録先が optional だったため、記録先を渡さないと監査レコードを 1 件も残さないまま
  // Fail-open で通過していた。
  it('監査記録先が未指定なら Fail-open せず、同意も求めず時間上限も消費しない', async () => {
    const window = createFailOpenWindow(60);
    let consentCalls = 0;
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      policy: { suppressPrompt: ['FO-1'] },
      window,
      key: KEY,
      nowSeconds: 1_000,
      requestConsent: () => {
        consentCalls += 1;
        return true;
      },
    });
    expect(warning).toBeUndefined();
    expect(consentCalls).toBe(0);
    // ウィンドウは開始していない（記録先を渡した最初の呼び出しが起点になる）。
    expect(window.allow(KEY, 5_000)).toBe(true);
  });

  it.each([
    [
      '同期 throw',
      () => {
        throw new Error('ui crashed');
      },
    ],
    ['Promise reject', () => Promise.reject(new Error('ui rejected'))],
  ])('同意コールバックが%sしても例外を伝播せず、undefined と rejected 記録 1 件を返す', async (_name, requestConsent) => {
    const sink = auditSink();
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      requestConsent,
      onPolicyEvent: sink.onPolicyEvent,
    });
    expect(warning).toBeUndefined();
    expect(sink.records).toHaveLength(1);
    expect(sink.records[0]?.user_consent).toBe('rejected');
  });

  it('監査記録に失敗したら Fail-open しない（記録は省略不可）', async () => {
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      policy: { suppressPrompt: ['FO-1'] },
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      onPolicyEvent: () => {
        throw new Error('storage unavailable');
      },
    });
    expect(warning).toBeUndefined();
  });

  it('記録先が Promise を返す場合は解決を待ってから通過させる', async () => {
    const records: FailSafeAuditRecord[] = [];
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      policy: { suppressPrompt: ['FO-1'] },
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      onPolicyEvent: async (r) => {
        await Promise.resolve();
        records.push(r);
      },
    });
    expect(warning).toBeDefined();
    // 通過を返す時点で記録が完了している。
    expect(records).toHaveLength(1);
  });

  /**
   * 監査レコードの判定部分は `auditContext` で上書きできない（回帰テスト）。
   *
   * 監査ログは「どう判定したか」の記録であり、呼び出し側が渡す付随情報（相関 ID 等）に
   * 判定を書き換えさせてはならない。`FailSafeAuditContext` は型では 3 フィールドに
   * 限られているが、JS からの呼び出しは型で防げないため展開順で担保する。
   */
  it('auditContext は監査レコードの判定部分を上書きできない', async () => {
    const sink = auditSink();
    const warning = await resolveFailOpen({
      policyEvent: 'FO-1',
      policy: { suppressPrompt: ['FO-1'] },
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      onPolicyEvent: sink.onPolicyEvent,
      // 型上は verifier / vc_id / trace_id のみ。判定部分の同名キーを混ぜた JS 呼び出しを模す。
      auditContext: {
        verifier: 'rp-hash',
        policy_event: 'FO-9',
        audit_event: 'spoofed',
        user_consent: 'accepted',
        override: { escalate: ['FO-1'] },
      } as never,
    });
    expect(warning).toBeDefined();
    const record = sink.records[0];
    // 相関情報は透過するが、判定部分は実際の判定結果のまま。
    expect(record?.verifier).toBe('rp-hash');
    expect(record?.policy_event).toBe('FO-1');
    expect(record?.audit_event).toBe('status_check_unreachable');
    expect(record?.user_consent).toBe('accepted');
    expect(record?.override).toEqual({ suppressPrompt: ['FO-1'] });
  });

  // 回帰: 未知 ID（型 cast / JS 利用者経由の FC-*）が warn に倒れて通過していた。
  it('未知 ID（FC-*）は Fail-open せず、監査記録もしない', async () => {
    const sink = auditSink();
    const warning = await resolveFailOpen({
      policyEvent: 'FC-11' as FailOpenId,
      policy: { suppressPrompt: ['FC-11' as FailOpenId] },
      window: createFailOpenWindow(),
      key: KEY,
      nowSeconds: 1_000,
      onPolicyEvent: sink.onPolicyEvent,
    });
    expect(warning).toBeUndefined();
    expect(sink.records).toEqual([]);
  });
});
