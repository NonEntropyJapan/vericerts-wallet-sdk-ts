/**
 * Fail-safe ポリシー判定（`decideFailSafe`）と Fail-open 時間上限（`createFailOpenWindow`）の単体テスト。
 *
 * FO-1〜FO-12 の判断・監査イベントと、利用者が指定したポリシーの扱いを確認する。
 *
 * 検証内容:
 * - 既定は Fail-open（`warn`）で同意プロンプトを要求する。
 * - `escalate` で Fail-closed（`deny`）に格上げされる。
 * - `suppressPrompt` で同意プロンプトが省かれる（重大度は `warn` のまま）。
 * - Fail-open として登録されていない ID（`FC-*` / 未知）は fail-closed（`deny`）に倒れる。
 * - `refreshFailure`（FO-9）/ `allowSubstantialPasskey`（FO-11）が判定に効く。
 * - FO-1〜FO-12 の監査ログイベント名が 各ポリシーに対応する期待値と一致する。
 * - 時間上限は 60 秒既定で、超過後は `clear()`（取得成功）までずっと不許可になる。
 * - 時間上限の緩和方向（60 超）の指定は 3002 で拒否する。
 * - 計時キー数の上限も非負整数でなければ 3002 で拒否する（NaN で上界が無効化されない）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  createFailOpenWindow,
  DEFAULT_FAIL_OPEN_MAX_SECONDS,
  decideFailSafe,
  FAIL_OPEN_AUDIT_EVENTS,
  FAIL_OPEN_IDS,
  UNKNOWN_POLICY_EVENT_AUDIT,
} from '../policy.js';
import type { FailOpenId } from '../types.js';

/** Fail-open ポリシー ID ごとの監査イベント名。 */
const SPEC_AUDIT_EVENTS: Record<FailOpenId, string> = {
  'FO-1': 'status_check_unreachable',
  'FO-2': 'status_list_stale',
  'FO-3': 'schema_fetch_failed',
  'FO-4': 'schema_optional_invalid',
  'FO-5': 'tsl_fetch_failed_cache_ok',
  'FO-6': 'federation_fetch_failed_cache_ok',
  'FO-7': 'did_config_missing',
  'FO-8': 'vc_expiring_soon',
  'FO-9': 'refresh_failed',
  'FO-10': 'mediator_unreachable',
  'FO-11': 'passkey_provider_substantial',
  'FO-12': 'evidence_fetch_failed',
};

describe('decideFailSafe', () => {
  it('override 未指定なら 既定どおり warn + 同意プロンプト要求', () => {
    expect(decideFailSafe('FO-1')).toEqual({
      policyEvent: 'FO-1',
      severity: 'warn',
      auditEvent: 'status_check_unreachable',
      promptRequired: true,
    });
  });

  it('空の override でも既定と同じ判定になる', () => {
    expect(decideFailSafe('FO-2', {})).toEqual({
      policyEvent: 'FO-2',
      severity: 'warn',
      auditEvent: 'status_list_stale',
      promptRequired: true,
    });
  });

  it('escalate に挙げた ID は deny に格上げされ、同意プロンプトも不要になる', () => {
    const decision = decideFailSafe('FO-1', { escalate: ['FO-1'] });
    expect(decision.severity).toBe('deny');
    expect(decision.promptRequired).toBe(false);
  });

  it('escalate は挙げた ID にだけ効く', () => {
    expect(decideFailSafe('FO-2', { escalate: ['FO-1'] }).severity).toBe('warn');
  });

  it('suppressPrompt に挙げた ID は warn のまま同意プロンプトが省かれる', () => {
    const decision = decideFailSafe('FO-1', { suppressPrompt: ['FO-1'] });
    expect(decision.severity).toBe('warn');
    expect(decision.promptRequired).toBe(false);
  });

  it('escalate と suppressPrompt の両方に挙げた場合は escalate（deny）が優先される', () => {
    const decision = decideFailSafe('FO-1', { escalate: ['FO-1'], suppressPrompt: ['FO-1'] });
    expect(decision.severity).toBe('deny');
    expect(decision.promptRequired).toBe(false);
  });

  it('FO-1〜FO-12 の監査ログイベント名が 各ポリシーに対応する期待値と一致する', () => {
    for (const id of FAIL_OPEN_IDS) {
      expect(decideFailSafe(id).auditEvent).toBe(SPEC_AUDIT_EVENTS[id]);
    }
  });

  // 回帰: 型 cast / JS 利用者経由で FC-* や未知 ID が渡ると warn（fail-open）に倒れていた。
  // fail-safe モジュールの倒れ方向は常に安全側でなければならない。
  it('Fail-open として登録されていない ID（FC-* / 未知）は fail-closed に倒れ、同意プロンプトも要求しない', () => {
    for (const unknown of ['FC-1', 'FC-11', 'FO-13', '', 'toString']) {
      const decision = decideFailSafe(unknown as FailOpenId);
      expect(decision.severity).toBe('deny');
      expect(decision.promptRequired).toBe(false);
      expect(decision.auditEvent).toBe(UNKNOWN_POLICY_EVENT_AUDIT);
    }
  });

  it('未知 ID は escalate / suppressPrompt を指定しても fail-closed のまま', () => {
    const decision = decideFailSafe('FC-1' as FailOpenId, {
      suppressPrompt: ['FC-1' as FailOpenId],
    });
    expect(decision.severity).toBe('deny');
  });
});

// 回帰: refreshFailure / allowSubstantialPasskey は宣言のみで判定に反映されておらず、
// FO-9 / FO-11 が値に関わらず一律 warn + 同意プロンプトになっていた。
describe('decideFailSafe（挙動変更オプション）', () => {
  it('FO-9 は refreshFailure: discard で fail-closed（旧 VC を破棄する選択）', () => {
    const decision = decideFailSafe('FO-9', { refreshFailure: 'discard' });
    expect(decision.severity).toBe('deny');
    expect(decision.promptRequired).toBe(false);
  });

  it('FO-9 は refreshFailure: keep-old なら同意プロンプト無しで旧 VC を継続する', () => {
    const decision = decideFailSafe('FO-9', { refreshFailure: 'keep-old' });
    expect(decision.severity).toBe('warn');
    expect(decision.promptRequired).toBe(false);
  });

  it('FO-9 は refreshFailure: prompt / 未指定なら同意プロンプトを要求する', () => {
    expect(decideFailSafe('FO-9', { refreshFailure: 'prompt' }).promptRequired).toBe(true);
    expect(decideFailSafe('FO-9').promptRequired).toBe(true);
  });

  it('refreshFailure は FO-9 以外の ID には影響しない', () => {
    expect(decideFailSafe('FO-1', { refreshFailure: 'discard' }).severity).toBe('warn');
    expect(decideFailSafe('FO-1', { refreshFailure: 'keep-old' }).promptRequired).toBe(true);
  });

  it('escalate は refreshFailure: keep-old より優先される', () => {
    const decision = decideFailSafe('FO-9', { escalate: ['FO-9'], refreshFailure: 'keep-old' });
    expect(decision.severity).toBe('deny');
  });

  it('FO-11 は allowSubstantialPasskey: true なら同意プロンプト無しで通過する', () => {
    const decision = decideFailSafe('FO-11', { allowSubstantialPasskey: true });
    expect(decision.severity).toBe('warn');
    expect(decision.promptRequired).toBe(false);
  });

  it('FO-11 は allowSubstantialPasskey: false / 未指定なら 既定の警告通過（同意必須）', () => {
    expect(decideFailSafe('FO-11', { allowSubstantialPasskey: false }).promptRequired).toBe(true);
    expect(decideFailSafe('FO-11').promptRequired).toBe(true);
  });

  it('allowSubstantialPasskey は FO-11 以外の ID には影響しない', () => {
    expect(decideFailSafe('FO-1', { allowSubstantialPasskey: true }).promptRequired).toBe(true);
  });
});

describe('FAIL_OPEN_AUDIT_EVENTS / FAIL_OPEN_IDS', () => {
  it('FO-1〜FO-12をすべて過不足なく登録している', () => {
    expect(FAIL_OPEN_IDS).toEqual(Object.keys(SPEC_AUDIT_EVENTS) as FailOpenId[]);
    expect(FAIL_OPEN_IDS).toHaveLength(12);
    expect(FAIL_OPEN_AUDIT_EVENTS).toEqual(SPEC_AUDIT_EVENTS);
  });

  it('監査ログイベント名は ID 間で重複しない', () => {
    expect(new Set(Object.values(FAIL_OPEN_AUDIT_EVENTS)).size).toBe(12);
  });
});

describe('createFailOpenWindow', () => {
  it('既定の上限は 60 秒', () => {
    expect(DEFAULT_FAIL_OPEN_MAX_SECONDS).toBe(60);
    const window = createFailOpenWindow();
    expect(window.allow('k', 1_000)).toBe(true);
    expect(window.allow('k', 1_060)).toBe(true);
    expect(window.allow('k', 1_061)).toBe(false);
  });

  it('初回は許可し、上限以内は許可を継続する', () => {
    const window = createFailOpenWindow(10);
    expect(window.allow('k', 100)).toBe(true);
    expect(window.allow('k', 105)).toBe(true);
    expect(window.allow('k', 110)).toBe(true);
  });

  // 回帰: 上限超過時にウィンドウを破棄していたため、1 回不許可を返した直後の失敗が新しい上限で
  // 許可されていた。これでは失敗が続く限り上限ごとに 1 回拒否するだけで fail-open が無期限に継続し、
  // 失効済み VC を受理し続ける窓が閉じない。破棄条件は取得成功（clear）のみ。
  it('上限を超えたら以降は clear() まで不許可を返し続ける（新しいウィンドウを開かない）', () => {
    const window = createFailOpenWindow(10);
    expect(window.allow('k', 100)).toBe(true);
    expect(window.allow('k', 111)).toBe(false);
    // 直後の再試行でも新しいウィンドウは始まらない。
    expect(window.allow('k', 111)).toBe(false);
    expect(window.allow('k', 121)).toBe(false);
    expect(window.allow('k', 1_000)).toBe(false);
    // 取得成功（clear）で初めて次のウィンドウが開く。
    window.clear('k');
    expect(window.allow('k', 1_000)).toBe(true);
  });

  it('キーごとに独立して計時する', () => {
    const window = createFailOpenWindow(10);
    expect(window.allow('a', 100)).toBe(true);
    expect(window.allow('b', 105)).toBe(true);
    expect(window.allow('a', 111)).toBe(false);
    expect(window.allow('b', 111)).toBe(true);
  });

  // 回帰: 60 秒は上限であり、緩和方向の上書きは受理してはならない。
  it('上限は既定 60 秒を超えて緩められない（3002 で拒否する）', () => {
    for (const relaxed of [61, 120, 86_400]) {
      expect(() => createFailOpenWindow(relaxed)).toThrow(VericertsError);
    }
    try {
      createFailOpenWindow(86_400);
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
    }
    // 上限ちょうど・短縮は許可する。
    expect(createFailOpenWindow(60).allow('k', 0)).toBe(true);
    expect(createFailOpenWindow(30).allow('k', 0)).toBe(true);
  });

  it('clear() でウィンドウが破棄され、以降は新しいウィンドウで計時する', () => {
    const window = createFailOpenWindow(10);
    expect(window.allow('k', 100)).toBe(true);
    window.clear('k');
    expect(window.allow('k', 200)).toBe(true);
    expect(window.allow('k', 210)).toBe(true);
    expect(window.allow('k', 211)).toBe(false);
  });

  it('未記録のキーに対する clear() は何も起きない', () => {
    const window = createFailOpenWindow(10);
    window.clear('missing');
    expect(window.allow('missing', 100)).toBe(true);
  });

  it('上限 0 秒なら初回のみ許可し、以降は同時刻でなければ不許可', () => {
    const window = createFailOpenWindow(0);
    expect(window.allow('k', 100)).toBe(true);
    expect(window.allow('k', 100)).toBe(true);
    expect(window.allow('k', 101)).toBe(false);
  });

  /**
   * 計時キー数の上界（回帰テスト）。
   *
   * キーは呼び出し側の入力（Status List URI など）由来なので、上界が無いとプロセス寿命に比例して
   * メモリが伸びる。かつ、上界を「古い順に追い出す」で実装すると追い出し＝計時リセットとなり、
   * 相異なるキーを流し込むだけで 60 秒上限を巻き戻せてしまう。したがって溢れたら**拒否**する。
   */
  it('計時キー数が上限に達したら新しいキーは拒否する（fail-closed）', () => {
    const window = createFailOpenWindow(60, 2);
    expect(window.allow('a', 100)).toBe(true);
    expect(window.allow('b', 100)).toBe(true);
    // 3 つ目の新規キーは計時できないため許可しない。
    expect(window.allow('c', 100)).toBe(false);
    // 既に計時中のキーは影響を受けない（過剰拒否の回帰）。
    expect(window.allow('a', 100)).toBe(true);
  });

  it('clear() で枠が空けば新しいキーを再び計時できる', () => {
    const window = createFailOpenWindow(60, 1);
    expect(window.allow('a', 100)).toBe(true);
    expect(window.allow('b', 100)).toBe(false);
    // 取得成功でウィンドウを破棄すると枠が空く。
    window.clear('a');
    expect(window.allow('b', 100)).toBe(true);
  });

  it('溢れさせても計時中キーの上限は巻き戻らない（リセット攻撃の回帰）', () => {
    const window = createFailOpenWindow(10, 2);
    expect(window.allow('victim', 100)).toBe(true);
    // 別キーを詰めても victim の開始時刻は捨てられない。
    expect(window.allow('filler', 100)).toBe(true);
    expect(window.allow('flood', 100)).toBe(false);
    // victim は最初の開始時刻から数え続け、上限超過後は拒否のまま。
    expect(window.allow('victim', 111)).toBe(false);
  });

  it('上限が非負整数でなければ 3002', () => {
    for (const invalid of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      try {
        createFailOpenWindow(invalid);
        throw new Error('should throw');
      } catch (e) {
        expect(e).toBeInstanceOf(VericertsError);
        expect((e as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
      }
    }
  });

  // 回帰: maxKeys が無検証で、NaN を渡すと `size >= NaN` が常に false になり計時キー数の上界が
  // 恒久的に無効化されていた（メモリ安全性の防御が外れる）。負値では逆に初回のキーすら計時できない。
  it('計時キー数の上限が非負整数でなければ 3002', () => {
    for (const invalid of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      try {
        createFailOpenWindow(60, invalid);
        throw new Error('should throw');
      } catch (e) {
        expect(e).toBeInstanceOf(VericertsError);
        expect((e as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
      }
    }
  });

  it('maxKeys に NaN を渡しても上限が無効化されない（生成時点で拒否する）', () => {
    expect(() => createFailOpenWindow(60, Number.NaN)).toThrow(VericertsError);
  });

  it('maxKeys の正常系（省略 / 非負整数）は従来どおり生成できる', () => {
    expect(createFailOpenWindow(60).allow('k', 0)).toBe(true);
    expect(createFailOpenWindow(60, 1).allow('k', 0)).toBe(true);
    // 上限 0 なら最初のキーすら計時できず拒否する（境界値）。
    expect(createFailOpenWindow(60, 0).allow('k', 0)).toBe(false);
  });
});
