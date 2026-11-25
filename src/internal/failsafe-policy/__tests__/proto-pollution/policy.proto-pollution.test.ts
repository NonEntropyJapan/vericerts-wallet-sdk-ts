/**
 * `decideFailSafe`（`policy.ts`）の `Object.prototype` 汚染耐性テスト。
 *
 * `resolveFailOpen` は `params.policy` 自体は own 限定（`ownProperty`）で読むが、渡された `policy`
 * オブジェクトの**個別フィールド**（`escalate` / `suppressPrompt` / `refreshFailure` /
 * `allowSubstantialPasskey`）は `policy?.field` という通常のオプショナルチェイニング（プロトタイプ
 * 鎖読み）だった。`policy` 自体は呼び出し側が用意した正当なオブジェクトリテラル（`Object.prototype`
 * を継承する）であっても、フィールドを**省略した**場合に `Object.prototype` の汚染値を拾ってしまう。
 *
 * ここでは `policy` を明示的に渡し（`gate.proto-pollution.test.ts` の「`policy` 自体を省略」ケースとは
 * 異なる、より一般的なケース）、その中の個別フィールドだけを未指定にしたまま `Object.prototype` を
 * 汚染し、既定挙動（warn + 同意必須）が保たれることを検証する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { decideFailSafe } from '../../policy.js';
import type { FailOpenId } from '../../types.js';

const ALL_FAIL_OPEN_IDS: readonly FailOpenId[] = [
  'FO-1',
  'FO-2',
  'FO-3',
  'FO-4',
  'FO-5',
  'FO-6',
  'FO-7',
  'FO-8',
  'FO-9',
  'FO-10',
  'FO-11',
  'FO-12',
];

describe('decideFailSafe の Object.prototype 汚染耐性', () => {
  it('継承した allowSubstantialPasskey は promptSuppressed の判定に使わない（FO-11）', () => {
    const decision = withPollutedPrototype({ allowSubstantialPasskey: true }, () =>
      decideFailSafe('FO-11', {}),
    );
    // 既定は同意必須（未指定を汚染値 true で埋めると同意プロンプトが無言で抑制されてしまう）。
    expect(decision.severity).toBe('warn');
    expect(decision.promptRequired).toBe(true);
  });

  it('継承した suppressPrompt は promptSuppressed の判定に使わない（全 FO-ID を汚染）', () => {
    const decision = withPollutedPrototype({ suppressPrompt: ALL_FAIL_OPEN_IDS }, () =>
      decideFailSafe('FO-1', {}),
    );
    expect(decision.severity).toBe('warn');
    expect(decision.promptRequired).toBe(true);
  });

  it('継承した refreshFailure: keep-old は promptSuppressed の判定に使わない（FO-9）', () => {
    const decision = withPollutedPrototype({ refreshFailure: 'keep-old' }, () =>
      decideFailSafe('FO-9', {}),
    );
    expect(decision.severity).toBe('warn');
    expect(decision.promptRequired).toBe(true);
  });

  it('継承した refreshFailure: discard は deniedByOption の判定に使わない（FO-9、fail-closed 誤爆の防止）', () => {
    const decision = withPollutedPrototype({ refreshFailure: 'discard' }, () =>
      decideFailSafe('FO-9', {}),
    );
    expect(decision.severity).toBe('warn');
    expect(decision.promptRequired).toBe(true);
  });

  it('継承した escalate は denied の判定に使わない', () => {
    const decision = withPollutedPrototype({ escalate: ['FO-1'] }, () =>
      decideFailSafe('FO-1', {}),
    );
    expect(decision.severity).toBe('warn');
    expect(decision.promptRequired).toBe(true);
  });

  it('明示的に指定したフィールドは汚染下でも own 優先で従来どおり機能する（正常系）', () => {
    const decision = withPollutedPrototype({ allowSubstantialPasskey: false }, () =>
      decideFailSafe('FO-11', { allowSubstantialPasskey: true }),
    );
    expect(decision.severity).toBe('warn');
    expect(decision.promptRequired).toBe(false);
  });
});
