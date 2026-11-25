/**
 * 共有ヘルパー `internal/identity/did-format.ts` の判定規則を固定するテスト。
 *
 * `identity/resolver.ts` の `DID_METHOD_PATTERN`（キャプチャあり）と
 * `issuer/module/validate-issue-input.ts` の `DID_PATTERN`（キャプチャなし）に個別定義されていた
 * 同一パターンの正規表現を {@link extractDidMethod} / {@link isValidDidFormat} へ集約した際の
 * **挙動不変**を担保する。
 */

import { describe, expect, it } from 'bun:test';
import { extractDidMethod, isValidDidFormat } from '../did-format.js';

describe('extractDidMethod', () => {
  it('did:<method>:<identifier> からメソッド名を取り出す', () => {
    expect(extractDidMethod('did:key:z6Mk...')).toBe('key');
    expect(extractDidMethod('did:web:example.com')).toBe('web');
    expect(extractDidMethod('did:pkh:eip155:1:0xabc')).toBe('pkh');
  });

  it('DID 形式でない文字列は undefined', () => {
    expect(extractDidMethod('not-a-did')).toBeUndefined();
  });

  it('method 部はあるが identifier がない場合は undefined', () => {
    expect(extractDidMethod('did:key:')).toBeUndefined();
  });

  it('method 部が大文字を含む場合は undefined（`[a-z0-9]+` のみ許容）', () => {
    expect(extractDidMethod('did:KEY:z6Mk...')).toBeUndefined();
  });
});

describe('isValidDidFormat', () => {
  it('extractDidMethod が値を返す入力は true', () => {
    expect(isValidDidFormat('did:key:z6Mk...')).toBe(true);
  });

  it('extractDidMethod が undefined を返す入力は false', () => {
    expect(isValidDidFormat('not-a-did')).toBe(false);
    expect(isValidDidFormat('did:key:')).toBe(false);
  });
});
