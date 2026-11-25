/**
 * `resolveStatusListType`（`statusListType` 既定値規則）の回帰テスト。
 *
 * `IssuerModule` facade 本体の回帰テストは `issuer-module.test.ts` にある。既定値解決は facade の
 * 状態に依存しない純関数のため、ファイルを分けて独立に固定する。
 *
 * 検証内容:
 * - `format` → `statusListType` の既定値対応（`jwt` / `sd-jwt` / `cose` → `token-status-list`、
 *   `data-integrity` → `bitstring-v1`）。
 * - `statusListType` の明示指定が `format` より優先される。
 * - `Object.prototype` 由来の値を `format` / `statusListType` として受理しない（3002）。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../../errors.js';
import { resolveStatusListType } from '../../module/issue-options.js';

describe('resolveStatusListType（既定値）', () => {
  it.each([
    ['jwt', 'token-status-list'],
    ['sd-jwt', 'token-status-list'],
    ['cose', 'token-status-list'],
    ['data-integrity', 'bitstring-v1'],
  ] as const)('format=%s の既定は %s', (format, expected) => {
    expect(resolveStatusListType({ format })).toBe(expected);
  });

  it('format 未指定の既定は jwt 相当（token-status-list）', () => {
    expect(resolveStatusListType({})).toBe('token-status-list');
  });

  it('明示指定は format より優先される', () => {
    expect(resolveStatusListType({ format: 'jwt', statusListType: 'statuslist2021' })).toBe(
      'statuslist2021',
    );
  });

  it('Object.prototype 由来の値は format として受理しない（プロトタイプ汚染耐性）', () => {
    // 通常のオブジェクトリテラルで対応表を作ると 'constructor' 等が Object.prototype にヒットし、
    // 未対応 format ガードをすり抜けて関数オブジェクトが返ってしまう。
    expect(() => resolveStatusListType({ format: 'constructor' as unknown as 'jwt' })).toThrow(
      VericertsError,
    );
    expect(() => resolveStatusListType({ format: 'toString' as unknown as 'jwt' })).toThrow(
      VericertsError,
    );
  });

  it('型外の statusListType は 3002 で拒否する', () => {
    expect(() =>
      resolveStatusListType({ statusListType: 'constructor' as unknown as 'bitstring-v1' }),
    ).toThrow(VericertsError);
  });
});
