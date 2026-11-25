/**
 * did:webvh の内部フック（`resolveDidWebVhHooked` / `WebVhResolveHooks`）が公開エントリに出ない pin。
 *
 * 拡張の in-flight 予算管理だけが内部 alias で使う。公開 API にすると
 * 互換の約束（api-stability）が増えるため、バレルへ誤って再エクスポートしないことを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as sdk from '../../index.js';
import * as identity from '../identity.js';

describe('公開エクスポート: did:webvh の内部フックは公開されない', () => {
  it.each([
    ['メインバレル', sdk],
    ['identity エントリ', identity],
  ])('resolveDidWebVhHooked は %s に存在しない', (_name, entry) => {
    expect('resolveDidWebVhHooked' in entry).toBe(false);
    expect('createWebVhAttemptLedger' in entry).toBe(false);
  });

  it.each([
    'index.ts',
    'exports/identity.ts',
  ])('%s のソースは resolveDidWebVhHooked / WebVhResolveHooks / WebVhAttemptLedger を再エクスポートしない（型を含む）', (file) => {
    const source = readFileSync(join(import.meta.dir, '..', '..', file), 'utf8');
    expect(source).not.toContain('resolveDidWebVhHooked');
    expect(source).not.toContain('WebVhResolveHooks');
    expect(source).not.toContain('WebVhAttemptLedger');
    expect(source).not.toContain('trackAttempt');
  });

  it('対照: 公開の resolveDidWebVh / resolveDidWebVhWithMetadata は存在する', () => {
    expect(typeof sdk.resolveDidWebVh).toBe('function');
    expect(typeof sdk.resolveDidWebVhWithMetadata).toBe('function');
  });
});
