/**
 * `isDebugNamespaceEnabled` の単位テスト（`DEBUG=vericerts:*`）。
 *
 * `DEBUG` はプロセス環境変数なので、各テストで退避・復元して他テストへ漏らさない。
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { isDebugNamespaceEnabled } from '../debug-namespace.js';

const ORIGINAL_DEBUG = process.env.DEBUG;

function setDebugEnv(value: string | undefined): void {
  if (value === undefined) {
    delete process.env.DEBUG;
  } else {
    process.env.DEBUG = value;
  }
}

beforeEach(() => {
  setDebugEnv(undefined);
});

afterEach(() => {
  setDebugEnv(ORIGINAL_DEBUG);
});

describe('isDebugNamespaceEnabled（DEBUG=vericerts:* パターン）', () => {
  it('DEBUG 未設定なら常に無効（本番既定 Off）', () => {
    expect(isDebugNamespaceEnabled('vericerts:did')).toBe(false);
    expect(isDebugNamespaceEnabled('vericerts')).toBe(false);
  });

  it('DEBUG が空文字なら常に無効', () => {
    setDebugEnv('');
    expect(isDebugNamespaceEnabled('vericerts:did')).toBe(false);
  });

  it('vericerts:* は全ネームスペースを有効化する', () => {
    setDebugEnv('vericerts:*');
    expect(isDebugNamespaceEnabled('vericerts:did')).toBe(true);
    expect(isDebugNamespaceEnabled('vericerts:oid4vc')).toBe(true);
    expect(isDebugNamespaceEnabled('vericerts')).toBe(true);
  });

  it('vericerts:did:* は did 名前空間のみ有効化し、他は無効のまま', () => {
    setDebugEnv('vericerts:did:*');
    expect(isDebugNamespaceEnabled('vericerts:did')).toBe(true);
    expect(isDebugNamespaceEnabled('vericerts:oid4vc')).toBe(false);
    expect(isDebugNamespaceEnabled('vericerts:vc')).toBe(false);
  });

  it('カンマ区切りで複数の名前空間を同時に有効化できる', () => {
    setDebugEnv('vericerts:did:*,vericerts:aa:*');
    expect(isDebugNamespaceEnabled('vericerts:did')).toBe(true);
    expect(isDebugNamespaceEnabled('vericerts:aa')).toBe(true);
    expect(isDebugNamespaceEnabled('vericerts:eudi')).toBe(false);
  });

  it('空白区切りでも複数の名前空間を指定できる', () => {
    setDebugEnv('vericerts:did:* vericerts:aa:*');
    expect(isDebugNamespaceEnabled('vericerts:did')).toBe(true);
    expect(isDebugNamespaceEnabled('vericerts:aa')).toBe(true);
  });

  it('`-` 接頭辞は除外として扱われ、包含パターンより優先される', () => {
    setDebugEnv('vericerts:*,-vericerts:vc:*');
    expect(isDebugNamespaceEnabled('vericerts:did')).toBe(true);
    expect(isDebugNamespaceEnabled('vericerts:vc')).toBe(false);
  });

  it('関係ないアプリの名前空間（例: `other:*`）は有効化しない', () => {
    setDebugEnv('other:*');
    expect(isDebugNamespaceEnabled('vericerts:did')).toBe(false);
  });
});
