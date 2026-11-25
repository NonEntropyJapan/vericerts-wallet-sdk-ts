/**
 * `fetchEvents` が到達不能 RPC でもプロセスを残さない。
 *
 * `JsonRpcProvider` は staticNetwork 無しだとネットワーク検出に失敗したあと
 * 1 秒周期で再試行し、`destroy` しないとプロセスが終了しない。
 */

import { describe, expect, it } from 'bun:test';
import { fileURLToPath } from 'node:url';

const SDK_ROOT = fileURLToPath(new URL('../../../../../', import.meta.url));

describe('createEthersEventSource provider lifecycle', () => {
  it('到達不能 RPC でも 2003 で戻り、検出リトライを残さずプロセスが終了する', async () => {
    const script = `
      import { createEthersEventSource } from './src/internal/identity/ethr/registry.ts';
      const source = createEthersEventSource({ 1: 'http://127.0.0.1:1' });
      try {
        await source.fetchEvents(1, '0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb');
        process.exit(2);
      } catch (error) {
        const code = error && typeof error === 'object' && 'code' in error ? error.code : '';
        if (code !== '2003') process.exit(3);
      }
    `;
    const proc = Bun.spawn(['bun', '-e', script], {
      cwd: SDK_ROOT,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const killer = setTimeout(() => proc.kill(), 4_000);
    const code = await proc.exited;
    clearTimeout(killer);
    const stderr = await new Response(proc.stderr).text();
    expect(stderr).not.toContain('retry in 1s');
    expect(code).toBe(0);
  });
});
