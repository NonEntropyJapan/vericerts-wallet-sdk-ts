/** ゲートの検出力テスト用: 一時 SDK ルートに 1 ファイルだけ置いて `findInheritedReads` を掛ける。 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import ts from 'typescript';
import { findInheritedReads, type ScanOptions } from './scan.js';

/**
 * 型検査器でプログラムを組む（実リポジトリでは数秒〜、`narrowedRequired` で 2 回走査する）テストの上限。
 * load average 40〜90 で実測 157 秒かかったので、HEAVY_INPUT_TIMEOUT_MS（120 秒）より余裕を持たせる。
 */
export const SCAN_TIMEOUT_MS = 600_000;

/** `entries` を渡すと、それを公開 API の入口（`src/a.ts` 等）として扱う。検出した式を `file:line` なしで返す。 */
export function scanSource(
  source: string,
  entries?: string[],
  extra: Omit<ScanOptions, 'publicEntries'> = {},
): string[] {
  const root = mkdtempSync(join(tmpdir(), 'inherited-reads-'));
  try {
    mkdirSync(join(root, 'src'));
    writeFileSync(
      join(root, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: { strict: true, target: 'ES2022', module: 'ESNext', noEmit: true },
        include: ['src/**/*.ts'],
      }),
    );
    writeFileSync(join(root, 'src', 'a.ts'), source);
    return findInheritedReads(root, ts, { publicEntries: entries, ...extra }).map(
      (r) => r.expression,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
