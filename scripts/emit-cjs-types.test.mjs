import { expect, test } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { emitCjsTypes } from './emit-cjs-types.mjs';

test('CJS宣言は相対グラフを保ち、旧生成物と実行コードを持ち込まない', () => {
  const dist = mkdtempSync(join(tmpdir(), 'cjs-types-'));
  try {
    mkdirSync(join(dist, 'nested'));
    const declaration = "import type { B } from './nested/b.js';\nexport declare const b: B;\n";
    writeFileSync(join(dist, 'index.d.ts'), declaration);
    writeFileSync(join(dist, 'index.d.ts.map'), '{}');
    writeFileSync(join(dist, 'nested/b.d.ts'), 'export interface B { readonly value: number }');
    writeFileSync(join(dist, 'index.js'), 'throw new Error("do not copy")');
    emitCjsTypes(dist);
    expect(JSON.parse(readFileSync(join(dist, 'cjs-types/package.json'), 'utf8'))).toEqual({
      type: 'commonjs',
    });
    expect(readFileSync(join(dist, 'cjs-types/index.d.ts'), 'utf8')).toBe(declaration);
    expect(existsSync(join(dist, 'cjs-types/nested/b.d.ts'))).toBe(true);
    expect(existsSync(join(dist, 'cjs-types/index.d.ts.map'))).toBe(false);
    expect(existsSync(join(dist, 'cjs-types/index.js'))).toBe(false);
    writeFileSync(join(dist, 'cjs-types/stale.d.ts'), 'stale');
    emitCjsTypes(dist);
    expect(existsSync(join(dist, 'cjs-types/stale.d.ts'))).toBe(false);
  } finally {
    rmSync(dist, { recursive: true, force: true });
  }
});

test('外部ESMの値importを型だけのimport解決へ変換する', () => {
  const dist = mkdtempSync(join(tmpdir(), 'cjs-external-types-'));
  try {
    writeFileSync(
      join(dist, 'index.d.ts'),
      'import { curve } from "external-esm";\nexport type Curve = typeof curve;\n//# sourceMappingURL=index.d.ts.map\n',
    );
    emitCjsTypes(dist);
    const result = readFileSync(join(dist, 'cjs-types/index.d.ts'), 'utf8');
    expect(result).toContain('import type { curve }');
    expect(result).toContain('"resolution-mode": "import"');
    expect(result).not.toContain('sourceMappingURL');
  } finally {
    rmSync(dist, { recursive: true, force: true });
  }
});
