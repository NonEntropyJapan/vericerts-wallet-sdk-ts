/**
 * `./layer-map.ts`（レイヤー間の依存方向を検査するロジック）のユニットテスト。
 *
 * `layer-direction.test.ts` の実走査は「違反 0 件」を主張するだけなので、判定側が壊れても
 * 0 件のまま緑になりうる（vacuous pass）。本ファイルは**ポジティブコントロール**として、
 * 実走査が通るのと同じ関数（`moduleSpecifiers` / `classify` / `layerViolations` /
 * `crossCuttingViolations`）へ擬似ソースを直接渡し、検知能力そのものを固定する。
 *
 * 特に、`moduleResolution: "bundler"` の本リポジトリで有効な次の 5 形式は
 * tsc も biome も素通りさせるため、ここで明示的に押さえる。
 * 1. 拡張子なしのディレクトリ import（`from '../failsafe'`）
 * 2. 副作用 import（`import '../failsafe/index.js';`）
 * 3. 動的 import（`await import('../failsafe/index.js')`）
 * 4. テンプレートリテラルの動的 import（``await import(`../failsafe/index.js`)``）
 * 5. tsconfig の `paths` エイリアス経由の import（`from '@/internal/failsafe/index.js'`）
 */

import { describe, expect, it } from 'bun:test';
import {
  classify,
  crossCuttingViolations,
  layerViolations,
  moduleSpecifiers,
} from './layer-map.js';

/** Foundation の実ファイルに相当する擬似パス（`src/` 相対）。 */
const FOUNDATION_FILE = 'internal/failsafe-policy/policy.ts';

describe('moduleSpecifiers は依存の張り方を漏れなく拾う', () => {
  it('静的 import / export from / 副作用 import / 動的 import をすべて抽出する', () => {
    const source = [
      "import { a } from '../failsafe/index.js';",
      "import type { B } from '../failsafe';",
      "export { c } from './c.js';",
      "import '../failsafe/side-effect.js';",
      "const d = await import('../failsafe/dynamic.js');",
    ].join('\n');

    expect(moduleSpecifiers(source).sort()).toEqual([
      '../failsafe',
      '../failsafe/dynamic.js',
      '../failsafe/index.js',
      '../failsafe/side-effect.js',
      './c.js',
    ]);
  });

  it('テンプレートリテラル形式の動的 import も抽出する', () => {
    const source = 'const a = await import(`../failsafe/index.js`);\n';

    expect(moduleSpecifiers(source)).toEqual(['../failsafe/index.js']);
  });

  it('複数行にまたがる import 文も 1 件として拾う', () => {
    const source = 'import {\n  a,\n  b,\n} from "../failsafe/index.js";\n';

    expect(moduleSpecifiers(source)).toEqual(['../failsafe/index.js']);
  });
});

describe('classify はディレクトリ import とファイルを区別する', () => {
  it('拡張子なしのディレクトリ指定はパッケージとして分類される', () => {
    expect(classify('internal/failsafe')).toEqual({ unit: 'failsafe', layer: 'Protocol' });
  });

  it('パッケージ配下のファイルはそのパッケージのレイヤーになる', () => {
    expect(classify('internal/failsafe/index.ts')).toEqual({ unit: 'failsafe', layer: 'Protocol' });
  });

  it('src/internal 直下のファイルは横断になる', () => {
    expect(classify('internal/fetch-di.ts')).toEqual({ unit: '横断', layer: '横断' });
  });

  it('未知のパッケージは分類対象外になる', () => {
    expect(classify('internal/unknown-package/foo.ts')).toBeNull();
  });
});

describe('layerViolations は逆方向の辺を検出する（ポジティブコントロール）', () => {
  /** Foundation → Protocol の辺を張る 5 形式 + 通常形。 */
  const reverseEdges: ReadonlyArray<readonly [string, string]> = [
    ['拡張子なしのディレクトリ import', "import type { X } from '../failsafe';"],
    ['副作用 import', "import '../failsafe/index.js';"],
    ['動的 import', "const x = await import('../failsafe/index.js');"],
    ['テンプレートリテラルの動的 import', 'const x = await import(`../failsafe/index.js`);'],
    ['パスエイリアス（@/）import', "import { x } from '@/internal/failsafe/index.js';"],
    ['通常の静的 import', "import { x } from '../failsafe/index.js';"],
  ];

  for (const [label, statement] of reverseEdges) {
    it(`${label} による Foundation → Protocol を violation として報告する`, () => {
      const violations = layerViolations(FOUNDATION_FILE, `${statement}\n`);

      expect(violations).toHaveLength(1);
      expect(violations[0]).toContain('failsafe-policy(Foundation) -> failsafe(Protocol)');
    });
  }

  it('順方向（Protocol → Foundation）は violation にならない', () => {
    const source = "import { x } from '../failsafe-policy/policy.js';\n";

    expect(layerViolations('internal/failsafe/index.ts', source)).toEqual([]);
  });

  it('同一パッケージ内の import は violation にならない', () => {
    const source = "import { x } from './types.js';\n";

    expect(layerViolations(FOUNDATION_FILE, source)).toEqual([]);
  });

  it('テスト支援（interop）への辺は対象外', () => {
    const source = "import { x } from '../interop/harness.js';\n";

    expect(layerViolations(FOUNDATION_FILE, source)).toEqual([]);
  });
});

describe('crossCuttingViolations は横断ヘルパーからの依存を検出する', () => {
  it('横断ファイルがパッケージへ依存すると violation になる', () => {
    const source = "import './failsafe-policy/policy.js';\n";

    expect(crossCuttingViolations('internal/fetch-di.ts', source)).toEqual([
      'internal/fetch-di.ts -> ./failsafe-policy/policy.js',
    ]);
  });

  it('パスエイリアス（@/）経由でパッケージへ依存しても violation になる', () => {
    const source = "import { x } from '@/internal/failsafe-policy/policy.js';\n";

    expect(crossCuttingViolations('internal/fetch-di.ts', source)).toEqual([
      'internal/fetch-di.ts -> @/internal/failsafe-policy/policy.js',
    ]);
  });

  it('横断ファイル同士の依存は violation にならない', () => {
    const source = "import { x } from './errors.js';\n";

    expect(crossCuttingViolations('internal/fetch-di.ts', source)).toEqual([]);
  });
});
