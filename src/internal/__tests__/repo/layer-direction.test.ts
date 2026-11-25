/**
 * レイヤー間の依存方向の回帰テスト。
 *
 * 背景:
 * レイヤー間の依存は Protocol → Domain → Foundation の向きに限る。
 * 実行時 import と型だけの import の双方で、逆方向の依存が再発しないことを検証する。
 *
 * linterly（行数上限）も biome も import の向きは見ないため、この検査はここでしか行われない。
 *
 * 検証内容:
 * 1. 製品コードの import が下位レイヤーまたは同一レイヤーだけを向いている
 *    （相対指定子に加え、tsconfig の `paths` エイリアス `@/...` も対象）。
 * 2. SDK レイヤー表の分類が有効で、対象とする実装ディレクトリが双方向に一致する。
 * 3. `src/` 直下の公開 API ディレクトリと `PUBLIC_API_DIRS` が双方向に一致する
 *    （新しい公開ディレクトリが検査から静かに脱落するのを防ぐ）。
 *
 * 判定ロジックそのものは `./layer-map.ts` にあり、その検知能力は
 * `./layer-map.test.ts` がポジティブコントロールで固定している。
 *
 * 型のみ import も対象に含める。型の依存も
 * レイヤー分類上は同じ向きを持つため。
 *
 * 「テスト支援」（`interop` と各 `__tests__/`）は 全レイヤーの機能を検証するため対象外。
 */

import { describe, expect, it } from 'bun:test';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  collectSources,
  crossCuttingViolations,
  isTestSupport,
  layerViolations,
  PACKAGE_LAYER,
  PUBLIC_API_DIRS,
  RANK,
  SRC_ROOT,
  TEST_SUPPORT,
} from './layer-map.js';

const sources = collectSources(SRC_ROOT).filter((path) => !isTestSupport(path));

/** `src/internal` 直下のサブディレクトリ名（`__tests__` を除く）。 */
function implementationPackages(): string[] {
  return readdirSync(join(SRC_ROOT, 'internal'))
    .filter((entry) => entry !== '__tests__')
    .filter((entry) => statSync(join(SRC_ROOT, 'internal', entry)).isDirectory())
    .sort();
}

/** `src/` 直下のディレクトリ名（`internal` と `__tests__` を除く）。 */
function publicApiDirectories(): string[] {
  return readdirSync(SRC_ROOT)
    .filter((entry) => entry !== 'internal' && entry !== '__tests__')
    .filter((entry) => statSync(join(SRC_ROOT, entry)).isDirectory())
    .sort();
}

describe('レイヤー間の依存方向は上→下のみ', () => {
  it('走査対象のソースが空振りしていない', () => {
    // 逆方向 0 件・横断ヘルパー 0 件という主張が「1 ファイルも読まずに緑」になるのを防ぐ。
    expect(sources.length).toBeGreaterThanOrEqual(300);
  });

  it('製品コードに逆方向依存（下位レイヤー → 上位レイヤー）が存在しない', () => {
    const violations = sources.flatMap((relPath) =>
      layerViolations(relPath, readFileSync(join(SRC_ROOT, relPath), 'utf8')),
    );

    expect(violations).toEqual([]);
  });

  it('横断ヘルパー（src/internal 直下）はどのレイヤーにも依存しない', () => {
    const violations = sources.flatMap((relPath) =>
      crossCuttingViolations(relPath, readFileSync(join(SRC_ROOT, relPath), 'utf8')),
    );

    expect(violations).toEqual([]);
  });
});

describe('レイヤー定義表は網羅的である', () => {
  it('SDK のレイヤー表と src/internal の実装ディレクトリが一致する', () => {
    expect(Object.keys(PACKAGE_LAYER).sort()).toEqual(implementationPackages());
  });

  it('パッケージの分類は有効なレイヤーまたはテスト支援である', () => {
    const knownLayers = new Set([...Object.keys(RANK), TEST_SUPPORT]);
    expect(Object.values(PACKAGE_LAYER).filter((layer) => !knownLayers.has(layer))).toEqual([]);
  });

  it('src/ 直下の公開 API ディレクトリがすべて PUBLIC_API_DIRS に含まれる', () => {
    const unclassified = publicApiDirectories().filter((entry) => !PUBLIC_API_DIRS.has(entry));

    expect(unclassified).toEqual([]);
  });

  it('PUBLIC_API_DIRS のエントリがすべて実在する', () => {
    const existing = new Set(publicApiDirectories());
    const ghosts = [...PUBLIC_API_DIRS].filter((entry) => !existing.has(entry)).sort();

    expect(ghosts).toEqual([]);
  });
});
