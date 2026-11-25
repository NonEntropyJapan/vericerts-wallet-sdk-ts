/**
 * レイヤー分類と依存方向検査の共有ロジック。
 *
 * `layer-direction.test.ts`（実リポジトリ走査）と `layer-map.test.ts`（判定関数の
 * ユニットテスト = ポジティブコントロール）の両方から使う。両者が同じ関数を通ることで、
 * 「実走査が 0 件」という主張が検知能力の裏付けを伴う。
 *
 * 本ファイルは `*.test.ts` ではないため bun test の探索対象にならず、
 * `isTestSupport()` により走査対象からも外れる。
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, normalize, relative, resolve, sep } from 'node:path';
import packageLayers from './package-layers.json' with { type: 'json' };

/** `src/` の絶対パス（本ファイルは `src/internal/__tests__/repo/` にある）。 */
export const SRC_ROOT = resolve(import.meta.dir, '..', '..', '..');

/**
 * レイヤーの序列。大きいほど上位で、上位から下位への依存だけが許される。
 *
 * 「横断」は `src/internal` 直下のファイル群で、どのレイヤーからも参照される代わりに
 * 上位レイヤーに依存しないため最下位に置く。
 */
export const RANK = { 横断: 0, Foundation: 1, Domain: 2, Protocol: 3, 公開API: 4 } as const;

export type Layer = keyof typeof RANK;

/** 全レイヤーへの依存が許される区分（テスト支援）。検査対象外。 */
export const TEST_SUPPORT = 'テスト支援';

/** SDK のパッケージ分類。値と実ディレクトリとの対応は layer-direction.test.ts が検証する。 */
type PackageLayer = Layer | typeof TEST_SUPPORT;
export const PACKAGE_LAYER = packageLayers as Readonly<Record<string, PackageLayer>>;

/** `src/` 直下の公開 API ディレクトリ。 */
export const PUBLIC_API_DIRS = new Set(['wallet', 'storage', 'exports']);

/**
 * `tsconfig.json` の `compilerOptions.paths` から導いたエイリアス表
 * （指定子の接頭辞 → `src/` 相対の接頭辞）。tsconfig 側でエイリアスが増減しても追随する。
 * `src/` の外を指すエイリアスは分類対象外なので落とす。
 */
const PATH_ALIASES: ReadonlyArray<readonly [string, string]> = loadPathAliases();

function loadPathAliases(): ReadonlyArray<readonly [string, string]> {
  const tsconfigPath = resolve(SRC_ROOT, '..', 'tsconfig.json');
  const config = JSON.parse(readFileSync(tsconfigPath, 'utf8')) as {
    compilerOptions?: { paths?: Record<string, string[]> };
  };
  const aliases: Array<readonly [string, string]> = [];
  for (const [pattern, targets] of Object.entries(config.compilerOptions?.paths ?? {})) {
    const target = targets[0];
    if (!pattern.endsWith('/*') || target === undefined || !target.endsWith('/*')) continue;
    const prefix = relative(SRC_ROOT, resolve(dirname(tsconfigPath), target.slice(0, -1)));
    if (prefix.startsWith('..')) continue;
    aliases.push([pattern.slice(0, -1), prefix]);
  }
  return aliases;
}

/** テスト・テスト支援のパスか。 */
export function isTestSupport(relPath: string): boolean {
  const parts = relPath.split(sep);
  return (
    parts.includes('__tests__') ||
    parts.includes('interop') ||
    relPath.endsWith('.test.ts') ||
    relPath.endsWith('.fixtures.ts')
  );
}

/**
 * `src/` からの相対パスが属する「レイヤーの単位」を返す。
 *
 * @param relPath `src/` を起点とする相対パス（例: `internal/credential/vc/jws.ts`）。
 * @returns 単位名とレイヤー。分類対象外なら `null`。
 */
export function classify(relPath: string): { unit: string; layer: PackageLayer } | null {
  const parts = relPath.split(sep);
  if (parts[0] === 'internal') {
    // `internal/foo/...` と拡張子なしの `internal/foo`（ディレクトリ import）はパッケージ、
    // `internal/foo.ts` は横断ファイル。
    if (parts.length === 1) return null;
    const name = parts[1] as string;
    if (parts.length === 2 && (name.endsWith('.ts') || name.endsWith('.js'))) {
      return { unit: '横断', layer: '横断' };
    }
    const layer = PACKAGE_LAYER[name];
    return layer === undefined ? null : { unit: name, layer };
  }
  if (PUBLIC_API_DIRS.has(parts[0] as string)) {
    return { unit: parts[0] as string, layer: '公開API' };
  }
  if (parts.length === 1) return { unit: 'src', layer: '公開API' }; // src/index.ts
  return null;
}

/** `dir` 配下の `*.ts` を再帰的に集める（`src/` 相対パスで返す）。 */
export function collectSources(dir: string, found: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'dist') continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) collectSources(path, found);
    else if (entry.endsWith('.ts')) found.push(relative(SRC_ROOT, path));
  }
  return found;
}

/**
 * モジュール解決先の指定子を列挙する。
 *
 * 静的 `import` / `export ... from` に加え、副作用 import（`import '...';`）と
 * 動的 import（`import('...')`・置換なしテンプレートリテラルの ``import(`...`)``）も
 * 拾う。いずれも本リポジトリ
 * （`moduleResolution: "bundler"`）で有効な依存の張り方であり、
 * 見落とすと逆流が検査をすり抜ける。
 */
export function moduleSpecifiers(source: string): string[] {
  const patterns = [
    // import ... from '...' / export ... from '...'
    /(?:^|\n)\s*(?:import|export)\b[^'"]*?\bfrom\s*['"]([^'"]+)['"]/g,
    // import '...'（副作用 import）
    /(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g,
    // import('...') / import(`...`)（動的 import。置換なしテンプレートリテラルを含む）
    /\bimport\s*\(\s*['"`]([^'"`\n]+)['"`]\s*\)/g,
  ];
  const specifiers: string[] = [];
  for (const pattern of patterns) {
    let match = pattern.exec(source);
    while (match !== null) {
      specifiers.push(match[1] as string);
      match = pattern.exec(source);
    }
  }
  return specifiers;
}

/**
 * 指定子を `src/` 相対の走査用パスへ正規化する（`.js` は実体の `.ts` に読み替える）。
 * 相対指定子と tsconfig の `paths` エイリアス（例 `@/internal/failsafe/index.js`）を扱う。
 * どちらでもない指定子（外部パッケージ）は分類対象外なので `null`。
 */
function resolveTarget(relPath: string, specifier: string): string | null {
  if (specifier.startsWith('.')) {
    return normalize(join(dirname(relPath), specifier)).replace(/\.js$/, '.ts');
  }
  for (const [prefix, targetPrefix] of PATH_ALIASES) {
    if (specifier.startsWith(prefix)) {
      return normalize(join(targetPrefix, specifier.slice(prefix.length))).replace(/\.js$/, '.ts');
    }
  }
  return null;
}

/**
 * 対象ファイルが上位レイヤーに依存している箇所を列挙する。
 *
 * @param relPath `src/` を起点とする当該ファイルの相対パス。
 * @param source そのファイルのソース文字列。
 */
export function layerViolations(relPath: string, source: string): string[] {
  const from = classify(relPath);
  if (from === null || from.layer === TEST_SUPPORT) return [];

  const violations: string[] = [];
  for (const specifier of moduleSpecifiers(source)) {
    const target = resolveTarget(relPath, specifier);
    if (target === null) continue;
    const to = classify(target);
    if (to === null || to.layer === TEST_SUPPORT) continue;
    if (to.unit === from.unit) continue; // 同一パッケージ内は対象外

    if (RANK[to.layer] > RANK[from.layer]) {
      violations.push(
        `${relPath}: ${from.unit}(${from.layer}) -> ${to.unit}(${to.layer}) [${specifier}]`,
      );
    }
  }
  return violations;
}

/**
 * 横断ヘルパー（`src/internal` 直下のファイル）がレイヤーへ依存している辺を列挙する。
 *
 * @param relPath `src/` を起点とする当該ファイルの相対パス。
 * @param source そのファイルのソース文字列。
 */
export function crossCuttingViolations(relPath: string, source: string): string[] {
  if (classify(relPath)?.layer !== '横断') return [];

  return moduleSpecifiers(source)
    .filter((specifier) => {
      const target = resolveTarget(relPath, specifier);
      if (target === null) return false;
      const to = classify(target);
      return to !== null && to.layer !== '横断';
    })
    .map((specifier) => `${relPath} -> ${specifier}`);
}
