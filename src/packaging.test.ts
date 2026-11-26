import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import pkg from '../package.json' with { type: 'json' };
import {
  EXPERIMENTAL_CALLABLES,
  EXPERIMENTAL_CONSTANTS,
} from './exports/__tests__/experimental-names.fixtures';
import * as experimental from './exports/experimental';
import * as sdk from './index';
import { SDK_VERSION } from './index';

/**
 * npm パッケージとして公開可能であることを検証する回帰テスト。
 *
 * - ESM / CJS のデュアルパッケージ構成（exports 条件）
 * - 型定義（.d.ts）の宣言
 * - package.json version と SDK_VERSION の同期
 *
 * 実際のビルド成果物（dist）を用いた require / import の疎通は
 * scripts/smoke-node.mjs（ESM）と scripts/smoke-node.cjs（CJS）で検証する。
 */
describe('npm package contract', () => {
  test('is publishable (not marked private)', () => {
    expect('private' in pkg).toBe(false);
  });

  test('exposes ESM, CJS and type entry points', () => {
    expect(pkg.module).toBe('./dist/index.js');
    expect(pkg.main).toBe('./dist/index.cjs');
    expect(pkg.types).toBe('./dist/index.d.ts');
    expect(pkg.type).toBe('module');
  });

  test('exports map declares dual (import/require) with types first', () => {
    const root = pkg.exports['.'];
    expect(root.types).toEqual({
      import: './dist/index.d.ts',
      require: './dist/cjs-types/index.d.ts',
      default: './dist/index.d.ts',
    });
    expect(root.import).toBe('./dist/index.js');
    expect(root.require).toBe('./dist/index.cjs');
    // types condition must be declared first so it is resolved before code conditions.
    expect(Object.keys(root)[0]).toBe('types');
    // package.json subpath must remain resolvable for tooling.
    expect(pkg.exports['./package.json']).toBe('./package.json');
  });

  test('packs only the built distribution and its distribution documents', () => {
    expect(pkg.files).toEqual(['dist', 'LICENSE', 'NOTICE', 'sbom/sdk.cdx.json']);
  });

  test('ships the complete Apache-2.0 license declared by the SDK', () => {
    expect(pkg.license).toBe('Apache-2.0');
    const text = readFileSync(new URL('../LICENSE', import.meta.url), 'utf8');
    expect(text).toContain('Apache License');
    expect(text).toContain('Version 2.0, January 2004');
    expect(text).toContain('9. Accepting Warranty or Additional Liability.');
    expect(text).toContain('END OF TERMS AND CONDITIONS');
    expect(text).toContain('See the License for the specific language governing permissions');
  });

  test('declares publish metadata required by the npm registry', () => {
    expect(pkg.name).toBe('@vericerts/vericerts-wallet-sdk');
    expect(pkg.repository).toBeTruthy();
    expect(pkg.publishConfig.access).toBe('public');
  });

  test('declares the actual minimum Node patch and verified-tarball dry-run entry', () => {
    expect(pkg.engines.node).toBe('>=20.19.0');
    expect(pkg.scripts['release:dry-run']).toBe('node scripts/packed-consumer/release.mjs');
  });

  test('package.json version is kept in sync with SDK_VERSION', () => {
    expect(pkg.version).toBe(SDK_VERSION);
  });

  test('build pipeline produces both module formats and type declarations', () => {
    expect(pkg.scripts.build).toContain('build:js');
    expect(pkg.scripts.build).toContain('build:cjs');
    expect(pkg.scripts.build).toContain('build:types');
    expect(pkg.scripts['build:cjs']).toContain('--format cjs');
    expect(pkg.scripts['publish:dry-run']).toBe('npm publish --dry-run');
  });
});

/**
 * `@experimental` サブパス（`@vericerts/vericerts-wallet-sdk/experimental`）の契約を固定する回帰テスト。
 *
 * 明示的な `@experimental` 宣言は専用サブパスで公開する。
 * メインバレルへ再び載せる変更（`src/index.ts` への `export *` 追加など）をここで落とす。
 * 型はランタイムに実体を持たないため、値として公開される名前を検査する。件数は下の
 * 「covers every callable」テストが実サーフェスと突き合わせて維持する。
 */

describe('experimental subpath contract', () => {
  test('exports map declares ./experimental with types first', () => {
    const sub = pkg.exports['./experimental'];
    expect(sub).toBeDefined();
    // types condition must be declared first so it is resolved before code conditions.
    expect(Object.keys(sub)[0]).toBe('types');
    expect(sub.types).toEqual({
      import: './dist/exports/experimental.d.ts',
      require: './dist/cjs-types/exports/experimental.d.ts',
      default: './dist/exports/experimental.d.ts',
    });
    expect(sub.import).toBe('./dist/exports/experimental.js');
    expect(sub.require).toBe('./dist/exports/experimental.cjs');
    expect(sub.default).toBe('./dist/exports/experimental.js');
  });

  test('build pipeline emits the experimental entry for both module formats', () => {
    expect(pkg.scripts['build:js']).toContain('./src/exports/experimental.ts');
    // CJS は共有バンドル + picker（下のテスト）で両サーフェスを出す。
    expect(pkg.scripts['build:cjs']).toContain('emit-cjs-pickers.mjs');
  });

  /**
   * CJS は**単一バンドル**（`dist/_shared.cjs`）に両サーフェスを束ね、`dist/index.cjs` と
   * `dist/exports/experimental.cjs` はそこから取り出すだけの picker にする。
   *
   * メインと `./experimental` を別々にバンドルすると内部モジュールの実体が 2 つになり、
   * `./experimental` が投げたエラーが `main.VericertsError` の `instanceof` に一致しなくなる
   * （利用者の `catch` が無警告で壊れる）。ESM は `--splitting` の共有チャンクで同じ性質を得る。
   * 実際に `instanceof` が成立することは `scripts/smoke-node.cjs` が実ビルドで検証する。
   */
  test('the CJS build bundles both surfaces once and re-exports them from a shared bundle', () => {
    expect(pkg.scripts['build:cjs']).toContain('./src/cjs-entry.ts');
    expect(pkg.scripts['build:cjs']).toContain('./dist/_shared.cjs');
    // 旧構成（2 バンドル）へ戻していないこと。
    expect(pkg.scripts['build:cjs']).not.toContain('./src/exports/experimental.ts');
    expect(pkg.scripts['build:cjs']).not.toContain('./src/index.ts');
  });

  /**
   * ESM は `--splitting` で共有チャンクを切り出すため、チャンク名に内容ハッシュが入る
   * （`dist/index-<hash>.js`）。`dist` を消さずに再ビルドすると**古いハッシュのチャンクが残り**、
   * `files` の `dist` がそれを公開 tarball に同梱してしまう。build の先頭で必ず消すこと。
   */
  test('build cleans dist first so stale hashed chunks are never published', () => {
    expect(pkg.scripts['build:clean']).toBe('rm -rf ./dist');
    expect(pkg.scripts.build.indexOf('build:clean')).toBeLessThan(
      pkg.scripts.build.indexOf('build:js'),
    );
  });

  test('the main barrel exposes none of the experimental names', () => {
    const main = sdk as unknown as Record<string, unknown>;
    const leaked = [...EXPERIMENTAL_CALLABLES, ...Object.keys(EXPERIMENTAL_CONSTANTS)].filter(
      (name) => main[name] !== undefined,
    );
    expect(leaked).toEqual([]);
  });

  for (const name of EXPERIMENTAL_CALLABLES) {
    test(`./experimental exposes ${name} as a callable`, () => {
      expect(typeof (experimental as unknown as Record<string, unknown>)[name]).toBe('function');
    });
  }

  /**
   * 上の per-name テストは**一覧に載った名前しか見ない**ため、`exports/experimental.ts` に新しい
   * 関数を追加して一覧に足し忘れた場合を検出できない（実際に 4 名が漏れていた）。漏れた名前は
   * メインバレルへの流出検査（`the main barrel exposes none of the experimental names`）の
   * 対象からも外れるので、件数の一致を機械的に確認する。
   */
  test('EXPERIMENTAL_CALLABLES covers every callable exposed by the subpath', () => {
    const surface = experimental as unknown as Record<string, unknown>;
    const actual = Object.keys(surface)
      .filter((name) => typeof surface[name] === 'function')
      .sort();
    expect(actual).toEqual([...EXPERIMENTAL_CALLABLES].sort());
  });

  for (const [name, kind] of Object.entries(EXPERIMENTAL_CONSTANTS)) {
    test(`./experimental exposes ${name} as ${kind}`, () => {
      expect(typeof (experimental as unknown as Record<string, unknown>)[name]).toBe(kind);
    });
  }
});

/**
 * `./otel` サブパス（OpenTelemetry アダプタ）の契約を固定する回帰テスト。
 *
 * `@opentelemetry/api` / `api-logs` は optional peer のため、ESM・CJS いずれのビルドでも
 * external にして裸 import/require として残す。インライン展開すると peer 宣言が実体と食い違い、
 * 利用者のインストール版とは別のコピーが埋め込まれる。実成果物（dist）に対する検証は
 * `scripts/smoke-node.mjs` / `scripts/smoke-node.cjs` が行う。
 */
describe('otel subpath contract', () => {
  test('exports map declares ./otel with types first and ESM/CJS entries', () => {
    const sub = pkg.exports['./otel'];
    expect(sub).toBeDefined();
    expect(Object.keys(sub)[0]).toBe('types');
    expect(sub.types).toEqual({
      import: './dist/exports/otel.d.ts',
      require: './dist/cjs-types/exports/otel.d.ts',
      default: './dist/exports/otel.d.ts',
    });
    expect(sub.import).toBe('./dist/exports/otel.js');
    expect(sub.require).toBe('./dist/exports/otel.cjs');
    expect(sub.default).toBe('./dist/exports/otel.js');
  });

  test('declares the OpenTelemetry packages as optional peers', () => {
    for (const name of ['@opentelemetry/api', '@opentelemetry/api-logs']) {
      expect(Object.keys(pkg.peerDependencies)).toContain(name);
      expect(pkg.peerDependenciesMeta[name as keyof typeof pkg.peerDependenciesMeta].optional).toBe(
        true,
      );
    }
  });

  test('ESM build emits the otel entry and keeps the peers external', () => {
    expect(pkg.scripts['build:js']).toContain('./src/exports/otel.ts');
    expect(pkg.scripts['build:js']).toContain('--external @opentelemetry/api ');
    expect(pkg.scripts['build:js']).toContain('--external @opentelemetry/api-logs');
  });

  test('CJS build emits otel.cjs as its own bundle with the peers external, not in _shared.cjs', () => {
    const build = pkg.scripts['build:cjs'];
    expect(build).toContain('./src/exports/otel.ts --outfile ./dist/exports/otel.cjs');
    expect(build).toContain('--external @opentelemetry/api ');
    expect(build).toContain('--external @opentelemetry/api-logs');
    // 共有バンドルのエントリ（cjs-entry.ts）に otel を含めると、メインの require が peer を要求する。
    const cjsEntry = readFileSync(new URL('./cjs-entry.ts', import.meta.url), 'utf8');
    expect(cjsEntry).not.toMatch(/^\s*import .* from '\.\/exports\/otel/m);
  });
});
