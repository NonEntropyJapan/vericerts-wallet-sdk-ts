import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

// 利用者側の型解決を検証する。
// `npm pack --dry-run` は .d.ts の存在しか見ないため、実際に tsc で import を解決させる。
// `bun run build` 後に実行すること。

const fromHere = (relativePath) => fileURLToPath(new URL(relativePath, import.meta.url));
const fixture = fromHere('./types-fixture/consumer.ts');
const pkg = JSON.parse(readFileSync(fromHere('../package.json'), 'utf8'));

if (!existsSync(fromHere('../dist/index.d.ts'))) {
  console.error('types smoke failed: dist/ がありません。先に `bun run build` を実行してください');
  process.exit(1);
}

// フィクスチャが exports マップの全 entry を網羅していることを確認する（追加漏れ防止）。
// consumer.ts は `import * as` を束ねて使うため、1 つ欠けても tsc は欠落を検出しない。
// そのため import 文をパースして specifier の集合を取り、exports の集合と比較する
// （コメントや文字列リテラルへの誤一致を避け、exports に無い余計な import も検出する）。
const fixtureSource = readFileSync(fixture, 'utf8');
const imported = new Set(
  [...fixtureSource.matchAll(/^import \* as \w+ from '(.+)';$/gm)].map((match) => match[1]),
);
const expected = new Set(
  Object.keys(pkg.exports)
    .filter((key) => key !== './package.json')
    .map((key) => (key === '.' ? pkg.name : `${pkg.name}/${key.slice(2)}`)),
);
const missing = [...expected].filter((specifier) => !imported.has(specifier));
const unexpected = [...imported].filter((specifier) => !expected.has(specifier));
if (missing.length > 0 || unexpected.length > 0) {
  console.error(
    `types smoke failed: fixture imports mismatch exports (missing: ${missing.join(', ') || '-'}; unexpected: ${unexpected.join(', ') || '-'})`,
  );
  process.exit(1);
}

const configPath = fromHere('./types-fixture/tsconfig.json');
const cjsConfigPath = fromHere('./types-fixture/tsconfig.cjs.json');
const tsc = createRequire(import.meta.url).resolve('typescript/bin/tsc');
const resolutionModes = [
  { module: 'node16', moduleResolution: 'node16', config: configPath },
  { module: 'nodenext', moduleResolution: 'nodenext', config: configPath },
  { module: 'esnext', moduleResolution: 'bundler', config: configPath },
  { module: 'node16', moduleResolution: 'node16', config: cjsConfigPath },
  { module: 'nodenext', moduleResolution: 'nodenext', config: cjsConfigPath },
];

let failed = false;
for (const { module, moduleResolution, config } of resolutionModes) {
  const result = spawnSync(
    process.execPath,
    [tsc, '--noEmit', '-p', config, '--module', module, '--moduleResolution', moduleResolution],
    { cwd: fromHere('..'), encoding: 'utf8' },
  );
  if (result.error) {
    failed = true;
    console.error(`types smoke failed (tsc を起動できません): ${result.error.message}`);
  } else if (result.status !== 0) {
    failed = true;
    console.error(`types smoke failed (moduleResolution: ${moduleResolution}):`);
    console.error(result.stdout || result.stderr);
    // typescript は ^5 で浮動のため、依存パッケージの d.ts が新たに型エラーになることがある
    console.error(
      'hint: 依存パッケージ（@noble/*, cbor-x, @opentelemetry/*）の d.ts 由来で、SDK 起因でない可能性があります',
    );
  }
}
if (failed) process.exit(1);
console.log(
  `types smoke ok: ${Object.keys(pkg.exports).length - 1} entries x ${resolutionModes.length} resolution modes`,
);
