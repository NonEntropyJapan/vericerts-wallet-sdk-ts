#!/usr/bin/env node
/**
 * CJS の公開エントリ（`dist/index.cjs` / `dist/exports/<name>.cjs`。otel を除く全サブパス）を、
 * 共有バンドル `dist/_shared.cjs` から該当サーフェスを取り出すだけの picker として生成する。
 *
 * CJS バンドルを分けると `VericertsError` に別々のクラスが割り当てられる。
 * 共有バンドルを使うと、メインとサブパスのどちらのエラーにも `instanceof` が使える。
 *
 * `dist/exports/otel.cjs` はここでは生成しない。`@opentelemetry/api` / `api-logs`（optional peer）を
 * `external` にした独立バンドルを `package.json` の `build:cjs` が出力する（`otel-adapter.ts` は
 * 内部モジュールを型でしか参照せず実体を共有する必要が無い。共有バンドルへ含めると、`require` で
 * メインだけを使う利用者の環境でも peer の解決を強いられる）。
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const distDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
mkdirSync(join(distDir, 'exports'), { recursive: true });

const banner = [
  '// 生成物: scripts/emit-cjs-pickers.mjs が出力する。直接編集しない。',
  '// 各 CJS エントリは dist/_shared.cjs を共有し、同じクラスを返す。',
  '',
].join('\n');

/**
 * 名前空間オブジェクトをそのまま `module.exports` に載せる。`_shared.cjs` 側で
 * getter として定義されているため、参照を代入するだけで各名前が引ける。
 * `__esModule` は名前空間側に無いので picker で明示し、既存の CJS 相互運用を保つ。
 */
function picker(sharedPath, surface) {
  return `${banner}const surface = require('${sharedPath}').${surface};

Object.defineProperty(module.exports, '__esModule', { value: true });
for (const key of Object.keys(surface)) {
  Object.defineProperty(module.exports, key, {
    enumerable: true,
    get: () => surface[key],
  });
}
`;
}

const SUBPATH_SURFACES = [
  'experimental',
  'aa',
  'asset',
  'common',
  'credential',
  'eudi',
  'gdpr',
  'identity',
  'keymanager',
  'oid4vci',
  'oid4vp',
  'persona',
  'trust',
];

writeFileSync(join(distDir, 'index.cjs'), picker('./_shared.cjs', 'main'));
for (const name of SUBPATH_SURFACES) {
  writeFileSync(join(distDir, 'exports', `${name}.cjs`), picker('../_shared.cjs', name));
}
mkdirSync(join(distDir, 'exports', 'experimental'), { recursive: true });
for (const [name, surface] of [
  ['eudi', 'experimentalEudi'],
  ['oid4vci', 'experimentalOid4vci'],
]) {
  writeFileSync(
    join(distDir, 'exports', 'experimental', `${name}.cjs`),
    picker('../../_shared.cjs', surface),
  );
}

console.log(
  `emitted CJS pickers: dist/index.cjs, ${SUBPATH_SURFACES.map((n) => `dist/exports/${n}.cjs`).join(', ')}`,
);
