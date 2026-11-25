import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { boundarySupportFiles } from '../boundary-files.mjs';

export function boundaryFixture() {
  const root = mkdtempSync(join(tmpdir(), 'sdk-module-boundary-'));
  const consumer = join(root, 'consumer');
  const outside = join(root, 'producer');
  mkdirSync(join(consumer, 'node_modules'), { recursive: true });
  mkdirSync(outside);
  writeFileSync(join(consumer, 'package.json'), '{"private":true,"type":"module"}');
  const own = createRequire(import.meta.url);
  cpSync(
    dirname(own.resolve('typescript/package.json')),
    join(consumer, 'node_modules/typescript'),
    { recursive: true },
  );
  for (const name of ['runtime-node.mjs', 'runtime-bun.mjs', ...boundarySupportFiles]) {
    cpSync(new URL(`../${name}`, import.meta.url), join(consumer, name));
  }
  const sdk = join(consumer, 'node_modules/vericerts-wallet-sdk');
  mkdirSync(join(sdk, 'dist'), { recursive: true });
  writeFileSync(
    join(sdk, 'package.json'),
    JSON.stringify({
      name: 'vericerts-wallet-sdk',
      type: 'module',
      exports: {
        '.': { types: './dist/index.d.ts', import: './dist/index.js', require: './dist/index.cjs' },
      },
      dependencies: { dep: '1.0.0' },
    }),
  );
  const dependency = join(consumer, 'node_modules/dep');
  mkdirSync(dependency);
  writeFileSync(
    join(dependency, 'package.json'),
    JSON.stringify({ name: 'dep', version: '1.0.0', main: 'index.cjs', types: 'index.d.ts' }),
  );
  writeFileSync(join(dependency, 'index.cjs'), 'module.exports = {value: 1};');
  writeFileSync(join(dependency, 'index.d.ts'), 'export declare const value: number;');
  const external = join(outside, 'private.mjs');
  const externalCjs = join(outside, 'private.cjs');
  const marker = join(root, 'outside-executed');
  writeFileSync(
    external,
    `import {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(marker)},'escaped');`,
  );
  writeFileSync(
    externalCjs,
    `require('node:fs').writeFileSync(${JSON.stringify(marker)},'escaped');`,
  );
  const config = join(consumer, 'tsconfig.json');
  writeFileSync(
    config,
    JSON.stringify({
      compilerOptions: {
        target: 'ES2022',
        module: 'NodeNext',
        moduleResolution: 'NodeNext',
        types: [],
        skipLibCheck: false,
        strict: true,
        noEmit: true,
        lib: ['ES2022'],
      },
      files: ['consumer.mts'],
    }),
  );
  writeFileSync(
    join(consumer, 'consumer.mts'),
    'import {value} from "vericerts-wallet-sdk"; void value;',
  );
  function reset() {
    writeFileSync(join(sdk, 'dist/index.js'), 'export const value = 1;');
    writeFileSync(join(sdk, 'dist/index.cjs'), 'exports.value = 1;');
    writeFileSync(join(sdk, 'dist/index.d.ts'), 'export declare const value: number;');
    rmSync(marker, { force: true });
  }
  reset();
  return {
    root,
    consumer,
    outside,
    sdk,
    dependency,
    external,
    externalCjs,
    marker,
    config,
    reset,
    writeSdk(name, source) {
      writeFileSync(join(sdk, 'dist', name), source);
    },
    runtime(source) {
      writeFileSync(join(consumer, 'runtime.mjs'), source);
    },
    verifyNoMarker() {
      return !readFileSyncSafe(marker);
    },
  };
}

function readFileSyncSafe(path) {
  try {
    return readFileSync(path);
  } catch {
    return undefined;
  }
}
