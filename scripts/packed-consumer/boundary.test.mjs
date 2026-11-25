import { afterAll, beforeAll, expect, test } from 'bun:test';
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkSdkSyntax } from './preflight.mjs';
import { isolatedEnv, run } from './process.mjs';
import { checkPublishResult } from './publish-result.mjs';
import { boundaryFixture } from './tests/boundary-fixtures.mjs';
import { checkTypeConfig } from './typescript-check.mjs';

let f;
beforeAll(() => {
  f = boundaryFixture();
});
afterAll(() => {
  rmSync(f.root, { recursive: true, force: true });
});

test('own TypeScript libs and dependency declarations stay inside consumer', () => {
  f.reset();
  f.writeSdk('index.d.ts', 'export {value} from "dep";');
  const files = checkTypeConfig(f.consumer, f.config);
  expect(files.some((name) => name.includes('node_modules/typescript/lib/lib.es2022.d.ts'))).toBe(
    true,
  );
  expect(files.some((name) => name.endsWith('node_modules/dep/index.d.ts'))).toBe(true);
  expect(files.every((name) => name.startsWith(`${realpathSync(f.consumer)}/`))).toBe(true);
});

test('triple slash path/types and absolute/import-type declarations cannot read producer types', () => {
  const external = join(f.outside, 'private.d.ts');
  writeFileSync(external, 'declare const privateOnly: string; export declare const value: number;');
  for (const source of [
    `/// <reference path=${JSON.stringify(external)} />\nexport declare const value:number;`,
    `/// <reference types=${JSON.stringify(external)} />\nexport declare const value:number;`,
    `export {value} from ${JSON.stringify(external)};`,
    `export declare const value: import(${JSON.stringify(external)}).value;`,
  ]) {
    f.reset();
    f.writeSdk('index.d.ts', source);
    expect(() => checkTypeConfig(f.consumer, f.config)).toThrow();
    expect(() => checkSdkSyntax(f.consumer, f.sdk)).toThrow();
  }
});

test('the actual compiler refuses symlinked declarations outside the consumer', () => {
  f.reset();
  const path = join(f.outside, 'types.d.ts');
  writeFileSync(path, 'export declare const value:number;');
  const link = join(f.sdk, 'dist/linked.d.ts');
  symlinkSync(path, link);
  try {
    f.writeSdk('index.d.ts', 'export {value} from "./linked.js";');
    expect(() => checkTypeConfig(f.consumer, f.config)).toThrow();
  } finally {
    rmSync(link);
  }
});

test('SDK AST rejects escaped, bound, require and file URL module escapes before execution', () => {
  for (const source of [
    `import ${JSON.stringify(f.external)};export const value=1;`,
    `import ${JSON.stringify(f.external).replace('/producer/', '/pro\\u0064ucer/')};export const value=1;`,
    `export * from ${JSON.stringify(f.external)};`,
    `const target=${JSON.stringify(f.external)};await import(target);export const value=1;`,
    `import {createRequire as make} from 'node:module';const load=make(import.meta.url);load(${JSON.stringify(f.externalCjs)});export const value=1;`,
    `await import(new URL(${JSON.stringify(pathToFileURL(f.external).href)},import.meta.url));export const value=1;`,
  ]) {
    f.reset();
    f.writeSdk('index.js', source);
    expect(() => checkSdkSyntax(f.consumer, f.sdk)).toThrow();
    expect(existsSync(f.marker)).toBe(false);
  }
});

test('SDK AST permits comments, relative URL modules, dependencies and native builtins', () => {
  f.reset();
  f.writeSdk('sibling.js', 'export const local=1;');
  f.writeSdk(
    'index.js',
    `// import '/producer/private.js'\nimport 'node:fs';import 'dep';await import(new URL('./sibling.js',import.meta.url));export const value=1;`,
  );
  expect(checkSdkSyntax(f.consumer, f.sdk)).toBeGreaterThan(0);
  rmSync(join(f.sdk, 'dist/sibling.js'));
});

for (const binary of ['node', 'bun']) {
  test(`${binary} runtime guard permits own dependency and builtin loads`, () => {
    f.reset();
    const copy = join(f.consumer, 'sdk-copy');
    rmSync(copy, { recursive: true, force: true });
    cpSync(f.sdk, copy, { recursive: true });
    f.runtime(
      `import {createRequire} from 'node:module';import 'node:fs';import 'dep';const req=createRequire(import.meta.url);if(req('dep').value!==1)throw new Error('wrong CJS value');if(req('./sdk-copy/dist/index.cjs').value!==1)throw new Error('wrong copy');await import('vericerts-wallet-sdk');`,
    );
    expect(() =>
      run(binary, [binary === 'bun' ? 'runtime-bun.mjs' : 'runtime-node.mjs'], f.consumer),
    ).not.toThrow();
  });
  test(`${binary} runtime guard refuses dynamic external import and masked CJS require before side effects`, () => {
    for (const source of [
      `const path=${JSON.stringify(f.external)};try{await import(path);}catch{};`,
      `import {createRequire} from 'node:module';const req=createRequire(import.meta.url);try{req(${JSON.stringify(f.externalCjs)});}catch{};`,
      `import 'dep';`,
    ]) {
      f.reset();
      writeFileSync(
        join(f.dependency, 'index.cjs'),
        `try{require(${JSON.stringify(f.externalCjs)});}catch{};module.exports={value:1};`,
      );
      f.runtime(source);
      expect(() =>
        run(binary, [binary === 'bun' ? 'runtime-bun.mjs' : 'runtime-node.mjs'], f.consumer),
      ).toThrow();
      expect(existsSync(f.marker)).toBe(false);
    }
    writeFileSync(join(f.dependency, 'index.cjs'), 'module.exports={value:1};');
  });
  test(`${binary} runtime guard rejects symlinks and consumer-prefix lookalikes`, () => {
    f.reset();
    const link = join(f.consumer, 'linked.mjs');
    symlinkSync(f.external, link);
    const lookalike = `${f.consumer}-outside`;
    mkdirSync(lookalike, { recursive: true });
    writeFileSync(join(lookalike, 'private.mjs'), readFileSync(f.external));
    try {
      for (const target of ['./linked.mjs', join(lookalike, 'private.mjs')]) {
        f.runtime(`const target=${JSON.stringify(target)};try{await import(target);}catch{};`);
        expect(() =>
          run(binary, [binary === 'bun' ? 'runtime-bun.mjs' : 'runtime-node.mjs'], f.consumer),
        ).toThrow();
        expect(existsSync(f.marker)).toBe(false);
      }
    } finally {
      rmSync(link);
    }
  });
  test(`${binary} runtime guard retains failure after a caught delayed require`, () => {
    f.reset();
    f.runtime(
      `import{createRequire}from'node:module';const req=createRequire(import.meta.url);setTimeout(()=>{try{req(${JSON.stringify(f.externalCjs)});}catch{}},10);`,
    );
    expect(() =>
      run(binary, [binary === 'bun' ? 'runtime-bun.mjs' : 'runtime-node.mjs'], f.consumer),
    ).toThrow();
    expect(existsSync(f.marker)).toBe(false);
  });
}

test('publisher metadata normalizes npm10 object/npm11 map/array and rejects wrong or extra artifacts', () => {
  const artifact = {
    name: 'vericerts-wallet-sdk',
    version: '0.1.0',
    integrity: 'sha512-abc',
    bytes: 123,
  };
  const item = {
    name: artifact.name,
    version: artifact.version,
    integrity: artifact.integrity,
    size: artifact.bytes,
  };
  for (const value of [item, { [item.name]: item }, [item]])
    expect(() => checkPublishResult(JSON.stringify(value), artifact)).not.toThrow();
  for (const value of [
    [item, item],
    { [item.name]: item, other: { ...item, name: 'other' } },
    { bad: item },
    { ...item, name: 'other' },
    { ...item, version: '1.0.0' },
    { ...item, integrity: 'sha512-bad' },
    { ...item, size: 124 },
  ]) {
    expect(() => checkPublishResult(JSON.stringify(value), artifact)).toThrow();
  }
});

test('child environment drops producer/auth values and normalizes cwd with distinct empty npm configs', () => {
  const env = isolatedEnv(
    {
      GITHUB_WORKSPACE: '/producer',
      SDK_SOURCE_ROOT: '/producer',
      GH_TOKEN: 'secret',
      OLDPWD: '/producer',
      PWD: '/producer',
      INIT_CWD: '/producer',
    },
    f.consumer,
  );
  for (const name of ['GITHUB_WORKSPACE', 'SDK_SOURCE_ROOT', 'GH_TOKEN', 'OLDPWD'])
    expect(env[name]).toBeUndefined();
  expect(env.PWD).toBe(f.consumer);
  expect(env.INIT_CWD).toBe(f.consumer);
  expect(env.npm_config_userconfig).not.toBe(env.npm_config_globalconfig);
  expect(readFileSync(env.npm_config_userconfig, 'utf8')).toBe('');
  expect(readFileSync(env.npm_config_globalconfig, 'utf8')).toBe('');
});
