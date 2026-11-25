import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fixture } from './gates-fixture';

const f = fixture();
afterAll(() => f.close());
writeFileSync(path.join(f.parent, 'private.cjs'), 'module.exports="outside-sentinel";');
writeFileSync(
  path.join(f.parent, 'private-types.d.ts'),
  'export interface Secret {privateData:true}',
);
f.write('src/local.cjs', 'module.exports="inside-sentinel";');
f.write('src/types.ts', 'export interface Public {value:true}');
const gate = (source: string, name = 'entry.mjs') => {
  f.write(`src/${name}`, source);
  const result = f.node('scripts/ci/source-boundary.mjs');
  rmSync(path.join(f.root, 'src', name));
  return result;
};
const external = "'../../private.cjs'";
describe('SDK standard module binding boundaries', () => {
  test('the actual Node and compiler sentinel reads are rejected by the CLI', () => {
    const source = `import {createRequire} from 'node:module';const req=createRequire(import.meta.url);console.log(req(${external}));`;
    f.write('src/sentinel.mjs', source);
    expect(f.node('src/sentinel.mjs').output).toContain('outside-sentinel');
    expect(f.node('scripts/ci/source-boundary.mjs').status).toBe(1);
    rmSync(path.join(f.root, 'src/sentinel.mjs'));
    f.write(
      'src/type.ts',
      "type Private=import('../../private-types').Secret; export type{Private};",
    );
    const compiler = f.node('node_modules/typescript/bin/tsc', [
      'src/type.ts',
      '--noEmit',
      '--listFiles',
      '--skipLibCheck',
      '--moduleResolution',
      'bundler',
      '--module',
      'ESNext',
    ]);
    expect(compiler.status).toBe(0);
    expect(compiler.output).toContain('private-types.d.ts');
    expect(f.node('scripts/ci/source-boundary.mjs').status).toBe(1);
    rmSync(path.join(f.root, 'src/type.ts'));
  }, 30_000);
  test.each([
    `import {createRequire as make} from 'node:module';const alias=make;const req=alias(import.meta.url);const load=req;load(${external});`,
    `import * as Module from 'node:module';const alias=Module;alias['createRequire'](import.meta.url)(${external});`,
    `import Module from 'node:module';const {createRequire:make}=Module;make(import.meta.url)(${external});`,
    `const {createRequire:make}=require('node:module');make(__filename)(${external});`,
    `const load=require;load(${external});`,
    `import {createRequire} from 'node:module';let make;make=createRequire;const req=make(import.meta.url);req.resolve(${external});`,
    `import {createRequire} from 'node:module';createRequire.call(null,import.meta.url)(${external});`,
    `import {createRequire} from 'node:module';createRequire.apply(null,[import.meta.url])(${external});`,
    `import {createRequire} from 'node:module';const make=createRequire.bind(null);make(import.meta.url)(${external});`,
    `import {createRequire} from 'node:module';const req=createRequire(import.meta.url);req.call(null,${external});`,
    `import {createRequire} from 'node:module';const req=createRequire(import.meta.url);req.apply(null,[${external}]);`,
    `module.require(${external});`,
    `const Module=module.constructor;const owned=new Module('/outside/entry.cjs');owned.require(${external});`,
    `import Module from 'node:module';Module._load.call(null,${external});`,
    `globalThis.require(${external});`,
    `import {register as hook} from 'node:module';hook('./local.cjs','file:///outside/anchor.mjs');`,
    `import * as Module from 'node:module';Module._load(${external});`,
  ])('tracks factory/namespace/destructuring/assignment/loader aliases and invocation forms: %s', (source) => {
    expect(gate(source).status, source).toBe(1);
  }, 30_000);
  test('rejects external or unknown factory bases, capability escape and dynamic specifiers', () => {
    const outside = JSON.stringify(path.join(f.parent, 'package.json'));
    for (const source of [
      `import {createRequire} from 'node:module';const req=createRequire(${outside});req('typescript');`,
      `import {createRequire} from 'node:module';const req=createRequire(somewhere);req('typescript');`,
      `import {createRequire} from 'node:module';const req=createRequire(import.meta.url);req(unknown);`,
      `import {createRequire} from 'node:module';const make=createRequire.bind(null,${outside});const req=make(import.meta.url);req('typescript');`,
      `import {createRequire} from 'node:module';function helper(){return createRequire(import.meta.url)};helper()(${external});`,
      `import {createRequire} from 'node:module';const box={make:createRequire};box.make(import.meta.url)(${external});`,
      `import {createRequire} from 'node:module';const box={};box.make=createRequire;box.make(import.meta.url)(${external});`,
      `import {createRequire} from 'node:module';export const req=createRequire(import.meta.url);`,
      `import {createRequire} from 'node:module';const req=createRequire(import.meta.url);export{req};`,
      `export {createRequire as make} from 'node:module';`,
    ])
      expect(gate(source).status, source).toBe(1);
  }, 30_000);
  test('validates type imports, import-equals and reference paths', () => {
    for (const source of [
      "type T=import('../../private-types').Secret;",
      "import Private=require('../../private.cjs');",
      'type T=import(dynamic).Secret;',
      '/// <reference path="../../private-types.d.ts"/>\nexport {};',
    ])
      expect(gate(source, 'entry.ts').status).toBe(1);
    expect(gate("type T=import('./types').Public; export type{T};", 'entry.ts').status).toBe(0);
    expect(gate("import local=require('./local.cjs'); export=local;", 'entry.cts').status).toBe(0);
  }, 30_000);
  test('accepts own relative modules, declared tools, builtins and lexical shadowing', () => {
    const source = `import {createRequire as make} from 'node:module';const factory=make;const load=factory(import.meta.url);console.log(load('./local.cjs'));load('typescript');load('node:fs');{const load=(text)=>text;load('../../not-a-module');}`;
    f.write('src/positive.mjs', source);
    expect(f.node('src/positive.mjs').output).toContain('inside-sentinel');
    expect(f.node('scripts/ci/source-boundary.mjs').status).toBe(0);
    rmSync(path.join(f.root, 'src/positive.mjs'));
    expect(
      gate(
        "import {createRequire} from 'node:module';const req=createRequire(new URL('./anchor.cjs',import.meta.url));req('./local.cjs');",
      ).status,
    ).toBe(0);
    expect(
      gate(
        "import {register} from 'node:module';register('./local.cjs',{parentURL:import.meta.url});",
      ).status,
    ).toBe(0);
  }, 30_000);
  test('rejects a symlink factory base even for a declared tool', () => {
    mkdirSync(path.join(f.parent, 'foreign'));
    symlinkSync(path.join(f.parent, 'foreign'), path.join(f.root, 'src/foreign'), 'dir');
    expect(
      gate(
        "import {createRequire} from 'node:module';const req=createRequire(new URL('./foreign/anchor.cjs',import.meta.url));req('typescript');",
      ).status,
    ).toBe(1);
    rmSync(path.join(f.root, 'src/foreign'));
  }, 30_000);
});
