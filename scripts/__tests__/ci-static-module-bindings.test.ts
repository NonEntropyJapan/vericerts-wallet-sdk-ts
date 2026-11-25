import { expect, test } from 'bun:test';
import path from 'node:path';
import { sourceLoads } from '../ci/source-loads.mjs';
import { ts } from '../lib/load-typescript.mjs';

const file = path.resolve('/fixture-sdk/src/entry.cts');

function references(text: string) {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  expect(source.parseDiagnostics).toHaveLength(0);
  return sourceLoads(source, file);
}

const origins = [
  "import { Module as Loader } from 'node:module';",
  "import { default as Loader } from 'node:module';",
  "import Loader from 'node:module';",
  "import * as Loader from 'node:module';",
  "import Loader = require('node:module');",
  "const { Module: Loader } = await import('node:module');",
  "const { Module: Loader } = require('node:module');",
  "const Loader = process.getBuiltinModule('node:module');",
  "import { getBuiltinModule as builtin } from 'node:process'; const Loader = builtin('module');",
  "import current from 'node:process'; const Loader = current.getBuiltinModule('module');",
  "const current = require('node:process'); const Loader = current.getBuiltinModule('module');",
  "const { default: { getBuiltinModule: builtin } } = await import('node:process'); const Loader = builtin('module');",
  "const { default: { Module: Loader } } = await import('node:module');",
];

test('tracks the same static factory and own module edge across Node binding forms', () => {
  for (const origin of origins) {
    const refs = references(
      `${origin} const load=Loader.createRequire(__filename); load('./local');`,
    );
    expect(
      refs.some((ref) => ref.kind === 'factory' && ref.base === file),
      origin,
    ).toBe(true);
    expect(
      refs.some((ref) => ref.kind === 'require' && ref.argument?.text === './local'),
      origin,
    ).toBe(true);
    expect(
      refs.some((ref) => ref.kind === 'unresolved'),
      origin,
    ).toBe(false);
  }
});

test('reports an unsupported module capability from the same origins using AST only', () => {
  for (const origin of origins) {
    const refs = references(`${origin} const member = Loader[unknownMember]; member('./local');`);
    expect(
      refs.some((ref) => ref.kind === 'unresolved'),
      origin,
    ).toBe(true);
  }
});

test('does not mistake non-loading builtin exports or lexical shadows for loaders', () => {
  const refs = references(`
    import { builtinModules, isBuiltin } from 'node:module';
    import { Module as Loader } from 'node:module';
    isBuiltin(builtinModules[0]);
    { const Loader = { arbitrary() {} }; Loader.arbitrary(); }
    { const process = { getBuiltinModule() {} }; process.getBuiltinModule('node:module'); }
  `);
  expect(refs.map((ref) => ref.kind)).toEqual(['import', 'import']);
});

test('reports an unresolved builtin accessor or module capability passed to an unknown consumer', () => {
  for (const text of [
    'process.getBuiltinModule(unknown);',
    'const accessor = process.getBuiltinModule; accessor(unknown);',
    "import { Module as Loader } from 'node:module'; take(Loader);",
  ]) {
    expect(
      references(text).some((ref) => ref.kind === 'unresolved'),
      text,
    ).toBe(true);
  }
});

test('diagnoses re-exports that lose Node loader provenance and preserves unrelated exports', () => {
  for (const text of [
    "export { getBuiltinModule as builtin } from 'node:process';",
    "export { default as process } from 'node:process';",
    "export * as core from 'node:process';",
    "export * from 'node:process';",
    "import core from 'node:process'; export { core };",
    "import { getBuiltinModule as builtin } from 'node:process'; export { builtin };",
    "export const core = require('node:process');",
    "export const core = (require('node:process'));",
  ])
    expect(
      references(text).some((ref) => ref.kind === 'unresolved'),
      text,
    ).toBe(true);
  expect(
    references("export { versions, type Process } from 'node:process';").map((ref) => ref.kind),
  ).toEqual(['import']);
  expect(
    references("import core from 'node:process'; export type { core };").map((ref) => ref.kind),
  ).toEqual(['import']);
  expect(
    references(
      "import { getBuiltinModule as builtin } from 'node:process'; export type { builtin };",
    ).map((ref) => ref.kind),
  ).toEqual(['import']);
});

test('rejects process namespace handoffs without blocking ordinary member reads', () => {
  for (const text of [
    'take(process);',
    "import * as core from 'node:process'; take(core);",
    "import core from 'node:process'; const box = { core };",
    'const box = { process };',
    'const box = { core: process };',
    'const { core = process } = inputs;',
    'const alias = process; const box = {}; box.core = alias;',
  ])
    expect(
      references(text).some((ref) => ref.kind === 'unresolved'),
      text,
    ).toBe(true);

  const refs = references(`
    import core from 'node:process';
    const alias = core;
    observe(alias.env.NODE_ENV);
    observe(process.env);
    observe(typeof process);
    type ProcessType = typeof core;
    export type { core };
    { const process = { env: {} }; observe(process); const box = { process }; }
  `);
  expect(refs.map((ref) => ref.kind)).toEqual(['import']);
});

test('keeps node:module type-only reference edges without exporting runtime loaders', () => {
  for (const text of [
    "export type { Module } from 'node:module';",
    "export { type Module } from 'node:module';",
    "import { Module } from 'node:module'; export type { Module };",
  ]) {
    const refs = references(text);
    expect(
      refs.map((ref) => ref.kind),
      text,
    ).toEqual(['import']);
    expect(refs[0].argument.text, text).toBe('node:module');
  }
  for (const text of [
    "export { createRequire } from 'node:module';",
    "export { type Module, createRequire } from 'node:module';",
  ])
    expect(
      references(text).some((ref) => ref.kind === 'unresolved'),
      text,
    ).toBe(true);
});
