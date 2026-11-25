import { expect, test } from 'bun:test';
import path from 'node:path';
import { checkTypeScriptConfigs } from '../ci/typescript-config.mjs';

const root = path.resolve('/virtual-sdk');
const outside = path.resolve('/virtual-sibling');

function virtual(input: Record<string, string>, links: Record<string, string> = {}) {
  const files = new Map(
    Object.entries(input).map(([key, value]) => [path.resolve(root, key), value]),
  );
  const directories = new Set([root]);
  for (const file of [...files.keys(), ...Object.keys(links).map((key) => path.join(root, key))]) {
    for (let dir = path.dirname(file); dir !== path.dirname(dir); dir = path.dirname(dir))
      directories.add(dir);
  }
  const reads: string[] = [];
  const searches: string[] = [];
  const underRoot = (name: string) => name === root || name.startsWith(root + path.sep);
  const io = {
    useCaseSensitiveFileNames: true,
    realpath(name: string) {
      for (const [link, target] of Object.entries(links)) {
        const alias = path.join(root, link);
        if (name === alias || name.startsWith(alias + path.sep))
          return path.join(target, path.relative(alias, name));
      }
      if (files.has(name) || directories.has(name)) return name;
      throw Object.assign(new Error('Missing virtual file'), { code: 'ENOENT' });
    },
    fileExists: (name: string) => files.has(name),
    directoryExists: (name: string) => directories.has(name),
    entries(dir: string) {
      if (!underRoot(dir)) throw new Error('Unexpected external directory enumeration');
      return [
        ...new Set(
          [
            ...files.keys(),
            ...directories,
            ...Object.keys(links).map((name) => path.join(root, name)),
          ]
            .filter((name) => path.dirname(name) === dir)
            .map((name) => path.basename(name)),
        ),
      ];
    },
    readFile(name: string) {
      reads.push(name);
      if (!underRoot(name)) throw new Error('Unexpected external content read');
      return files.get(name);
    },
    search(dir: string) {
      searches.push(dir);
      if (!underRoot(dir)) throw new Error('Unexpected external directory search');
      return [...files.keys()].filter(
        (name) => name.startsWith(dir + path.sep) && name.endsWith('.ts'),
      );
    },
  };
  return {
    check: (...configs: string[]) => checkTypeScriptConfigs(root, configs, io),
    reads,
    searches,
  };
}

const local = 'export interface Local { valid: true }';
const preset = { compilerOptions: { types: [], noEmit: true, noLib: true } };
const config = (entries: object) => JSON.stringify({ ...preset, ...entries });

test('reads inherited and referenced SDK projects and transitive own declarations', () => {
  const fs = virtual({
    'tsconfig.json': config({
      extends: './settings/base.json',
      files: ['src/root.ts'],
      references: [{ path: './child' }],
    }),
    'settings/base.json': JSON.stringify({ compilerOptions: { baseUrl: '../src' } }),
    'child/tsconfig.json': config({
      compilerOptions: { types: [], noLib: true, composite: true },
      files: ['child.ts'],
    }),
    'child/child.ts': local,
    'src/root.ts': "import type {Dep} from 'test-dep'; export type Root=Dep;",
    'node_modules/test-dep/package.json': '{"name":"test-dep","types":"local.d.ts"}',
    'node_modules/test-dep/local.d.ts': 'export type Dep=true;',
  });
  expect(fs.check('tsconfig.json')).toEqual([]);
  for (const file of [
    'settings/base.json',
    'child/tsconfig.json',
    'child/child.ts',
    'node_modules/test-dep/local.d.ts',
  ])
    expect(fs.reads).toContain(path.join(root, file));
});

test('rejects explicit outside config paths without reading or globbing them', () => {
  for (const entries of [
    { files: [path.join(outside, 'type.d.ts')] },
    { include: [path.join(outside, '**/*.ts')] },
    { references: [{ path: outside }] },
    { extends: ['./sdk-base.json', path.join(outside, 'tsconfig.json')] },
    { compilerOptions: { typeRoots: [path.join(outside, 'types')] } },
    { compilerOptions: { types: ['@types/node', path.join(outside, 'types')] } },
    { compilerOptions: { baseUrl: outside } },
    { compilerOptions: { rootDirs: ['src', outside] } },
    { compilerOptions: { paths: { '@/*': ['../virtual-sibling/*'] } } },
  ]) {
    const fs = virtual({
      'tsconfig.json': config({ files: ['src/root.ts'], ...entries }),
      'sdk-base.json': '{}',
      'src/root.ts': local,
    });
    const problems = fs.check('tsconfig.json');
    expect(problems, JSON.stringify(entries)).toHaveLength(1);
    expect(problems[0]).toContain('config path escapes SDK');
    expect(fs.reads).toEqual([path.join(root, 'tsconfig.json')]);
    expect(fs.searches).toEqual([]);
  }
});

test('rejects an outside symlink before a wildcard search or a source read', () => {
  const fs = virtual(
    { 'tsconfig.json': config({ include: ['src/**/*.ts'] }), 'src/root.ts': local },
    { 'src/linked': outside },
  );
  expect(fs.check('tsconfig.json')).toEqual(['tsconfig.json: TypeScript path symlink escapes SDK']);
  expect(fs.searches).toEqual([]);
  expect(fs.reads).toEqual([path.join(root, 'tsconfig.json')]);
});

test('checks transitive explicit declaration references before asking the host to read them', () => {
  const fs = virtual({
    'tsconfig.json': config({ files: ['src/root.ts'] }),
    'src/root.ts': '/// <reference path="./contained.d.ts" />\nexport {};',
    'src/contained.d.ts': `/// <reference path="${outside}/types.d.ts" />`,
  });
  expect(fs.check('tsconfig.json')).toEqual(['tsconfig.json: config path escapes SDK']);
  expect(fs.reads).toContain(path.join(root, 'src/contained.d.ts'));
  expect(fs.reads.every((name) => name.startsWith(root + path.sep))).toBe(true);
});

test('rejects existing empty, malformed and missing-input configurations', () => {
  for (const source of [
    config({ files: [] }),
    config({ files: ['missing.ts'] }),
    config({ include: 'src' }),
  ]) {
    const fs = virtual({ 'tsconfig.json': source });
    expect(fs.check('tsconfig.json')).toHaveLength(1);
  }
});

test('resolves a linked config relative to the requested SDK path', () => {
  const fs = virtual(
    {
      'actual/base.json': config({ files: ['input.ts'] }),
      'client/input.ts': local,
    },
    { 'client/tsconfig.json': path.join(root, 'actual/base.json') },
  );
  expect(fs.check('client/tsconfig.json')).toEqual([]);
  expect(fs.reads).toContain(path.join(root, 'client/input.ts'));
});

test('checks explicit dependencies and package declaration metadata before trying to load them', () => {
  for (const field of ['types', 'typings', 'main', 'typesVersions']) {
    const external = path.join(outside, 'types.d.ts');
    const pkg =
      field === 'typesVersions'
        ? { typesVersions: { '*': { '*': [external] } } }
        : { [field]: external };
    const fs = virtual({
      'tsconfig.json': config({ files: ['src/root.ts'] }),
      'src/root.ts': "import type { Dep } from 'test-dep'; export type Root=Dep;",
      'node_modules/test-dep/package.json': JSON.stringify(pkg),
      'node_modules/test-dep/index.d.ts': 'export type Dep=true;',
    });
    expect(fs.check('tsconfig.json'), field).toEqual(['tsconfig.json: config path escapes SDK']);
    expect(fs.reads).toContain(path.join(root, 'node_modules/test-dep/package.json'));
    expect(fs.reads.every((name) => name.startsWith(root + path.sep))).toBe(true);
  }
});

test('checks that explicit type packages are present in the SDK closure', () => {
  const fs = virtual({
    'tsconfig.json': config({
      compilerOptions: { noLib: true, types: ['custom-types'] },
      files: ['src/root.ts'],
    }),
    'src/root.ts': local,
    'node_modules/@types/custom-types/index.d.ts': 'declare type OwnType = true;',
  });
  expect(fs.check('tsconfig.json')).toEqual([]);
  expect(fs.reads).toContain(path.join(root, 'node_modules/@types/custom-types/index.d.ts'));

  const missing = virtual({
    'tsconfig.json': config({
      compilerOptions: { noLib: true, types: ['custom-types'] },
      files: ['src/root.ts'],
    }),
    'src/root.ts': local,
  });
  expect(missing.check('tsconfig.json')[0]).toContain(
    "Cannot find type definition file for 'custom-types'",
  );
});
