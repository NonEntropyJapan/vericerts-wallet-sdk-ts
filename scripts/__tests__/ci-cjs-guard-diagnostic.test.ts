import { expect, test } from 'bun:test';
import path from 'node:path';
import { sourceLoads } from '../ci/source-loads.mjs';
import { ts } from '../lib/load-typescript.mjs';

const guardPath = 'scripts/packed-consumer/boundary-node.mjs';
const moduleImport = "import Module from 'node:module';";
const guardImport = "import { installCjsLoadGuard } from './cjs-load-guard.mjs';";
const install = 'installCjsLoadGuard(Module.prototype, root, cjsViolations.record);';
const installer = (body: string) => `export function installNodeBoundary() { ${body} }`;

function hasUnresolved(code: string, relative = guardPath) {
  const file = path.resolve('/virtual-sdk', relative);
  const source = ts.createSourceFile(file, code, ts.ScriptTarget.Latest, true);
  expect(source.parseDiagnostics).toHaveLength(0);
  return sourceLoads(source, file, relative).some((ref) => ref.kind === 'unresolved');
}

test('recognizes only the direct CommonJS guard installation in the Node boundary', () => {
  const valid = `${moduleImport} ${guardImport} ${installer(install)}`;
  expect(hasUnresolved(valid)).toBe(false);
  expect(hasUnresolved(valid, 'scripts/other.mjs')).toBe(true);
  expect(hasUnresolved(valid, 'scripts/packed-consumer/runtime-node.mjs')).toBe(true);
  for (const source of [
    `${moduleImport} ${installer(install)}`,
    `${moduleImport} import { installCjsLoadGuard } from './other.mjs'; ${installer(install)}`,
    `${moduleImport} import { other as installCjsLoadGuard } from './cjs-load-guard.mjs'; ${installer(install)}`,
    `${moduleImport} ${guardImport} ${install}`,
    `${moduleImport} ${guardImport} function installNodeBoundary() { ${install} }`,
    `${moduleImport} ${guardImport} export function installOtherBoundary() { ${install} }`,
    `${moduleImport} ${guardImport} ${installer(`function install() { ${install} }`)}`,
    `${moduleImport} ${guardImport} ${installer(`if (true) { ${install} }`)}`,
    ...[
      'installCjsLoadGuard?.(Module.prototype, root, cjsViolations.record);',
      "installCjsLoadGuard(Module['prototype'], root, cjsViolations.record);",
      'installCjsLoadGuard(root, Module.prototype, cjsViolations.record);',
      'installCjsLoadGuard(Module.prototype, other, cjsViolations.record);',
      'installCjsLoadGuard(Module.prototype, root, callback);',
      `${install} inspect(Module.prototype);`,
    ].map((body) => `${moduleImport} ${guardImport} ${installer(body)}`),
  ]) {
    expect(hasUnresolved(source), source).toBe(true);
  }
});
