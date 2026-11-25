import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { isBuiltin } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isMainModule } from '../lib/is-main-module.mjs';
import { ts } from '../lib/load-typescript.mjs';
import { listRepoFiles } from '../lib/repo-files.mjs';
import { dependencyProblems } from './dependency-policy.mjs';
import { sourceLoads } from './source-loads.mjs';
import { peerFixtureContext } from './sphereon-fixture-policy.mjs';
import { checkTypeScriptConfigs } from './typescript-config.mjs';

const SCRIPT = /\.[cm]?[jt]sx?$/;
const packageName = (specifier) =>
  specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0];
const inside = (root, target) => {
  const rel = path.relative(root, target);
  return !rel.startsWith('..') && !path.isAbsolute(rel);
};

// These distribution probes load only generated SDK output or verified package exports.
const PROBES = new Map([
  ['scripts/packed-consumer/containment.mjs', new Set(['compiler'])],
  ['scripts/packed-consumer/boundary-node.mjs', new Set(['specifier', 'Module.prototype.require'])],
  ['scripts/packed-consumer/preflight.mjs', new Set(['specifier'])],
  ['scripts/gen-notice.mjs', new Set(['dependency'])],
  ['test/browser-consumer/run.mjs', new Set(['peer'])],
  ['scripts/smoke-node.mjs', new Set(['distUrl.href'])],
  ['scripts/smoke-node.cjs', new Set(['distPath'])],
  ['scripts/packed-consumer/runtime.mjs', new Set(['name', 'pkg.name'])],
  [
    'scripts/test-support/export.test.ts',
    new Set([
      "pathToFileURL(join(materials,'tools/did-fixtures.mjs')).href",
      "pathToFileURL(join(materials,'tools/inherited-reads.mjs')).href",
    ]),
  ],
]);
const RESOLUTION_PROBES = new Map([
  [
    'test/browser-consumer/boundary-regression.mjs',
    new Set(["createRequire(join(fixture,'package.json')).resolve('boundary-dep')"]),
  ],
]);
const FACTORY_PROBES = new Map([
  ['test/browser-consumer/boundary-regression.mjs', new Set(["join(fixture,'package.json')"])],
  ['scripts/gen-notice.mjs', new Set(['noticeInput(resolve(manifest),{modulesOnly:true})'])],
  ['scripts/packed-consumer/containment.mjs', new Set(["join(consumer,'package.json')"])],
  ['scripts/packed-consumer/preflight.mjs', new Set(['file'])],
  ['scripts/packed-consumer/boundary-node.mjs', new Set(['this.filename'])],
  ['test/test-support/run-consumer.mjs', new Set(["join(root,'package.json')"])],
  ['test/browser-consumer/run.mjs', new Set(["import.meta.resolve('vericerts-wallet-sdk')"])],
]);
const GENERATED_MATERIALS = new Set(['./tools/did-fixtures.mjs', './tools/inherited-reads.mjs']);

function manifestFor(root, file) {
  let dir = path.dirname(file);
  while (inside(root, dir)) {
    const name = path.join(dir, 'package.json');
    if (existsSync(name)) return JSON.parse(readFileSync(name, 'utf8'));
    if (dir === root) break;
    dir = path.dirname(dir);
  }
  throw new Error('SDK package manifest is missing');
}

function moduleProblem(root, file, specifier, pkg) {
  if (isBuiltin(specifier) || specifier === 'bun' || specifier === 'bun:test') return null;
  if (specifier.startsWith('@/'))
    specifier = `./${path.relative(path.dirname(file), path.join(root, 'src', specifier.slice(2)))}`;
  if (specifier.startsWith('.') || path.isAbsolute(specifier) || /^[a-z]:[\\/]/i.test(specifier)) {
    const target = path.resolve(path.dirname(file), specifier);
    if (!inside(root, target)) return 'module path escapes SDK';
    const candidates = [
      target,
      target.replace(/\.[cm]?js$/, '.ts'),
      target.replace(/\.js$/, '.tsx'),
      ...['.ts', '.tsx', '.mts', '.cts', '.mjs', '.js', '.json', '/index.ts', '/index.js'].map(
        (ext) => target + ext,
      ),
    ];
    const found = candidates.find(existsSync);
    if (found && !inside(realpathSync(root), realpathSync(found)))
      return 'module symlink escapes SDK';
    const materialConsumer =
      path.relative(root, file).split(path.sep).join('/') ===
        'test/test-support/tools-consumer.mjs' && GENERATED_MATERIALS.has(specifier);
    if (!found && !materialConsumer && !target.startsWith(path.join(root, 'dist') + path.sep))
      return 'unresolved SDK module';
    return null;
  }
  const sdk = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  const declared = new Set([
    sdk.name,
    pkg.name,
    ...[sdk, pkg].flatMap((manifest) =>
      Object.keys({
        ...manifest.dependencies,
        ...manifest.devDependencies,
        ...manifest.peerDependencies,
        ...manifest.optionalDependencies,
      }),
    ),
  ]);
  return declared.has(packageName(specifier)) ? null : `undeclared module ${specifier}`;
}

export function checkSourceBoundary(root = process.cwd()) {
  root = path.resolve(root);
  const files = listRepoFiles(root);
  const scripts = files.filter((file) => SCRIPT.test(file));
  if (!scripts.length) throw new Error('No SDK sources to inspect');
  const problems = [];
  for (const relative of scripts) {
    const file = path.join(root, relative);
    if (!inside(realpathSync(root), realpathSync(file))) {
      problems.push(`${relative}: source symlink escapes SDK`);
      continue;
    }
    const pkg = manifestFor(root, file);
    const text = readFileSync(file, 'utf8');
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
    const compact = (node) => node?.getText(source).replace(/\s+/g, '');
    if (source.parseDiagnostics.length) problems.push(`${relative}: cannot parse SDK module`);
    for (const load of sourceLoads(source, file, relative)) {
      const { node, argument: expression } = load;
      const report = (problem) =>
        problems.push(
          `${relative}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}: ${problem}`,
        );
      if (load.kind === 'mutation') {
        if (!PROBES.get(relative)?.has(compact(expression)))
          report('unresolved module capability mutation');
        continue;
      }
      if (load.kind === 'factory') {
        let base = load.base;
        if (base?.startsWith('file:')) base = fileURLToPath(base);
        if (base !== undefined) {
          if (!path.isAbsolute(base) || !inside(root, path.resolve(base)))
            report('createRequire base escapes SDK');
          else {
            let existing = path.resolve(base);
            while (!existsSync(existing) && path.dirname(existing) !== existing)
              existing = path.dirname(existing);
            if (!inside(realpathSync(root), realpathSync(existing)))
              report('createRequire base symlink escapes SDK');
          }
        } else if (!FACTORY_PROBES.get(relative)?.has(compact(expression)))
          report('unresolved createRequire base');
        continue;
      }
      if (!expression) {
        report('unresolved dynamic module boundary');
        continue;
      }
      let anchor = load.anchor;
      if (anchor?.startsWith('file:')) anchor = fileURLToPath(anchor);
      if (ts.isStringLiteralLike(expression)) {
        const syntheticControl =
          load.kind === 'resolve' && RESOLUTION_PROBES.get(relative)?.has(compact(node));
        const problem = syntheticControl
          ? null
          : moduleProblem(root, anchor ?? file, expression.text, pkg);
        if (problem) report(problem);
      } else if (
        ts.isTemplateExpression(expression) &&
        expression.head.text.startsWith(`${pkg.name}/`)
      ) {
        // Bare package subpaths remain constrained by its export map.
      } else if (!PROBES.get(relative)?.has(compact(expression)))
        report('unresolved dynamic module boundary');
    }
  }
  for (const file of files.filter((name) => /(?:^|\/)package\.json$/.test(name))) {
    const pkg = JSON.parse(readFileSync(path.join(root, file), 'utf8'));
    problems.push(
      ...dependencyProblems(pkg, peerFixtureContext(root, file)).map(
        (problem) => `${file}: ${problem}`,
      ),
    );
  }
  const configs = files.filter((name) => /(?:^|\/)tsconfig[^/]*\.json$/.test(name));
  problems.push(...checkTypeScriptConfigs(root, configs));
  return { problems, files: scripts.length };
}
if (isMainModule(import.meta.url)) {
  const result = checkSourceBoundary();
  if (result.problems.length) throw new Error(result.problems.join('\n'));
  console.log(`SDK source boundary: OK (${result.files} files)`);
}
