import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { cleanEnvironment } from '../ci/environment.mjs';

function readPackage(directory: string, name: string): boolean {
  try {
    return JSON.parse(readFileSync(path.join(directory, 'package.json'), 'utf8')).name === name;
  } catch {
    if (path.dirname(directory) === directory) throw new Error(`Missing dependency ${name}`);
    return false;
  }
}
const sdk = fileURLToPath(new URL('../../', import.meta.url));
export function fixture() {
  const parent = mkdtempSync(path.join(tmpdir(), 'SDK gates 空白-'));
  const root = path.join(parent, ' sdk ');
  mkdirSync(root);
  mkdirSync(path.join(root, 'scripts'));
  for (const name of ['lib', 'ci'])
    cpSync(path.join(sdk, 'scripts', name), path.join(root, 'scripts', name), { recursive: true });
  for (const name of ['coverage', 'diff-coverage', 'skipped-tests', 'test-results'])
    cpSync(
      path.join(sdk, 'scripts', `check-${name}.mjs`),
      path.join(root, 'scripts', `check-${name}.mjs`),
    );
  const packed = path.join(sdk, 'scripts/packed-consumer');
  cpSync(packed, path.join(root, 'scripts/packed-consumer'), {
    recursive: true,
    filter: (file) => file !== path.join(packed, 'tests') && !file.endsWith('.test.mjs'),
  });
  mkdirSync(path.join(root, 'node_modules'));
  const copied = new Set<string>();
  const copyDependency = (name: string, owner = sdk) => {
    if (copied.has(name)) return;
    let search = owner;
    while (!existsSync(path.join(search, 'node_modules', name, 'package.json'))) {
      if (search === sdk || path.dirname(search) === search)
        throw new Error(`Missing SDK-owned dependency ${name}`);
      search = path.dirname(search);
    }
    const directory = path.join(search, 'node_modules', name);
    if (!readPackage(directory, name)) throw new Error(`Unexpected dependency ${name}`);
    copied.add(name);
    const target = path.join(root, 'node_modules', name);
    mkdirSync(path.dirname(target), { recursive: true });
    cpSync(realpathSync(directory), target, { recursive: true });
    const manifest = JSON.parse(readFileSync(path.join(directory, 'package.json'), 'utf8'));
    for (const child of Object.keys(manifest.dependencies ?? {})) copyDependency(child, directory);
  };
  copyDependency('typescript');
  copyDependency('fast-xml-parser');
  copyDependency('semver');
  const write = (name: string, value: string) => {
    mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    writeFileSync(path.join(root, name), value);
  };
  write(
    'package.json',
    JSON.stringify({
      name: '@vericerts/vericerts-wallet-sdk',
      type: 'module',
      devDependencies: {
        typescript: '5.9.3',
        'fast-xml-parser': '5.12.1',
        semver: '7.8.6',
      },
    }),
  );
  write('.gitignore', 'node_modules/\ncoverage/\n');
  const run = (command: string, args: string[], cwd = root) => {
    const result = spawnSync(command, args, { cwd, env: cleanEnvironment(), encoding: 'utf8' });
    if (result.error) throw result.error;
    return { status: result.status, output: `${result.stdout}${result.stderr}` };
  };
  const git = (...args: string[]) => {
    const result = run('git', args);
    if (result.status !== 0) throw new Error(result.output);
    return result.output.trim();
  };
  git('init', '-q');
  git('config', 'user.name', 'SDK fixture');
  git('config', 'user.email', 'fixture@example.invalid');
  const commit = () => {
    git('add', '.');
    git('commit', '-qm', 'SDK fixture');
    return git('rev-parse', 'HEAD');
  };
  commit();
  return {
    root,
    parent,
    write,
    run,
    git,
    commit,
    cli: (name: string, args: string[] = []) =>
      run('node', [path.join(root, 'scripts', `check-${name}.mjs`), ...args]),
    node: (name: string, args: string[] = []) => run('node', [path.join(root, name), ...args]),
    read: (name: string) => readFileSync(path.join(root, name), 'utf8'),
    close: () => rmSync(parent, { recursive: true, force: true }),
  };
}
export function lcov(file: string, hit: number, found = 100) {
  return `SF:${file}\n${Array.from({ length: found }, (_, i) => `DA:${i + 1},${i < hit ? 1 : 0}`).join('\n')}\nend_of_record\n`;
}
export function junit(files: string[], status = '') {
  return `<testsuites tests="${files.length}">${files.map((file) => `<testsuite file="${file}"><testcase file="${file}" name="case">${status}</testcase></testsuite>`).join('')}</testsuites>`;
}
