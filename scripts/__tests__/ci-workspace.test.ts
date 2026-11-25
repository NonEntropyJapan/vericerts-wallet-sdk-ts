import { afterAll, describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { audit } from '../ci/audit.mjs';
import { projectSdk } from '../ci/git-projection.mjs';
import { fixture } from './gates-fixture';

const f = fixture();
const outputs: string[] = [];
afterAll(() => {
  f.close();
  for (const name of outputs) rmSync(name, { recursive: true, force: true });
});
const out = () => {
  const name = mkdtempSync(path.join(tmpdir(), 'SDK projected 空白-'));
  outputs.push(name);
  return name;
};
describe('SDK-only projection and boundaries', () => {
  test('projects exactly the SDK tree and diff without parent history or remote', () => {
    rmSync(path.join(f.root, '.git'), { recursive: true });
    f.run('git', ['init', '-q'], f.parent);
    f.git('config', 'user.name', 'SDK fixture');
    f.git('config', 'user.email', 'fixture@example.invalid');
    f.git('config', '--local', 'core.abbrev', '12');
    f.git('remote', 'add', 'origin', 'https://private.invalid/source.git');
    f.write('src/value.ts', 'export const value = 1;\n');
    const base = f.commit();
    f.write('src/value.ts', 'export const value = 2;\n');
    const head = f.commit();
    const a = projectSdk(f.root, out(), { base, head });
    const b = projectSdk(f.root, out(), { base, head });
    expect(a.sdkProjectedSHA).toBe(b.sdkProjectedSHA);
    expect(a.sdkTree).toBe(f.git('rev-parse', `${head}: sdk `));
    expect(readFileSync(path.join(a.workspace, '.git/config'), 'utf8')).not.toContain(
      'private.invalid',
    );
    expect(readFileSync(path.join(a.workspace, 'src/value.ts'), 'utf8')).toContain('value = 2');
    f.write('src/dirty.ts', 'export const dirty = 1;\n');
    expect(() => projectSdk(f.root, out(), { base })).toThrow('clean');
    rmSync(path.join(f.root, 'src/dirty.ts'));
    expect(() => projectSdk(f.root, out(), { base: '--help' })).toThrow('SHA');
  });
  test('rejects external relative/dynamic/alias and nonregistry dependencies', () => {
    try {
      f.write(
        'src/unsafe.ts',
        "import '../../private.js';\nexport const load = (target) => import(target);\n",
      );
      f.write('tsconfig.json', '{"compilerOptions":{"paths":{"external":["../outside.ts"]}}}');
      f.write('nested/package.json', '{"dependencies":{"unsafe":"file:../outside"}}');
      // One scan reports every violation without restarting Node and TypeScript per fixture.
      const result = f.node('scripts/ci/source-boundary.mjs');
      expect(result.status).toBe(1);
      expect(result.output).toContain('src/unsafe.ts:1: module path escapes SDK');
      expect(result.output).toContain('src/unsafe.ts:2: unresolved dynamic module boundary');
      expect(result.output).toMatch(/^tsconfig\.json:[^\r\n]*config path escapes SDK/m);
      expect(result.output).toContain(
        'nested/package.json: nonregistry or unsupported dependency dependencies.unsafe',
      );
    } finally {
      rmSync(path.join(f.root, 'src/unsafe.ts'));
      rmSync(path.join(f.root, 'tsconfig.json'));
      rmSync(path.join(f.root, 'nested'), { recursive: true });
    }
  });
  test('own parser cannot fallback to producer symlink or NODE_PATH', () => {
    for (const [dependency, gate] of [
      ['typescript', 'skipped-tests'],
      ['fast-xml-parser', 'test-results'],
      ['semver', 'source-boundary'],
    ]) {
      const own = path.join(f.root, 'node_modules', dependency);
      const saved = path.join(f.parent, 'foreign-node_modules', dependency);
      mkdirSync(path.dirname(saved), { recursive: true });
      f.run('mv', [own, saved]);
      symlinkSync(saved, own, 'dir');
      const command =
        gate === 'source-boundary' ? 'scripts/ci/source-boundary.mjs' : `scripts/check-${gate}.mjs`;
      expect(f.node(command).output).toContain('inside this SDK');
      rmSync(own);
      const fallbackEnv = { ...process.env, NODE_PATH: path.dirname(saved) };
      const control = spawnSync(
        'node',
        ['-e', 'console.log(require.resolve(process.argv[1]))', dependency],
        { cwd: f.root, env: fallbackEnv, encoding: 'utf8' },
      );
      expect(control.status).toBe(0);
      const result = spawnSync('node', [path.join(f.root, command)], {
        cwd: f.root,
        env: fallbackEnv,
        encoding: 'utf8',
      });
      expect(result.status).toBe(1);
      f.run('mv', [saved, own]);
    }
  });
});
describe('SDK Critical-only audit policy', () => {
  test('preserves lower severity and rejects Critical, network and invalid JSON', () => {
    const spawn =
      (stdout: string, status = 1) =>
      () => ({ stdout, status });
    expect(() => audit('.', spawn('{"pkg":[{"severity":"high"}]}'))).not.toThrow();
    expect(() =>
      audit(
        '.',
        spawn('{"pkg":[{"severity":"critical","url":"https://example.invalid/advisory"}]}'),
      ),
    ).toThrow('Critical');
    expect(() => audit('.', spawn(''))).toThrow('no report');
    expect(() => audit('.', spawn('invalid'))).toThrow();
    expect(() => audit('.', spawn('{"pkg":[{}]}'))).toThrow('severity');
    expect(() => audit('.', spawn('{}', 2))).toThrow('failed');
  });
});
