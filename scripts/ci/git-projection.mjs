import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { cleanEnvironment, execute } from './environment.mjs';

const SHA = /^[0-9a-f]{40}$/;
export const validRevision = (value) => typeof value === 'string' && SHA.test(value);
const git = (cwd, args, options) => execute('git', ['-C', cwd, ...args], cwd, options);
const FIXED_DIFF = [
  'diff',
  '--text',
  '--no-ext-diff',
  '--no-textconv',
  '--no-color',
  '--no-relative',
  // Git's default index abbreviation depends on the size of each repository.
  '--full-index',
  '--src-prefix=a/',
  '--dst-prefix=b/',
  '--unified=0',
];

function copyTree(source, tree, target) {
  const entries = git(source, ['ls-tree', '--full-tree', '-rz', tree]).split('\0').filter(Boolean);
  if (!entries.length) throw new Error('Empty SDK source tree');
  for (const entry of entries) {
    const [metadata, name] = entry.split('\t');
    if (
      !/^100(?:644|755) blob [a-f0-9]{40}$/.test(metadata) ||
      name.split('/').some((part) => part === '..' || part === '.git' || part === 'node_modules') ||
      /[\r\n]/.test(name) ||
      path.isAbsolute(name)
    )
      throw new Error('SDK snapshot contains a nonportable or external file');
  }
  const tar = git(source, ['archive', '--format=tar', tree], { encoding: null });
  execute('tar', ['-xf', '-', '-C', target], target, { input: tar, encoding: null });
}

export function snapshot(repo, message) {
  git(repo, ['add', '--all']);
  git(
    repo,
    [
      '-c',
      'user.name=SDK validation',
      '-c',
      'user.email=sdk-ci@example.invalid',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '--allow-empty',
      '-qm',
      message,
    ],
    {
      env: cleanEnvironment({
        GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z',
        GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z',
      }),
    },
  );
  return git(repo, ['rev-parse', 'HEAD']).trim();
}

export function projectSdk(source, output, { head, base } = {}) {
  if (head !== undefined && !validRevision(head))
    throw new Error('head must be an exact commit SHA');
  if (base !== undefined && !validRevision(base))
    throw new Error('base must be an exact commit SHA');
  const revision = head ?? git(source, ['rev-parse', 'HEAD']).trim();
  if (!validRevision(revision)) throw new Error('Invalid source commit');
  if (git(source, ['status', '--porcelain', '--untracked-files=normal', '--', '.']).length) {
    throw new Error('SDK source must be clean before isolated validation');
  }
  const prefix = git(source, ['rev-parse', '--show-prefix']).replace(/\n$/, '').replace(/\/$/, '');
  const producerRoot = git(source, ['rev-parse', '--show-toplevel']).replace(/\r?\n$/, '');
  const baseRevision = base ? git(source, ['merge-base', base, revision]).trim() : revision;
  const selector = (sha) => (prefix ? `${sha}:${prefix}` : `${sha}^{tree}`);
  const baseTree = git(source, ['rev-parse', selector(baseRevision)]).trim();
  const headTree = git(source, ['rev-parse', selector(revision)]).trim();
  mkdirSync(output, { recursive: true });
  if (readdirSync(output).length) throw new Error('Projection output must be empty');
  const repo = path.join(output, 'sdk');
  mkdirSync(repo);
  git(repo, ['init', '-q', '--initial-branch=validation']);
  copyTree(producerRoot, baseTree, repo);
  const projectedBase = snapshot(repo, 'SDK validation base');
  for (const entry of readdirSync(repo))
    if (entry !== '.git') rmSync(path.join(repo, entry), { recursive: true, force: true });
  copyTree(producerRoot, headTree, repo);
  const projectedHead = snapshot(repo, 'SDK validation head');
  if (git(repo, ['rev-parse', 'HEAD^{tree}']).trim() !== headTree)
    throw new Error('Projected SDK tree differs');
  const originalDiff = git(producerRoot, [...FIXED_DIFF, baseTree, headTree, '--']);
  const projectedDiff = git(repo, [...FIXED_DIFF, `${projectedBase}...${projectedHead}`, '--']);
  if (originalDiff !== projectedDiff) throw new Error('Projected SDK diff differs');
  const result = {
    context: 'private-validation',
    producerRevision: revision,
    producerBase: baseRevision,
    sdkTree: headTree,
    sdkBaseTree: baseTree,
    sdkProjectedSHA: projectedHead,
    sdkProjectedBase: base ? projectedBase : null,
  };
  writeFileSync(path.join(output, 'projection.qa.json'), `${JSON.stringify(result, null, 2)}\n`);
  if (
    existsSync(path.join(repo, '.git/config')) &&
    /\[remote /.test(readFileSync(path.join(repo, '.git/config'), 'utf8'))
  ) {
    throw new Error('Isolated SDK must not retain a producer remote');
  }
  return { ...result, workspace: repo };
}
