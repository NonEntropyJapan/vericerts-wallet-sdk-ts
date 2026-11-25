import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
export function git(root, args) {
  return execFileSync('git', ['-C', root, '-c', 'core.excludesFile=', ...args], {
    env: Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_'))),
    encoding: 'utf8',
    maxBuffer: 1 << 28,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}
export function gitPrefix(root) {
  if (git(root, ['rev-parse', '--is-inside-work-tree']) !== 'true\n')
    throw new Error('SDK must be a Git worktree');
  return git(root, ['rev-parse', '--show-prefix']).replace(/\n$/, '').replace(/\/$/, '');
}
export function listRepoFiles(root, trackedOnly = false) {
  gitPrefix(root);
  const args = ['ls-files', '-z', '--cached'];
  if (!trackedOnly) args.push('--others', '--exclude-standard');
  args.push('--', '.');
  return [...new Set(git(root, args).split('\0').filter(Boolean))]
    .filter((file) => existsSync(path.join(root, file)))
    .sort();
}
