import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { isolatedEnv } from '../packed-consumer/process.mjs';

export function cleanEnvironment(extra = {}) {
  const env = isolatedEnv();
  delete env.PWD;
  delete env.INIT_CWD;
  if (env.PATH)
    env.PATH = env.PATH.split(path.delimiter)
      .filter((part) => !part.replace(/\\/g, '/').endsWith('/node_modules/.bin'))
      .join(path.delimiter);
  return { ...env, ...extra };
}

export function execute(command, args, cwd, options = {}) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    ...options,
    env: { ...cleanEnvironment(), ...options.env, PWD: cwd, INIT_CWD: cwd },
  });
  if (result.error || result.status !== 0)
    throw new Error(
      `${command} failed (${result.status}): ${result.error ?? ''}\n${result.stderr ?? ''}`,
    );
  return result.stdout;
}
