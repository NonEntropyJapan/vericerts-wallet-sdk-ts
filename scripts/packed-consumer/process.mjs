import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let npmConfigs;
function emptyNpmConfigs() {
  if (!npmConfigs) {
    const dir = mkdtempSync(join(tmpdir(), 'sdk-empty-npm-config-'));
    npmConfigs = { user: join(dir, 'user.npmrc'), global: join(dir, 'global.npmrc') };
    for (const file of Object.values(npmConfigs)) writeFileSync(file, '', { flag: 'wx' });
    process.once('exit', () => rmSync(dir, { recursive: true, force: true }));
  }
  return npmConfigs;
}

export function isolatedEnv(extra = {}, cwd = process.cwd()) {
  const configs = emptyNpmConfigs();
  const allowed = new Set([
    'PATH',
    'HOME',
    'TMPDIR',
    'TMP',
    'TEMP',
    'LANG',
    'LC_ALL',
    'TZ',
    'CI',
    'TERM',
    'NO_COLOR',
    'FORCE_COLOR',
    'SYSTEMROOT',
    'WINDIR',
    'CHROME_BIN',
    'PLAYWRIGHT_BROWSERS_PATH',
    'NPM_CONFIG_CACHE',
    'npm_config_cache',
  ]);
  const input = { ...process.env, ...extra };
  const env = Object.fromEntries(Object.entries(input).filter(([key]) => allowed.has(key)));
  const cache =
    extra.NPM_CONFIG_CACHE ??
    extra.npm_config_cache ??
    input.NPM_CONFIG_CACHE ??
    input.npm_config_cache;
  delete env.npm_config_cache;
  if (cache) env.NPM_CONFIG_CACHE = cache;
  return {
    ...env,
    NODE_PATH: '',
    NODE_OPTIONS: '',
    TAR_OPTIONS: '',
    COPYFILE_DISABLE: '1',
    COPY_EXTENDED_ATTRIBUTES_DISABLE: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    npm_config_userconfig: configs.user,
    npm_config_globalconfig: configs.global,
    PWD: cwd,
    INIT_CWD: cwd,
  };
}

export function run(command, args, cwd, extraEnv = {}) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    env: isolatedEnv(extraEnv, cwd),
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${command} failed\n${result.error ?? ''}\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout;
}

export const installArgs = [
  'install',
  '--ignore-scripts',
  '--legacy-peer-deps',
  '--no-audit',
  '--no-fund',
  '--workspaces=false',
];
