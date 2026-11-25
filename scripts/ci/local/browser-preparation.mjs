import assert from 'node:assert/strict';
import {
  appendFileSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
} from 'node:fs';
import path from 'node:path';
import { installArgs } from '../../packed-consumer/process.mjs';
import { execute } from '../environment.mjs';

const cachePrefix = 'sdk-playwright-';
const readJson = (file) => JSON.parse(readFileSync(file, 'utf8'));

export function prepareChromium(workspace, { env = process.env, run = execute } = {}) {
  const root = realpathSync(workspace);
  const fixture = path.join(root, 'test/browser-consumer');
  const modules = path.join(root, 'node_modules');
  assert.equal(realpathSync(fixture), fixture, 'Browser fixture must belong to the SDK workspace');
  assert.equal(realpathSync(modules), modules, 'Install the prepared SDK before Chromium');

  const pin = readJson(path.join(fixture, 'package.json')).devDependencies['playwright-core'];
  assert.match(pin, /^\d+\.\d+\.\d+$/, 'Playwright must be pinned to an exact version');
  const lock = readJson(path.join(fixture, 'package-lock.json'));
  assert.equal(
    lock.packages['node_modules/playwright-core'].version,
    pin,
    'Playwright lock pin differs',
  );

  const fixtureModules = path.join(fixture, 'node_modules');
  if (existsSync(fixtureModules)) {
    assert.equal(
      realpathSync(fixtureModules),
      fixtureModules,
      'Browser fixture dependencies must be local',
    );
  }
  // Progress goes to stderr so the local CLI can print only the managed path.
  const stdio = ['ignore', 2, 2];
  run('npm', ['ci', ...installArgs.slice(1)], fixture, { stdio });
  const playwright = path.join(fixtureModules, 'playwright-core');
  const cli = path.join(playwright, 'cli.js');
  assert.ok(
    lstatSync(cli).isFile() && realpathSync(cli) === cli,
    'Expected the fixture Playwright CLI',
  );
  assert.equal(
    readJson(path.join(playwright, 'package.json')).version,
    pin,
    'Installed Playwright pin differs',
  );

  const browsers = mkdtempSync(path.join(modules, cachePrefix));
  try {
    assert.ok(!/[\r\n]/.test(browsers), 'Browser cache path cannot contain a line break');
    run(process.execPath, [cli, 'install', 'chromium'], fixture, {
      stdio,
      env: { PLAYWRIGHT_BROWSERS_PATH: browsers, CHROME_BIN: '' },
    });
    if (env.GITHUB_ENV) {
      appendFileSync(env.GITHUB_ENV, `PLAYWRIGHT_BROWSERS_PATH=${browsers}\nCHROME_BIN=\n`);
    }
    return browsers;
  } catch (error) {
    rmSync(browsers, { recursive: true, force: true });
    throw error;
  }
}

export function requirePreparedChromium(workspace, env = process.env) {
  const modules = path.join(realpathSync(workspace), 'node_modules');
  const browsers = env.PLAYWRIGHT_BROWSERS_PATH;
  assert.ok(
    browsers &&
      path.dirname(browsers) === modules &&
      path.basename(browsers).startsWith(cachePrefix) &&
      !env.CHROME_BIN &&
      lstatSync(browsers).isDirectory() &&
      realpathSync(browsers) === browsers,
    'Run prepared.mjs browser before the CI SDK artifact producer',
  );
}
