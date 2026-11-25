import { expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { prepareChromium, requirePreparedChromium } from '../ci/local/browser-preparation.mjs';

const pin = '1.61.1';

function withBrowserFixture(run: (workspace: string, fixture: string) => void) {
  const workspace = realpathSync(mkdtempSync(path.join(tmpdir(), 'sdk-browser-prep-test-')));
  try {
    const fixture = path.join(workspace, 'test/browser-consumer');
    mkdirSync(fixture, { recursive: true });
    mkdirSync(path.join(workspace, 'node_modules'));
    writeFileSync(
      path.join(fixture, 'package.json'),
      JSON.stringify({ devDependencies: { 'playwright-core': pin } }),
    );
    writeFileSync(
      path.join(fixture, 'package-lock.json'),
      JSON.stringify({ packages: { 'node_modules/playwright-core': { version: pin } } }),
    );
    run(workspace, fixture);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

test('Chromium preparation uses the locked fixture CLI and exports its fresh workspace cache', () => {
  withBrowserFixture((workspace, fixture) => {
    const envFile = path.join(workspace, 'github-env');
    const playwright = path.join(fixture, 'node_modules/playwright-core');
    const cli = path.join(playwright, 'cli.js');
    const calls: string[][] = [];
    let browserCache: string | undefined;
    const browsers = prepareChromium(workspace, {
      env: { GITHUB_ENV: envFile },
      run(command, args, cwd, options) {
        expect(cwd).toBe(fixture);
        calls.push([command, ...args]);
        if (command === 'npm') {
          mkdirSync(playwright, { recursive: true });
          writeFileSync(path.join(playwright, 'package.json'), JSON.stringify({ version: pin }));
          writeFileSync(cli, '// synthetic installer fixture\n');
        } else {
          browserCache = options.env?.PLAYWRIGHT_BROWSERS_PATH;
          expect(options.env?.CHROME_BIN).toBe('');
        }
      },
    });

    expect(calls).toEqual([
      [
        'npm',
        'ci',
        '--ignore-scripts',
        '--legacy-peer-deps',
        '--no-audit',
        '--no-fund',
        '--workspaces=false',
      ],
      [process.execPath, cli, 'install', 'chromium'],
    ]);
    expect(browserCache).toBe(browsers);
    expect(path.dirname(browsers)).toBe(path.join(workspace, 'node_modules'));
    expect(readFileSync(envFile, 'utf8')).toBe(
      `PLAYWRIGHT_BROWSERS_PATH=${browsers}\nCHROME_BIN=\n`,
    );
    expect(() =>
      requirePreparedChromium(workspace, { PLAYWRIGHT_BROWSERS_PATH: browsers }),
    ).not.toThrow();
    expect(() => requirePreparedChromium(workspace, {})).toThrow('prepared.mjs browser');
    expect(() =>
      requirePreparedChromium(workspace, { PLAYWRIGHT_BROWSERS_PATH: browsers, CHROME_BIN: cli }),
    ).toThrow('prepared.mjs browser');
  });
});

test('Chromium preparation rejects a mismatched Playwright pin before running npm', () => {
  withBrowserFixture((workspace, fixture) => {
    writeFileSync(
      path.join(fixture, 'package-lock.json'),
      JSON.stringify({ packages: { 'node_modules/playwright-core': { version: '0.0.0' } } }),
    );
    const run = () => {
      throw new Error('should not run installer');
    };
    expect(() => prepareChromium(workspace, { run })).toThrow('Playwright lock pin differs');
  });
});
