// Run in the isolated consumer directory after installing the SDK tarball.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { gzipSync } from 'node:zlib';
import { chromium } from 'playwright-core';
import { build, preview } from 'vite';
import { browserBoundary } from './boundary.mjs';
import { checkBrowserBoundary } from './boundary-regression.mjs';

const withOtel = process.argv.includes('--otel');
const sdkRequire = createRequire(import.meta.resolve('@vericerts/vericerts-wallet-sdk'));
for (const peer of ['@opentelemetry/api', '@opentelemetry/api-logs']) {
  if (withOtel) {
    sdkRequire.resolve(peer);
  } else {
    assert.throws(
      () => sdkRequire.resolve(peer),
      { code: 'MODULE_NOT_FOUND' },
      `SDK can resolve ${peer}`,
    );
  }
}
const input = withOtel ? ['index.html', 'otel.html'] : ['index.html'];
await checkBrowserBoundary();
const result = await build({
  ...browserBoundary(),
  configFile: false,
  build: { rollupOptions: { input } },
});
const chunks = result.output.filter((item) => item.type === 'chunk');
console.log(
  JSON.stringify({
    jsBytes: chunks.reduce((n, c) => n + Buffer.byteLength(c.code), 0),
    gzipBytes: chunks.reduce((n, c) => n + gzipSync(c.code).length, 0),
  }),
);
const server = await preview({ configFile: false, preview: { host: '127.0.0.1', port: 0 } });
try {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || undefined });
  try {
    console.log(`Chromium ${browser.version()}`);
    for (const entry of input) {
      const page = await browser.newPage();
      const failure = new Promise((_, reject) => page.once('pageerror', reject));
      const probe = async () => {
        await page.goto(new URL(entry, server.resolvedUrls.local[0]).href);
        assert.deepEqual(
          await page.evaluate(() => [typeof globalThis.Buffer, typeof globalThis.process]),
          ['undefined', 'undefined'],
        );
        await page.waitForSelector('html[data-sdk-result="pass"]', { state: 'attached' });
      };
      await Promise.race([probe(), failure]);
      await page.close();
      console.log(`${entry}: passed`);
    }
  } finally {
    await browser.close();
  }
} finally {
  await server.close();
}
