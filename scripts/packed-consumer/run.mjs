import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectArtifact } from './archive.mjs';
import { checkBrowser } from './browser.mjs';
import { parseArgs } from './cli.mjs';
import { checkNode } from './node.mjs';
import { assertReceiptArtifact, readReceipt, saveReceipt } from './receipt.mjs';
import { COMMITTED_PROJECTION, DEVELOPMENT_SNAPSHOT } from './source-origin.mjs';

async function main() {
  const options = parseArgs(process.argv.slice(2));
  let tarball = options.tarball;
  let receiptPath = options.receipt;
  let receipt;
  if (tarball) {
    receipt = readReceipt(receiptPath);
  } else {
    // Existing-artifact mode never loads the producer or reads its Git/package/dependencies.
    const sdk = fileURLToPath(new URL('../..', import.meta.url));
    const { packDirtySdk } = await import('../ci/local/smoke-source.mjs');
    if (packDirtySdk(sdk, options)) return;
    const { produceArtifact } = await import('./producer.mjs');
    ({ tarball, receiptPath, receipt } = produceArtifact({
      ...options,
      validationOrigin: options['development-snapshot']
        ? DEVELOPMENT_SNAPSHOT
        : COMMITTED_PROJECTION,
    }));
    assert.equal(existsSync(receiptPath), false, 'Refusing to overwrite a producer receipt');
  }
  const { pkg, artifact } = inspectArtifact(tarball);
  const sourceSha = options['source-sha'] ?? receipt.source.privateRevision.sha;
  assertReceiptArtifact(receipt, artifact, sourceSha);
  const version = process.versions.node;
  receipt.checks.node = receipt.checks.node.filter((check) => check.version !== version);
  receipt.checks.node.push({ status: 'running', version });
  if (options.bun) receipt.checks.bun = { status: 'running' };
  saveReceipt(receiptPath, receipt);
  const root = mkdtempSync(join(tmpdir(), 'sdk-packed-consumer-'));
  try {
    const { bun, ...check } = checkNode(
      root,
      tarball,
      pkg,
      receipt.tooling.typescript,
      options.bun ? receipt.tooling.bun : undefined,
    );
    if (bun) receipt.checks.bun = bun;
    receipt.checks.node[receipt.checks.node.length - 1] = check;
    saveReceipt(receiptPath, receipt);
    if (options.browser) {
      receipt.checks.browser = { status: 'running' };
      saveReceipt(receiptPath, receipt);
      receipt.checks.browser = checkBrowser(root, tarball, pkg, receipt.tooling.browser);
    }
    assertReceiptArtifact(receipt, inspectArtifact(tarball).artifact, sourceSha);
    saveReceipt(receiptPath, receipt);
    console.log(`packed artifact SHA256: ${artifact.sha256}\nSRI: ${artifact.integrity}`);
    console.log(
      `packed consumer: Node ${version}; all JavaScript, class identity and declaration checks passed`,
    );
    console.log(`artifact: ${tarball}\nreceipt: ${receiptPath}`);
  } catch (error) {
    const check = receipt.checks.node.at(-1);
    check.status = 'failed';
    if (options.bun) receipt.checks.bun.status = 'failed';
    if (options.browser) receipt.checks.browser.status = 'failed';
    saveReceipt(receiptPath, receipt);
    throw error;
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

try {
  await main();
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
