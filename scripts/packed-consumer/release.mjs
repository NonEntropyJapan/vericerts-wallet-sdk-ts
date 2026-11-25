import assert from 'node:assert/strict';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest, inspectArtifact } from './archive.mjs';
import { parseArgs } from './cli.mjs';
import { run } from './process.mjs';
import { checkPublishResult } from './publish-result.mjs';
import { assertReceiptArtifact, readReceipt, requireReleaseChecks } from './receipt.mjs';

export function plannedReleaseTag(version) {
  // This gate also runs from a copied verifier directory without installed dependencies.
  assert.ok(typeof version === 'string' && version.length <= 256, 'Invalid SDK release version');
  const match =
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(
      version,
    );
  assert.ok(
    match?.slice(1, 4).every((part) => Number.isSafeInteger(Number(part))),
    'Invalid SDK release version',
  );
  assert.ok(
    !match[4]?.split('.').some((part) => /^0\d+$/.test(part)),
    'Invalid SDK prerelease version',
  );
  return `v${version}`;
}

export function plannedReleaseCandidate(artifact, repository, targetSha) {
  assert.match(repository, /^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/);
  assert.match(targetSha, /^[a-f0-9]{40}$/);
  assert.match(artifact.sha256, /^[a-f0-9]{64}$/);
  return {
    packageName: artifact.name,
    version: artifact.version,
    plannedTag: plannedReleaseTag(artifact.version),
    repository,
    targetSha,
    tarballSha256: artifact.sha256,
  };
}

function verifyRelease(options, execute) {
  const receipt = readReceipt(options.receipt);
  assert.equal(
    digest(readFileSync(options.tarball)),
    receipt.artifact.sha256,
    'Receipt artifact identity/digest mismatch',
  );
  const { artifact } = inspectArtifact(options.tarball);
  assertReceiptArtifact(receipt, artifact, options['source-sha']);
  requireReleaseChecks(receipt);
  const plannedTag = plannedReleaseTag(artifact.version);
  const output = execute(
    'npm',
    ['publish', options.tarball, '--dry-run', '--ignore-scripts', '--json'],
    resolve(options.tarball, '..'),
  );
  checkPublishResult(output, artifact);
  // The bytes tested by consumers must be the bytes that npm was given.
  assertReceiptArtifact(receipt, inspectArtifact(options.tarball).artifact, options['source-sha']);
  return { output, plannedTag, artifact };
}

export function dryRunRelease(options, execute = run) {
  return verifyRelease(options, execute).output;
}

if (
  process.argv[1] &&
  existsSync(process.argv[1]) &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
) {
  try {
    const { plannedTag, artifact } = verifyRelease(parseArgs(process.argv.slice(2), true), run);
    console.log(
      `SDK release dry-run passed for ${artifact.name}@${artifact.version} (private validation only). Planned Git tag ${plannedTag}, tarball SHA-256 ${artifact.sha256}. Verified tarball unchanged, nothing published.`,
    );
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
