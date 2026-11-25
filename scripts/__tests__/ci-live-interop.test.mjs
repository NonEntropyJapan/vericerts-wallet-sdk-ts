import { expect, test } from 'bun:test';
import { copyFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { sha256 } from '../ci/candidate.mjs';
import { finalizeLiveArtifact, materializeLiveContext } from '../ci/interop/live.mjs';
import { fixture as createArtifact } from '../packed-consumer/artifact-fixtures.mjs';
import { saveReceipt } from '../packed-consumer/receipt.mjs';
import { fixture as createWorkspace } from './gates-fixture';

test('live context binds exact committed harness bytes to a runtime-validated artifact', () => {
  const workspace = createWorkspace();
  const artifact = createArtifact();
  try {
    const driver = 'test/interop/driver.mjs';
    workspace.write(driver, 'export const fixture = true;\n');
    workspace.write('bun.lock', 'synthetic lock\n');
    const sdkProjectedSHA = workspace.commit();
    const sdkTree = workspace.git('rev-parse', 'HEAD^{tree}');
    const producer = 'a'.repeat(40);
    const input = path.join(artifact.root, 'runtime-artifact');
    mkdirSync(input);
    copyFileSync(artifact.tarball, path.join(input, artifact.receipt.artifact.filename));
    Object.assign(artifact.receipt.source.privateRevision, {
      sha: sdkProjectedSHA,
      tree: sdkTree,
      lockSha256: sha256(workspace.read('bun.lock')),
    });
    saveReceipt(path.join(input, 'receipt.json'), artifact.receipt);
    const projection = path.join(artifact.root, 'projection.qa.json');
    saveReceipt(projection, {
      context: 'private-validation',
      producerRevision: producer,
      sdkProjectedSHA,
      sdkTree,
    });
    const env = {
      GITHUB_SHA: producer,
      SDK_CI_WORKSPACE: workspace.root,
      SDK_CI_REVISION: sdkProjectedSHA,
      SDK_CI_PROJECTION: projection,
      SDK_CI_ARTIFACT_DIR: input,
    };
    const bundle = path.join(artifact.root, 'bundle');
    const context = path.join(artifact.root, 'context');
    finalizeLiveArtifact(bundle, env);
    const binding = JSON.parse(readFileSync(path.join(bundle, 'live-binding.json'), 'utf8'));
    expect(binding.harnessManifestSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(binding.integrity).toBe(artifact.receipt.artifact.integrity);
    materializeLiveContext(bundle, context, env);
    expect(readFileSync(path.join(context, driver), 'utf8')).toBe(workspace.read(driver));
    workspace.write(driver, 'export const fixture = false;\n');
    expect(() => materializeLiveContext(bundle, path.join(artifact.root, 'dirty'), env)).toThrow(
      'not clean',
    );
  } finally {
    workspace.close();
    rmSync(artifact.root, { recursive: true, force: true });
  }
});
