import { copyFile, mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pkg from '../../package.json' with { type: 'json' };
import { sha256, verifyMaterials } from '../../test/test-support/verify.mjs';
import { credentialVectors, didVectors, statusVectors } from './vectors.js';

const sdkRoot = fileURLToPath(new URL('../../', import.meta.url));
export const MATERIAL_VERSION = '1.0.0';

/** 空の出力先だけに書く。生成時以外はSDK checkoutを要求しない。 */
export async function exportMaterials(output: string) {
  const root = resolve(output);
  await mkdir(root, { recursive: true });
  if ((await readdir(root)).length !== 0) throw new Error('Output directory must be empty');
  await mkdir(join(root, 'vectors'));
  await mkdir(join(root, 'tools'));
  const generatedFrom = `${pkg.name}@${pkg.version}`;
  for (const [name, vector] of Object.entries({
    did: await didVectors(),
    credential: credentialVectors(),
    'status-list': await statusVectors(),
  })) {
    await writeFile(
      join(root, `vectors/${name}.json`),
      `${JSON.stringify({ generatedFrom, ...vector }, null, 2)}\n`,
    );
  }
  const conformance = JSON.parse(
    await readFile(join(sdkRoot, 'schemas/conformance-vectors.json'), 'utf8'),
  );
  if (conformance.generatedFrom !== generatedFrom)
    throw new Error('Regenerate SDK conformance vectors first');
  await writeFile(
    join(root, 'vectors/conformance.json'),
    `${JSON.stringify(conformance, null, 2)}\n`,
  );
  for (const name of ['README.md', 'consumer.mjs', 'tools-consumer.mjs', 'verify.mjs']) {
    await copyFile(join(sdkRoot, 'test/test-support', name), join(root, name));
  }
  await copyFile(join(sdkRoot, 'LICENSE'), join(root, 'LICENSE'));
  let notices = 'Test-only bundles include the following third-party software.\n';
  for (const name of ['@noble/curves', '@noble/hashes', '@scure/base']) {
    const directory = join(sdkRoot, 'node_modules', name);
    const metadata = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'));
    notices += `\n${name}@${metadata.version}\n${await readFile(join(directory, 'LICENSE'), 'utf8')}\n`;
  }
  await writeFile(join(root, 'THIRD_PARTY_NOTICES'), notices);
  for (const [name, entry] of [
    ['did-fixtures', 'scripts/test-support/did-fixtures.ts'],
    ['inherited-reads', 'src/internal/__tests__/inherited-reads/scan.ts'],
  ]) {
    const result = await Bun.build({
      entrypoints: [join(sdkRoot, entry as string)],
      target: 'node',
      format: 'esm',
      external: ['typescript'],
      minify: false,
    });
    if (!result.success || result.outputs.length !== 1) throw new Error(`Failed to bundle ${name}`);
    const artifact = result.outputs[0];
    if (!artifact) throw new Error(`Missing bundle ${name}`);
    await writeFile(join(root, `tools/${name}.mjs`), await artifact.text());
  }
  const files: Record<string, { sha256: string; bytes: number; caseCount: number | null }> = {};
  for (const directory of ['', 'vectors', 'tools']) {
    for (const name of (await readdir(join(root, directory))).sort()) {
      if (directory === '' && ['vectors', 'tools'].includes(name)) continue;
      const relative = directory ? `${directory}/${name}` : name;
      const bytes = await readFile(join(root, relative));
      files[relative] = {
        sha256: sha256(bytes),
        bytes: bytes.length,
        caseCount: directory === 'vectors' ? JSON.parse(bytes.toString()).cases.length : null,
      };
    }
  }
  const manifest = { schemaVersion: 1, materialVersion: MATERIAL_VERSION, generatedFrom, files };
  await writeFile(join(root, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  verifyMaterials(root);
  return manifest;
}
