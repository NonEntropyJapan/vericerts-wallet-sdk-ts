import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REQUIRED_FILES = [
  'README.md',
  'LICENSE',
  'THIRD_PARTY_NOTICES',
  'consumer.mjs',
  'tools-consumer.mjs',
  'verify.mjs',
  'vectors/did.json',
  'vectors/credential.json',
  'vectors/status-list.json',
  'vectors/conformance.json',
  'tools/did-fixtures.mjs',
  'tools/inherited-reads.mjs',
];

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** 配布物を自己検査する。信頼するmanifest自体のhashは受渡し側で別途固定する。 */
export function verifyMaterials(root = dirname(fileURLToPath(import.meta.url))) {
  const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
  if (
    manifest.schemaVersion !== 1 ||
    manifest.materialVersion !== '1.0.0' ||
    !/^@vericerts\/vericerts-wallet-sdk@\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(manifest.generatedFrom)
  ) {
    throw new Error('Invalid material manifest version');
  }
  const names = Object.keys(manifest.files).sort();
  if (JSON.stringify(names) !== JSON.stringify([...REQUIRED_FILES].sort())) {
    throw new Error('Unexpected or missing manifest file');
  }
  const actualFiles = [];
  const visit = (directory, prefix = '') => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const name = `${prefix}${entry.name}`;
      if (entry.isDirectory()) visit(join(directory, entry.name), `${name}/`);
      else {
        if (!entry.isFile()) throw new Error('Material contains a non-regular file');
        actualFiles.push(name);
      }
    }
  };
  visit(root);
  if (JSON.stringify(actualFiles.sort()) !== JSON.stringify([...names, 'manifest.json'].sort())) {
    throw new Error('Unexpected or missing material file');
  }
  for (const name of names) {
    const path = join(root, name);
    if (!lstatSync(path).isFile()) throw new Error(`Not a regular material: ${name}`);
    const bytes = readFileSync(path);
    const record = manifest.files[name];
    if (record.bytes !== bytes.length || record.sha256 !== sha256(bytes)) {
      throw new Error(`Material integrity mismatch: ${name}`);
    }
    if (name.startsWith('vectors/')) {
      const vector = JSON.parse(bytes.toString('utf8'));
      if (
        !Array.isArray(vector.cases) ||
        vector.cases.length !== record.caseCount ||
        new Set(vector.cases.map((item) => item.id)).size !== vector.cases.length ||
        vector.generatedFrom !== manifest.generatedFrom
      ) {
        throw new Error(`Material case count or provenance mismatch: ${name}`);
      }
    } else if (record.caseCount !== null) throw new Error(`Invalid non-vector case count: ${name}`);
  }
  return manifest;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const manifest = verifyMaterials(process.argv[2]);
  console.log(
    `test-support: verified ${manifest.generatedFrom} material ${manifest.materialVersion}`,
  );
}
