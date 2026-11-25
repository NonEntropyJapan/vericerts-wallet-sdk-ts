import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';

const manifest = 'test/interop/adapters/sphereon/package.json';
const lock = 'test/interop/adapters/sphereon/package-lock.json';
const dependency = '@veramo-community/lds-ecdsa-secp256k1-recovery2020';
const replacement =
  'git+https://github.com/uport-project/EcdsaSecp256k1RecoverySignature2020.git#ab0db52de6f4e6663ef271a48009ba26e688ef9b';
const expectedLock = '54b8dba72ed99d641bb39fb3750e3849aa029fa0011148c6b6adde78e370f944';

// Sphereon's existing public peer uses this immutable override. Other dependencies
// in the same fixture still go through the registry policy.
export function peerFixtureContext(root, file) {
  if (file !== manifest) return undefined;
  const expectedPath = path.join(realpathSync(root), lock);
  try {
    if (!lstatSync(expectedPath).isFile() || realpathSync(expectedPath) !== expectedPath)
      return { file };
    return {
      file,
      lockSha256: createHash('sha256').update(readFileSync(expectedPath)).digest('hex'),
    };
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return { file };
  }
}

export function peerFixtureOverride(pkg, context) {
  if (context?.file !== manifest) return undefined;
  if (
    pkg.name !== 'interop-sphereon-adapter' ||
    pkg.private !== true ||
    context.lockSha256 !== expectedLock ||
    pkg.overrides?.[dependency] !== replacement
  )
    return null;
  return { at: `overrides.${dependency}`, value: replacement };
}
