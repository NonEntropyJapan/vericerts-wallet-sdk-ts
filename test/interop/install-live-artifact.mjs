import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';

const directory = './artifact';
const receipt = `${directory}/receipt.json`;
assert.ok(lstatSync(receipt).isFile(), 'Expected a regular artifact receipt');
const { artifact } = JSON.parse(readFileSync(receipt, 'utf8'));
assert.match(artifact.filename, /^[a-zA-Z0-9._-]+\.tgz$/);
assert.deepEqual(readdirSync(directory).sort(), [artifact.filename, 'receipt.json'].sort());
const tarball = `${directory}/${artifact.filename}`;
assert.ok(lstatSync(tarball).isFile(), 'Expected a regular SDK tarball');
const bytes = readFileSync(tarball);
assert.equal(createHash('sha256').update(bytes).digest('hex'), artifact.sha256);
assert.equal(`sha512-${createHash('sha512').update(bytes).digest('base64')}`, artifact.integrity);

// The image build passes this verified local filename to npm.
process.stdout.write(tarball);
