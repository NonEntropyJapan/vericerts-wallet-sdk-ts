import assert from 'node:assert/strict';
import { resolve } from 'node:path';

export function parseArgs(args, release = false) {
  const options = {};
  for (const arg of args) {
    if (['--browser', '--bun', '--development-snapshot'].includes(arg) && !release) {
      const key = arg.slice(2);
      assert.equal(options[key], undefined, `Duplicate ${arg}`);
      options[key] = true;
      continue;
    }
    const match = /^--(tarball|receipt|source-sha|artifact-dir)=(.+)$/.exec(arg);
    assert.ok(match, `Unknown/empty argument: ${arg}`);
    const [, key, value] = match;
    assert.equal(options[key], undefined, `Duplicate --${key}`);
    assert.ok(!release || key !== 'artifact-dir', 'Release dry-run cannot produce an artifact');
    options[key] = key === 'source-sha' ? value : resolve(value);
  }
  if (options['source-sha']) assert.match(options['source-sha'], /^[a-f0-9]{40}$/);
  if (options.tarball || release) {
    for (const key of ['tarball', 'receipt', 'source-sha']) {
      assert.ok(options[key], `--${key}= is required for an existing artifact`);
    }
    assert.equal(options['artifact-dir'], undefined, 'Existing-artifact mode cannot repack');
    assert.equal(
      options['development-snapshot'],
      undefined,
      'Existing artifact retains its origin',
    );
  }
  return options;
}
