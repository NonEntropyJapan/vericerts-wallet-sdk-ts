import assert from 'node:assert/strict';
import { isMainModule } from '../lib/is-main-module.mjs';
import { runPackageInterop } from './interop/runner.mjs';

if (isMainModule(import.meta.url)) {
  const options = {};
  for (const argument of process.argv.slice(2)) {
    const match = /^--(workspace|artifact-dir|source-sha|manifest|result|validation)=(.+)$/.exec(
      argument,
    );
    assert.ok(match && !Object.hasOwn(options, match[1]), 'Invalid package Interop argument');
    options[match[1]] = match[2];
  }
  assert.equal(Object.keys(options).length, 6, 'Package Interop requires all six arguments');
  runPackageInterop({
    workspace: options.workspace,
    artifactDir: options['artifact-dir'],
    sourceSha: options['source-sha'],
    manifestFile: options.manifest,
    result: options.result,
    validation: options.validation,
  });
}
