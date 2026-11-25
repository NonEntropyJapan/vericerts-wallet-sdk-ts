import assert from 'node:assert/strict';
import { isMainModule } from '../lib/is-main-module.mjs';
import { runSdkTests } from './local/test-run.mjs';

if (isMainModule(import.meta.url)) {
  const args = process.argv.slice(2);
  const choice = /^--input=(working-tree|committed)$/.exec(args[0] ?? '');
  assert.ok(
    choice && (args.length === 1 || (args.length === 2 && args[1] === '--coverage')),
    'usage: --input=<working-tree|committed> [--coverage]',
  );
  runSdkTests({ input: choice[1], coverage: args.length === 2 });
}
