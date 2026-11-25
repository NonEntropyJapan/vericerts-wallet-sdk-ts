import { execute } from './environment.mjs';
import { currentSuiteManifest } from './suite-manifest.mjs';

const cwd = process.cwd();
const { suites } = currentSuiteManifest(cwd);
console.log('SDK watch runs source tests only. Restart watch after adding or removing test files.');
execute('bun', ['test', '--watch', ...suites.source.map((file) => `./${file}`)], cwd, {
  stdio: 'inherit',
});
