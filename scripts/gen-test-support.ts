import { exportMaterials } from './test-support/export.js';

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--out' || !args[1]) {
  throw new Error('Usage: bun run export:test-support --out <empty-or-new-directory>');
}
const manifest = await exportMaterials(args[1]);
console.log(
  `test-support: exported ${manifest.generatedFrom} material ${manifest.materialVersion}`,
);
