// Generate the npm NOTICE from the packages that actually contributed bytes to the bundles.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve, sep } from 'node:path';
import { noticeInput } from './lib/notice-boundary.mjs';

function packageRoot(input) {
  const parts = noticeInput(input).split('/');
  const start = parts.lastIndexOf('node_modules') + 1;
  if (!start) return undefined;
  const end = start + (parts[start].startsWith('@') ? 2 : 1);
  return noticeInput(resolve(parts.slice(0, end).join('/')), { modulesOnly: true });
}

const roots = new Set();
const inputs = new Set();
for (const build of ['esm', 'cjs', 'otel']) {
  const { outputs } = JSON.parse(readFileSync(noticeInput(`.build-meta-${build}.json`), 'utf8'));
  for (const output of Object.values(outputs)) {
    for (const [file, { bytesInOutput }] of Object.entries(output.inputs)) {
      if (bytesInOutput > 0 && packageRoot(file)) inputs.add(file);
    }
  }
}

const copyrights = new Map();
for (const file of inputs) {
  const root = packageRoot(file);
  roots.add(root);
  // Some bundled files (e.g. detect-libc) put the author's notice in source only.
  if (!/\.[cm]?js$/.test(file)) continue;
  for (const match of readFileSync(noticeInput(file), 'utf8').matchAll(
    /^\/\/ (Copyright [^\r\n]+)/gim,
  )) {
    if (!copyrights.has(root)) copyrights.set(root, new Set());
    copyrights.get(root).add(match[1]);
  }
}

if (!roots.size) throw new Error('Build metadata contains no bundled npm dependencies');

const sections = [];
for (const root of roots) {
  const manifest = noticeInput(join(root, 'package.json'), { modulesOnly: true });
  const pkg = JSON.parse(readFileSync(manifest, 'utf8'));
  const id = `${pkg.name}@${pkg.version}`;
  const files = readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter((name) =>
      /^(licen[cs]es?|copying|copyright|notice|third[-_ ]party[-_ ](?:licenses?|notices?))(?:$|[.-])/i.test(
        name,
      ),
    )
    .sort();
  const docs = files.map(
    (name) =>
      `${name}\n${readFileSync(noticeInput(join(root, name), { modulesOnly: true }), 'utf8')}`,
  );
  if (!files.some((name) => /^(licen[cs]e|copying)/i.test(name))) {
    if (id !== 'permissionless@0.2.57') throw new Error(`Missing license text for ${id}`);
    // This npm release omits LICENSE. Its npm gitHead identifies the upstream copy:
    // https://github.com/pimlicolabs/permissionless.js/blob/b7f301c8412c4052a967d3bf91a408da52383c54/LICENSE
    docs.push(
      readFileSync(
        noticeInput(new URL('./licenses/permissionless-0.2.57.LICENSE', import.meta.url)),
        'utf8',
      ),
    );
  }

  if (pkg.name === 'jsonpath-plus') {
    // jsonpath-plus ships its runtime dependencies already inlined into index-{browser,node}-esm.js.
    const fromPackage = createRequire(noticeInput(resolve(manifest), { modulesOnly: true }));
    for (const dependency of Object.keys(pkg.dependencies)) {
      roots.add(packageRoot(fromPackage.resolve(dependency).split(sep).join('/')));
    }
  }
  sections.push([id, ...(copyrights.get(root) ?? []), ...docs].join('\n\n'));
}

writeFileSync(
  noticeInput('NOTICE', { allowMissing: true }),
  [
    'VeriCerts Wallet SDK',
    'Copyright (c) 2026 VeriCerts Wallet contributors',
    'Third-party notices',
    ...sections.sort(),
    '',
  ].join('\n\n'),
);
