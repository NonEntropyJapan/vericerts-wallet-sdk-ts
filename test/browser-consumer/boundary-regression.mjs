import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'vite';
import { browserBoundary } from './boundary.mjs';

// Runs after the isolated fixture's npm ci, with its own pinned Vite. These
// tiny graphs exercise the real resolver/loader without another install/pack.
export async function checkBrowserBoundary() {
  const fixture = fs.realpathSync(fs.mkdtempSync(join(process.cwd(), '.browser-boundary-')));
  const outside = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'sdk-browser-outside-')));
  const write = (file, contents) => {
    fs.mkdirSync(dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
  };
  const dep = join(fixture, 'node_modules/boundary-dep');
  const foreign = join(outside, 'private.js');
  const secret = 'foreign_browser_fixture_4244';
  const original = { readFile: fs.promises.readFile, readFileSync: fs.readFileSync };
  let foreignReads = 0;
  const observe = (path) => {
    if (typeof path !== 'string') return;
    const rel = relative(outside, path);
    if (rel === '' || (!rel.startsWith('..') && !rel.startsWith('/'))) foreignReads++;
  };
  const virtual = {
    name: 'boundary-regression-virtual',
    resolveId: (id) => (id === 'virtual:boundary-probe' ? '\0boundary-probe' : null),
    load: (id) => (id === '\0boundary-probe' ? 'export default "own-virtual";' : null),
  };
  const bundle = async (guarded = true) => {
    const options = guarded ? browserBoundary(fixture) : {};
    const output = await build({
      ...options,
      root: fixture,
      configFile: false,
      logLevel: 'silent',
      plugins: [...(options.plugins ?? []), virtual],
      build: { write: false, minify: false, rolldownOptions: { input: ['index.html'] } },
    });
    return output.output
      .map((item) => (item.type === 'chunk' ? item.code : item.source))
      .join('\n');
  };
  try {
    write(join(fixture, 'package.json'), '{"private":true,"type":"module"}');
    write(join(fixture, 'index.html'), '<script type="module" src="/probe.mjs"></script>');
    write(
      join(dep, 'package.json'),
      JSON.stringify({
        name: 'boundary-dep',
        type: 'module',
        exports: { browser: './browser.js', default: './index.js' },
      }),
    );
    write(join(dep, 'index.js'), 'export const value=1;');
    write(join(dep, 'browser.js'), 'export const value=1;');
    write(
      join(fixture, 'node_modules/boundary-cjs/package.json'),
      '{"name":"boundary-cjs","main":"index.cjs"}',
    );
    write(
      join(fixture, 'node_modules/boundary-cjs/index.cjs'),
      'module.exports={value:"own-cjs"};',
    );
    write(join(fixture, 'local.svg'), '<svg>own-asset</svg>');
    write(join(fixture, 'local.txt'), 'own-raw');
    write(join(fixture, 'local-dynamic.js'), 'console.log("own-dynamic");');
    write(join(fixture, 'local.css'), 'body{background:url(./local.svg)}');
    write(join(fixture, 'worker.js'), 'postMessage("own-worker");');
    write(foreign, `console.log(${JSON.stringify(secret)}); export const value=1;`);
    write(join(outside, 'private.css'), 'body{color:red}');
    write(join(outside, 'private.svg'), `<svg>${secret}</svg>`);
    const probe = (source) => write(join(fixture, 'probe.mjs'), source);
    const positive = `import {value}from'boundary-dep';import cjs from'boundary-cjs';import virtual from'virtual:boundary-probe';import './local.css';import raw from'./local.txt?raw';import Worker from'./worker.js?worker';import(\`./local-dynamic.js\`);const img=new URL(\`./local.svg?x#icon\`,import.meta.url);const rootImg=new URL('/local.svg',import.meta.url);console.log(value,cjs,virtual,raw,img,rootImg,new Worker());`;
    probe(positive);
    const ownOutput = await bundle();
    for (const marker of ['own-cjs', 'own-virtual', 'own-raw', 'own-worker', 'own-dynamic'])
      assert.ok(ownOutput.includes(marker), 'Normal browser loader changed');
    assert.equal(ownOutput.includes(secret), false);

    const conditional = `export {value} from ${JSON.stringify(foreign)};`;
    write(join(dep, 'browser.js'), conditional);
    probe('import {value}from"boundary-dep";console.log(value);');
    assert.equal(
      createRequire(join(fixture, 'package.json')).resolve('boundary-dep'),
      fs.realpathSync(join(dep, 'index.js')),
    );
    assert.ok(
      (await bundle(false)).includes(secret),
      'Negative control did not reproduce outside browser condition',
    );

    fs.promises.readFile = function read(...args) {
      observe(args[0]);
      return original.readFile.apply(this, args);
    };
    fs.readFileSync = function readSync(...args) {
      observe(args[0]);
      return original.readFileSync.apply(this, args);
    };
    syncBuiltinESMExports();
    const cases = [
      ['browser condition', 'import {value}from"boundary-dep";console.log(value);'],
      ['absolute', `import ${JSON.stringify(foreign)};`],
      ['ancestor', `import ${JSON.stringify(relative(fixture, foreign))};`],
      ['file URL', `import ${JSON.stringify(pathToFileURL(foreign).href)};`],
      ['bare dependency', 'import "boundary-escaped";'],
      ['literal dynamic import', `import(${JSON.stringify(pathToFileURL(foreign).href)});`],
      ['symlink', 'import "./linked.js";'],
      ['CSS import', 'import "./bad.css";'],
      ['CSS asset', 'import "./bad-url.css";'],
      [
        'asset URL',
        `console.log(new URL(${JSON.stringify(relative(fixture, join(outside, 'private.svg')))},import.meta.url));`,
      ],
      [
        'worker entry',
        `new Worker(new URL(${JSON.stringify(relative(fixture, foreign))},import.meta.url),{type:'module'});`,
      ],
      ['worker dependency', 'import Worker from "./bad-worker.js?worker";new Worker();'],
      ['nonliteral import', 'const target="./worker.js";import(target);'],
      [
        'nonliteral asset URL',
        'const target="./local.svg";console.log(new URL(target,import.meta.url));',
      ],
      ['external module', 'import "https://example.invalid/private.js";'],
    ];
    fs.symlinkSync(foreign, join(fixture, 'linked.js'));
    write(
      join(outside, 'package.json'),
      '{"name":"boundary-escaped","type":"module","exports":"./private.js"}',
    );
    fs.symlinkSync(outside, join(fixture, 'node_modules/boundary-escaped'));
    write(
      join(fixture, 'bad.css'),
      `@import ${JSON.stringify(relative(fixture, join(outside, 'private.css')))};`,
    );
    write(
      join(fixture, 'bad-url.css'),
      `body{background:url(${JSON.stringify(relative(fixture, join(outside, 'private.svg')))})}`,
    );
    write(join(fixture, 'bad-worker.js'), `import ${JSON.stringify(foreign)};postMessage(1);`);
    for (const [name, source] of cases) {
      probe(source);
      foreignReads = 0;
      await assert.rejects(
        bundle(),
        /Browser module escapes|Non-literal browser|External or unresolved browser/,
        name,
      );
      assert.equal(foreignReads, 0, `Foreign content was read before rejecting ${name}`);
    }
    console.log(
      `browser boundary: normal modules/assets/worker/virtual passed; ${cases.length} escapes rejected before foreign content reads`,
    );
    return { passed: cases.length + 2, failed: 0 };
  } finally {
    fs.promises.readFile = original.readFile;
    fs.readFileSync = original.readFileSync;
    syncBuiltinESMExports();
    fs.rmSync(fixture, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
}
