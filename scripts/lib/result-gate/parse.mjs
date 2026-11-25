import { readFileSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const modules = path.join(root, 'node_modules');
const own = path.join(modules, 'fast-xml-parser');
const relative = path.relative(realpathSync(modules), realpathSync(own));
if (
  relative.startsWith('..') ||
  path.isAbsolute(relative) ||
  realpathSync(modules) !== path.resolve(modules)
) {
  throw new Error('XML tooling must be installed inside this SDK node_modules');
}
const declared = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).devDependencies[
  'fast-xml-parser'
];
const installed = JSON.parse(readFileSync(path.join(own, 'package.json'), 'utf8')).version;
if (declared !== installed) throw new Error('SDK XML tooling must match its exact devDependency');
const { XMLParser, XMLValidator } = createRequire(path.join(root, 'package.json'))(
  './node_modules/fast-xml-parser',
);
const namedRefs = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
const invalidXmlChar = /[^\t\n\r\u0020-\uD7FF\uE000-\uFFFD\u{10000}-\u{10FFFF}]/u;

function decodeAttribute(value) {
  if (value.includes('<') || invalidXmlChar.test(value)) fail('invalid XML attribute character');
  // Normalize literal whitespace and decode references in one pass. An escaped
  // ampersand in an identity must not make the following text a new reference.
  return value.replace(
    /\r\n?|[\t\n]|&(amp|lt|gt|quot|apos);|&#(x[0-9a-fA-F]+|[0-9]+);|&/g,
    (match, name, numeric) => {
      if (name !== undefined) return namedRefs[name];
      if (numeric !== undefined) {
        const point = numeric.startsWith('x')
          ? Number.parseInt(numeric.slice(1), 16)
          : Number(numeric);
        if (point > 0x10ffff) fail('XML attribute character reference is out of range');
        const character = String.fromCodePoint(point);
        if (invalidXmlChar.test(character)) fail('invalid XML attribute character reference');
        return character;
      }
      if (match === '&') fail('malformed or unknown XML attribute reference');
      return ' ';
    },
  );
}

const parser = new XMLParser({
  preserveOrder: true,
  ignoreAttributes: false,
  ignoreDeclaration: true,
  parseTagValue: false,
  parseAttributeValue: false,
  trimValues: false,
  commentPropName: '#comment',
  cdataPropName: '#cdata',
  processEntities: false,
  attributeValueProcessor: (_name, value) => decodeAttribute(value),
});
const attributes = (node) => node[':@'] ?? {};
const tagName = (node) => Object.keys(node).find((name) => name !== ':@');
const elements = (nodes) =>
  nodes.filter((node) => !['#text', '#comment', '#cdata'].includes(tagName(node)));
const count = (text) =>
  typeof text === 'string' && /^(?:0|[1-9]\d*)$/.test(text) && Number.isSafeInteger(Number(text))
    ? Number(text)
    : null;
const fail = (message) => {
  throw new Error(`Invalid Bun JUnit: ${message}`);
};

// This is the Bun JUnit protocol, not a general XML reader. DTDs and entities
// declared by a document are unnecessary; comments/CDATA remain inert content.
export function parseBunJunit(xml, cwd) {
  const relative = (file) =>
    !cwd || !file ? file : path.relative(cwd, path.resolve(cwd, file)).split(path.sep).join('/');
  const markup = xml.replace(/<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>/g, '');
  if (/<!DOCTYPE\b/i.test(markup) || /<!ENTITY\b/i.test(markup))
    fail('DTD/entity declarations are forbidden');
  if (XMLValidator.validate(xml) !== true) fail('incomplete or malformed XML document');
  const roots = elements(parser.parse(xml));
  if (roots.length !== 1 || tagName(roots[0]) !== 'testsuites')
    fail('expected exactly one testsuites root');
  const declaredTests = count(attributes(roots[0])['@_tests']);
  if (declaredTests === null) fail('testsuites tests count is required');
  const cases = [];
  const files = new Set();
  function visitSuite(node, inheritedFile = '') {
    const tag = tagName(node);
    const attrs = attributes(node);
    const file = relative(attrs['@_file'] ?? inheritedFile);
    if (file) files.add(file);
    const before = cases.length;
    for (const child of elements(node[tag])) {
      const name = tagName(child);
      if (name === 'testsuite') visitSuite(child, file);
      else if (tag === 'testsuite' && name === 'testcase') {
        const values = attributes(child);
        const testFile = relative(values['@_file'] ?? file);
        if (!testFile || typeof values['@_name'] !== 'string')
          fail('testcase file/name is required');
        const statuses = elements(child.testcase);
        if (
          statuses.some(
            (item) =>
              !['skipped', 'failure', 'error', 'system-out', 'system-err'].includes(tagName(item)),
          )
        )
          fail('unexpected testcase content');
        if (statuses.some((item) => elements(item[tagName(item)]).length))
          fail('nested testcase status content');
        const skipped = statuses.find((item) => tagName(item) === 'skipped');
        const failed = statuses.some((item) => ['failure', 'error'].includes(tagName(item)));
        cases.push({
          file: testFile,
          name: values['@_name'],
          ...(typeof values['@_classname'] === 'string'
            ? { classname: values['@_classname'] }
            : {}),
          status: failed
            ? 'failed'
            : skipped
              ? attributes(skipped)['@_message'] === 'TODO'
                ? 'todo'
                : 'skipped'
              : 'passed',
        });
        files.add(testFile);
      } else if (!['system-out', 'system-err', 'properties'].includes(name))
        fail(`unexpected ${tag} child ${name}`);
    }
    const declared = attrs['@_tests'] === undefined ? null : count(attrs['@_tests']);
    if (attrs['@_tests'] !== undefined && (declared === null || declared !== cases.length - before))
      fail(`${tag} tests count differs from cases`);
  }
  visitSuite(roots[0]);
  return { cases, files, declaredTests };
}
