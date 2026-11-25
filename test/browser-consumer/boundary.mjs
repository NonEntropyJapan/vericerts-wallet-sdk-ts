import assert from 'node:assert/strict';
import { realpathSync } from 'node:fs';
import { isAbsolute, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const clean = (id) => id.replace(/[?#].*$/, '');
const virtual = (id) =>
  id.startsWith('\0') ||
  id === '__vite-browser-external' ||
  id.startsWith('__vite-browser-external:');

export function browserFileBoundary(consumer) {
  const root = realpathSync(consumer);
  return (id) => {
    if (virtual(id)) return;
    const file = id.startsWith('file:') ? fileURLToPath(id) : clean(id);
    assert.ok(isAbsolute(file), 'Unresolved browser module');
    const rel = relative(root, realpathSync(file));
    assert.ok(
      !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`),
      'Browser module escapes isolated consumer',
    );
  };
}

function literal(node) {
  if (node?.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node?.type === 'TemplateLiteral' && node.expressions.length === 0)
    return node.quasis[0].value.cooked;
}
const importMetaUrl = (node) =>
  node?.type === 'MemberExpression' &&
  !node.computed &&
  node.property.name === 'url' &&
  node.object.type === 'MetaProperty' &&
  node.object.meta.name === 'import' &&
  node.object.property.name === 'meta';

async function checkExpressions(ast, resolveAsset) {
  async function visit(node) {
    if (node.type === 'ImportExpression') {
      assert.equal(typeof literal(node.source), 'string', 'Non-literal browser module binding');
    }
    if (
      node.type === 'NewExpression' &&
      node.callee.type === 'Identifier' &&
      node.callee.name === 'URL' &&
      importMetaUrl(node.arguments[1])
    ) {
      const source = literal(node.arguments[0]);
      assert.equal(typeof source, 'string', 'Non-literal browser asset URL');
      await resolveAsset(source);
    }
    for (const value of Object.values(node)) {
      for (const child of Array.isArray(value) ? value : [value]) {
        if (child && typeof child.type === 'string') await visit(child);
      }
    }
  }
  await visit(ast);
}

export function browserBoundary(consumer = process.cwd()) {
  const check = browserFileBoundary(consumer);
  const plugin = () => ({
    name: 'isolated-browser-module-boundary',
    enforce: 'pre',
    load(id) {
      check(id);
      return null;
    },
    async transform(code, id) {
      if (!virtual(id) && /\.[cm]?[jt]sx?$/.test(clean(id))) {
        // Vite's own parser sees imports and asset URLs before core transforms.
        // Asset URL transforms can read directly without calling resolveId/load.
        const extension = clean(id).match(/\.([cm]?[jt]sx?)$/)[1];
        const lang = extension.endsWith('x') ? extension : extension.endsWith('ts') ? 'ts' : 'js';
        await checkExpressions(this.parse(code, { lang }), async (source) => {
          const result = await this.resolve(source, id, { skipSelf: true });
          assert.ok(result && !result.external, 'External or unresolved browser asset');
          check(result.id);
        });
      }
      return null;
    },
  });
  return {
    resolve: {
      alias: [
        {
          find: /^(?!\0)/,
          replacement: '',
          async customResolver(id, importer, options) {
            // CSS @import/url use Vite's separate resolver container. Its alias
            // hook lets us check that native result without replacing resolution.
            const result = await this.resolve(id, importer, { ...options, skipSelf: true });
            assert.ok(result && !result.external, 'External or unresolved browser module');
            check(result.id);
            return result;
          },
        },
      ],
    },
    plugins: [plugin()],
    worker: { plugins: () => [plugin()] },
  };
}
