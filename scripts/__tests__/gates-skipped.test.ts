import { afterAll, describe, expect, test } from 'bun:test';
import { rmSync } from 'node:fs';
import path from 'node:path';
import { fixture } from './gates-fixture';

const f = fixture();
afterAll(() => f.close());
describe('SDK disabled-test AST gate', () => {
  const forms = [
    "test.skip('x', () => {})",
    "test.only('x', () => {})",
    "test.todo('x')",
    "test.skipIf(true)('x', () => {})",
    "test.runIf(false)('x', () => {})",
    "test.each([])('x', () => {})",
    "const t=test; t.skip('x', () => {})",
    "const {skip}=test; skip('x', () => {})",
    "test('x', {skip:true}, () => {})",
    "test('x', (t) => t.skip())",
    "test('x', (t) => {const carrier={t}; carrier.t.skip()})",
    "test('x', ({skip}) => skip())",
    "test['skip']('x', () => {})",
    "test('x', (t) => {const carrier=[t]; carrier[0].todo()})",
  ];
  for (const [index, form] of forms.entries())
    test(`rejects disabled form ${index + 1}`, () => {
      f.write('src/sample.test.ts', `import {test} from 'bun:test';\n${form};\n`);
      expect(f.cli('skipped-tests').status).toBe(1);
    });
  test('scans imported carriers and tracked directories named coverage', () => {
    f.write('helper.ts', "import {test} from 'bun:test'; export const walletTest = test;\n");
    f.write(
      'src/sample.test.ts',
      "import {walletTest} from '../helper'; walletTest.only('x',()=>{});\n",
    );
    expect(f.cli('skipped-tests').status).toBe(1);
    rmSync(path.join(f.root, 'src/sample.test.ts'));
    f.write('coverage/hidden.test.ts', "import {test} from 'bun:test';test.skip('x',()=>{});\n");
    f.git('add', '-f', 'coverage/hidden.test.ts');
    expect(f.cli('skipped-tests').status).toBe(1);
    rmSync(path.join(f.root, 'coverage/hidden.test.ts'));
  });
  test('accepts regular context and nonempty table', () => {
    f.write(
      'src/sample.test.ts',
      "import {test} from 'bun:test'; test.each([1])('x',()=>{}); test('ok',()=>{}); const data={skip(){}};data.skip();\n",
    );
    expect(f.cli('skipped-tests').status).toBe(0);
  });
});
