/**
 * Trust Chain の constraints / crit 強制（OpenID Federation 1.0 §3.1・§6.2）。
 *
 * Leaf → Intermediate → Anchor の 3 段チェーンで、Subordinate Statement / Entity Configuration に
 * 任意クレームを足して署名し直し、`buildTrustChain` の結果を見る。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { buildTrustChain } from '../../trust-chain.js';
import {
  ANCHOR_KEY,
  INTERMEDIATE_KEY,
  LEAF_KEY,
  makeFetchMock,
  nowFn,
  signStatement,
  toJwk,
  validPeriod,
} from '../federation-fixtures.js';

type Claims = Record<string, unknown>;

interface Extras {
  /** Anchor が Intermediate について発行する Subordinate Statement への追加クレーム。 */
  readonly anchorAboutInt?: Claims;
  /** Intermediate が Leaf について発行する Subordinate Statement への追加クレーム。 */
  readonly intAboutLeaf?: Claims;
  /** Leaf の Entity Configuration への追加クレーム。 */
  readonly leafEc?: Claims;
  /** Anchor の Entity Configuration への追加クレーム。 */
  readonly anchorEc?: Claims;
}

const LEAF = 'https://leaf.example.eu';
const INT = 'https://intermediate.example.eu';
const ANCHOR = 'https://anchor.example.eu';

/** 追加クレームを載せた 3 段チェーンを組み、`buildTrustChain` を呼ぶ。 */
async function build(extras: Extras) {
  const leafJwks = { keys: [toJwk(LEAF_KEY, 'leaf-1')] };
  const intJwks = { keys: [toJwk(INTERMEDIATE_KEY, 'int-1')] };
  const anchorJwks = { keys: [toJwk(ANCHOR_KEY, 'anchor-1')] };
  const endpoint = (id: string) => ({
    metadata: { federation_entity: { federation_fetch_endpoint: `${id}/fetch` } },
  });
  const ec = (key: Uint8Array, id: string, jwks: unknown, rest: Claims, extra?: Claims) =>
    signStatement(key, { iss: id, sub: id, ...validPeriod(), jwks, ...rest, ...extra });
  const responses = new Map<string, string>([
    [
      `${LEAF}/.well-known/openid-federation`,
      ec(LEAF_KEY, LEAF, leafJwks, { authority_hints: [INT] }, extras.leafEc),
    ],
    [
      `${INT}/.well-known/openid-federation`,
      ec(INTERMEDIATE_KEY, INT, intJwks, { authority_hints: [ANCHOR], ...endpoint(INT) }),
    ],
    [
      `${ANCHOR}/.well-known/openid-federation`,
      ec(ANCHOR_KEY, ANCHOR, anchorJwks, endpoint(ANCHOR), extras.anchorEc),
    ],
    [
      `${INT}/fetch?sub=${encodeURIComponent(LEAF)}`,
      signStatement(INTERMEDIATE_KEY, {
        iss: INT,
        sub: LEAF,
        ...validPeriod(),
        jwks: leafJwks,
        ...extras.intAboutLeaf,
      }),
    ],
    [
      `${ANCHOR}/fetch?sub=${encodeURIComponent(INT)}`,
      signStatement(ANCHOR_KEY, {
        iss: ANCHOR,
        sub: INT,
        ...validPeriod(),
        jwks: intJwks,
        ...extras.anchorAboutInt,
      }),
    ],
  ]);
  return buildTrustChain(LEAF, ANCHOR, { fetchFn: makeFetchMock(responses), now: nowFn });
}

async function expectInvalid(extras: Extras): Promise<void> {
  let caught: unknown;
  try {
    await build(extras);
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
}

describe('constraints.max_path_length（§6.2.1）', () => {
  // Anchor → Intermediate → Leaf: Anchor から見て Leaf までの Intermediate は 1 つ（I）。
  it.each([1, 2, 5])('Anchor が %i を課す（Intermediate 1 つ ≤ 上限）なら成立', async (max) => {
    const chain = await build({ anchorAboutInt: { constraints: { max_path_length: max } } });
    expect(chain.valid).toBe(true);
  });

  it('Anchor が 0 を課す（Intermediate 1 つ > 0）なら拒否', async () => {
    await expectInvalid({ anchorAboutInt: { constraints: { max_path_length: 0 } } });
  });

  it('Intermediate が 0 を課す（Leaf 直下）なら成立', async () => {
    const chain = await build({ intAboutLeaf: { constraints: { max_path_length: 0 } } });
    expect(chain.valid).toBe(true);
  });

  it.each([-1, 1.5, '1', null, true, Number.NaN])('不正な値 %p は拒否', async (value) => {
    await expectInvalid({ anchorAboutInt: { constraints: { max_path_length: value } } });
  });
});

describe('constraints.naming_constraints（§6.2.2）', () => {
  const naming = (naming_constraints: unknown) => ({
    anchorAboutInt: { constraints: { naming_constraints } },
  });

  it('permitted のサブドメイン制約（.example.eu）を満たせば成立', async () => {
    expect((await build(naming({ permitted: ['.example.eu'] }))).valid).toBe(true);
  });

  it('ホスト指定の permitted は当該ホスト以外を拒否（Leaf/Intermediate が合致しない）', async () => {
    await expectInvalid(naming({ permitted: ['intermediate.example.eu'] }));
  });

  it('permitted に合致しない名前空間は拒否', async () => {
    await expectInvalid(naming({ permitted: ['.example.org'] }));
  });

  it('excluded が permitted より優先する（Leaf を除外）', async () => {
    await expectInvalid(naming({ permitted: ['.example.eu'], excluded: ['leaf.example.eu'] }));
  });

  it('.example.eu は example.eu 自体には合致しない（RFC 5280）', async () => {
    await expectInvalid({
      anchorAboutInt: { constraints: { naming_constraints: { permitted: ['.leaf.example.eu'] } } },
    });
  });

  it('excluded のみ: 合致しなければ成立', async () => {
    expect((await build(naming({ excluded: ['.example.org'] }))).valid).toBe(true);
  });

  it.each([
    ['非オブジェクト', 'x'],
    ['permitted が配列でない', { permitted: '.example.eu' }],
    ['空文字の要素', { permitted: [''] }],
    ['URL を渡している', { permitted: ['https://example.eu'] }],
  ])('不正な形（%s）は拒否', async (_label, value) => {
    await expectInvalid(naming(value));
  });
});

describe('constraints.allowed_entity_types（§6.2.3）', () => {
  const leafWith = (types: readonly string[]) => ({
    leafEc: { metadata: Object.fromEntries(types.map((type) => [type, {}])) },
  });
  const allowed = (allowed_entity_types: unknown) => ({
    anchorAboutInt: { constraints: { allowed_entity_types } },
  });

  it('許可された Entity Type のみなら成立', async () => {
    const chain = await build({
      ...leafWith(['openid_provider']),
      ...allowed(['openid_provider']),
    });
    expect(chain.valid).toBe(true);
  });

  it('許可リストに無い Entity Type を Leaf が持てば拒否', async () => {
    await expectInvalid({
      ...leafWith(['openid_provider', 'oauth_client']),
      ...allowed(['openid_provider']),
    });
  });

  it('空配列は federation_entity のみ許可（他 Type は拒否・federation_entity は成立）', async () => {
    expect((await build({ ...leafWith(['federation_entity']), ...allowed([]) })).valid).toBe(true);
    await expectInvalid({ ...leafWith(['openid_provider']), ...allowed([]) });
  });

  it('制約の無い Anchor は任意の Entity Type を許す', async () => {
    expect((await build(leafWith(['openid_provider']))).valid).toBe(true);
  });

  it.each([
    ['文字列', 'openid_provider'],
    ['非文字列要素', [1]],
    ['空文字要素', ['']],
  ])('不正な形（%s）は拒否', async (_label, value) => {
    await expectInvalid(allowed(value));
  });
});

describe('constraints の形', () => {
  it('constraints がオブジェクトでなければ拒否', async () => {
    await expectInvalid({ anchorAboutInt: { constraints: 'none' } });
    await expectInvalid({ anchorAboutInt: { constraints: [] } });
  });

  it('未知のメンバは無視する（§6.2）', async () => {
    const chain = await build({ anchorAboutInt: { constraints: { future_constraint: 1 } } });
    expect(chain.valid).toBe(true);
  });
});

describe('crit / metadata_policy_crit（§3.1）', () => {
  it.each([
    ['Subordinate Statement の crit', { anchorAboutInt: { crit: ['x-ext'], 'x-ext': 1 } }],
    [
      'Subordinate Statement の metadata_policy_crit',
      { intAboutLeaf: { metadata_policy_crit: ['x_op'] } },
    ],
    ['Leaf Entity Configuration の crit', { leafEc: { crit: ['x-ext'], 'x-ext': 1 } }],
    ['Trust Anchor Entity Configuration の crit', { anchorEc: { crit: ['x-ext'] } }],
    ['空配列の crit も存在するだけで拒否', { anchorAboutInt: { crit: [] } }],
  ])('%s は理解できないので拒否する', async (_label, extras) => {
    await expectInvalid(extras);
  });

  it('crit を含まなければ通常どおり成立', async () => {
    expect((await build({})).valid).toBe(true);
  });
});
