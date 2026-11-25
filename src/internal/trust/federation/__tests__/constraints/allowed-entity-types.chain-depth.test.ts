/**
 * `allowed_entity_types` は発行者から Leaf までの**全エンティティ**の Entity Configuration に効く。
 *
 * 以前は集める対象が `nodes`（Leaf の EC と Subordinate Statement）と直近の `current.statement` だけで、
 * 中間エンティティの EC は発行者が直下でない限り見落とされた（Leaf → I1 → I2 → Anchor で、Anchor が
 * I2 について課した制約は I1 の EC を見ない）。
 *
 * チェーン長 2〜5（エンティティ数）× 制約を課す発行者の位置 × 不許可 Entity Type を置くエンティティの位置の
 * 全組み合わせで、許可・不許可を決定的な結果（成立 / `5010`）で pin する。
 * 制約を課す発行者より上のエンティティ（発行者自身・上位・Anchor）の `metadata` は対象外で、拒否してはならない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { buildTrustChain } from '../../trust-chain.js';
import { makeFetchMock, nowFn, signStatement, toJwk, validPeriod } from '../federation-fixtures.js';

const ALLOWED = 'openid_provider';
const FORBIDDEN = 'oauth_authorization_server';

const entityId = (index: number): string => `https://e${index}.example.eu`;
const keyOf = (index: number): Uint8Array => new Uint8Array(32).fill(40 + index);
const jwksOf = (index: number) => ({ keys: [toJwk(keyOf(index), `k${index}`)] });

interface Shape {
  /** エンティティ数（Leaf = 0、Anchor = length - 1）。 */
  readonly length: number;
  /** `allowed_entity_types: [ALLOWED]` を課す発行者のインデックス（`entity[issuer]` が `entity[issuer-1]` について発行）。 */
  readonly issuer: number;
  /** `FORBIDDEN` を自身の EC の metadata に宣言するエンティティのインデックス（無ければ `undefined`）。 */
  readonly forbiddenAt?: number;
  /** `FORBIDDEN` を、このエンティティについての Subordinate Statement（その `sub`）の metadata に置く。 */
  readonly forbiddenInStatementAbout?: number;
}

/** 長さ `length` の鎖（E0 = Leaf、E(length-1) = Anchor）を組んで `buildTrustChain` を呼ぶ。 */
async function build(shape: Shape) {
  const { length, issuer, forbiddenAt, forbiddenInStatementAbout } = shape;
  const last = length - 1;
  const responses = new Map<string, string>();
  for (let i = 0; i < length; i++) {
    const metadata: Record<string, unknown> = {
      federation_entity: { federation_fetch_endpoint: `${entityId(i)}/fetch` },
      [ALLOWED]: {},
    };
    if (forbiddenAt === i) {
      metadata[FORBIDDEN] = {};
    }
    responses.set(
      `${entityId(i)}/.well-known/openid-federation`,
      signStatement(keyOf(i), {
        iss: entityId(i),
        sub: entityId(i),
        ...validPeriod(),
        jwks: jwksOf(i),
        ...(i === last ? {} : { authority_hints: [entityId(i + 1)] }),
        metadata,
      }),
    );
  }
  for (let i = 1; i < length; i++) {
    // E[i] が E[i-1] について発行する Subordinate Statement。
    const sub = i - 1;
    responses.set(
      `${entityId(i)}/fetch?sub=${encodeURIComponent(entityId(sub))}`,
      signStatement(keyOf(i), {
        iss: entityId(i),
        sub: entityId(sub),
        ...validPeriod(),
        jwks: jwksOf(sub),
        ...(forbiddenInStatementAbout === sub ? { metadata: { [FORBIDDEN]: {} } } : {}),
        ...(i === issuer ? { constraints: { allowed_entity_types: [ALLOWED] } } : {}),
      }),
    );
  }
  return buildTrustChain(entityId(0), entityId(last), {
    fetchFn: makeFetchMock(responses),
    now: nowFn,
  });
}

async function expectInvalid(shape: Shape): Promise<void> {
  let caught: unknown;
  try {
    await build(shape);
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
}

describe('allowed_entity_types: 全チェーン長 × 発行者位置 × 不許可 Type の位置', () => {
  for (const length of [2, 3, 4, 5]) {
    describe(`チェーン長 ${length}`, () => {
      it('不許可 Type が無ければ、どの発行者の制約でも成立する（正常系）', async () => {
        for (let issuer = 1; issuer < length; issuer++) {
          const chain = await build({ length, issuer });
          expect(chain.valid).toBe(true);
          expect(chain.nodes).toHaveLength(length + 1);
        }
      });

      for (let issuer = 1; issuer < length; issuer++) {
        for (let at = 0; at < length; at++) {
          // 発行者から見て下位（Leaf〜`issuer - 1`）の EC だけが対象。発行者自身と上位は対象外。
          const below = at < issuer;
          it(`発行者 E${issuer} が制約、E${at} の EC が不許可 Type → ${below ? '拒否 (5010)' : '成立（対象外）'}`, async () => {
            const shape: Shape = { length, issuer, forbiddenAt: at };
            if (below) {
              await expectInvalid(shape);
            } else {
              expect((await build(shape)).valid).toBe(true);
            }
          });
        }
      }
    });
  }

  it('Leaf → I1 → I2 → Anchor、Anchor が I2 に課し、中間 I1 の EC に不許可 Type', async () => {
    await expectInvalid({ length: 4, issuer: 3, forbiddenAt: 1 });
  });

  it('5 段で 2 段以上離れた中間（Anchor から見て I1・I2）の EC も拒否する', async () => {
    await expectInvalid({ length: 5, issuer: 4, forbiddenAt: 1 });
    await expectInvalid({ length: 5, issuer: 4, forbiddenAt: 2 });
    await expectInvalid({ length: 5, issuer: 4, forbiddenAt: 3 });
  });

  it('下位の Subordinate Statement の metadata の不許可 Type も、深い発行者の制約で拒否する（既存挙動を保つ）', async () => {
    await expectInvalid({ length: 5, issuer: 4, forbiddenInStatementAbout: 0 });
    await expectInvalid({ length: 5, issuer: 4, forbiddenInStatementAbout: 2 });
  });
});
