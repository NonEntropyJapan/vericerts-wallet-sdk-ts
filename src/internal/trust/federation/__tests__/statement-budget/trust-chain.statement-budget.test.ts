/**
 * `buildTrustChain` の Statement 本文量の予算。
 *
 * 1 通ごとの上限（`MAX_DOCUMENT_BYTES` = 1 MiB）だけでは、最大 5 段の連鎖（Entity Configuration 5 通 +
 * Subordinate Statement 4 通 = 9 通）に 1 MiB 近い未知クレーム `pad` を載せた連鎖が、署名検証より前に
 * 9 MiB ぶんの base64url デコードと JSON パースを強いた（Node で約 3.4 秒）。実時間ではなく、
 * `JSON.parse` に渡った総文字数・大きなパースの回数・例外の種別で pin する。
 * 大きさと件数の比率を変えた複数形状（少数の巨大 / 多数の中型 / 配列・入れ子）で確認する。
 */

import { afterEach, describe, expect, it, spyOn } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { MAX_CHAIN_STATEMENT_CHARS } from '../../statement/statement-budget.js';
import { buildTrustChain } from '../../trust-chain.js';
import { makeFetchMock, nowFn, signStatement, toJwk, validPeriod } from '../federation-fixtures.js';

const CHAIN_LENGTH = 5;
const BIG_PARSE_CHARS = 100_000;

const entityId = (index: number): string => `https://e${index}.example.eu`;
const entityKey = (index: number): Uint8Array => new Uint8Array(32).fill(41 + index);

/**
 * Leaf（e0）→ … → Anchor（e4）の 5 段チェーンを組み、全 9 通の Statement に未知クレーム `pad` を載せる。
 */
function buildPaddedChain(pad: () => unknown): Map<string, string> {
  const responses = new Map<string, string>();
  for (let i = 0; i < CHAIN_LENGTH; i++) {
    const id = entityId(i);
    const isTop = i === CHAIN_LENGTH - 1;
    const jwks = { keys: [toJwk(entityKey(i), `k${i}`)] };
    responses.set(
      `${id}/.well-known/openid-federation`,
      signStatement(
        entityKey(i),
        {
          iss: id,
          sub: id,
          ...validPeriod(),
          jwks,
          ...(isTop ? {} : { authority_hints: [entityId(i + 1)] }),
          ...(i === 0
            ? {}
            : { metadata: { federation_entity: { federation_fetch_endpoint: `${id}/fetch` } } }),
          pad: pad(),
        },
        { kid: `k${i}` },
      ),
    );
    if (i > 0) {
      // e_i が e_(i-1) について発行する Subordinate Statement。
      const childId = entityId(i - 1);
      responses.set(
        `${id}/fetch?sub=${encodeURIComponent(childId)}`,
        signStatement(entityKey(i), {
          iss: id,
          sub: childId,
          ...validPeriod(),
          jwks: { keys: [toJwk(entityKey(i - 1), `k${i - 1}`)] },
          pad: pad(),
        }),
      );
    }
  }
  return responses;
}

interface ParseSpy {
  totalChars(): number;
  bigParses(): number;
  restore(): void;
}

/** `JSON.parse` に渡った文字数を数える（決定的なカウンタ）。 */
function spyJsonParse(): ParseSpy {
  const original = JSON.parse;
  const lengths: number[] = [];
  const spy = spyOn(JSON, 'parse').mockImplementation(((text: string, reviver?: never) => {
    lengths.push(text.length);
    return original(text, reviver);
  }) as typeof JSON.parse);
  return {
    totalChars: () => lengths.reduce((sum, n) => sum + n, 0),
    bigParses: () => lengths.filter((n) => n >= BIG_PARSE_CHARS).length,
    restore: () => spy.mockRestore(),
  };
}

let parseSpy: ParseSpy | undefined;
afterEach(() => {
  parseSpy?.restore();
  parseSpy = undefined;
});

async function build(responses: Map<string, string>) {
  return buildTrustChain(entityId(0), entityId(CHAIN_LENGTH - 1), {
    fetchFn: makeFetchMock(responses),
    now: nowFn,
  });
}

async function expectBudgetExceeded(responses: Map<string, string>): Promise<void> {
  let caught: unknown;
  try {
    await build(responses);
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
  expect((caught as VericertsError).context).toMatchObject({ reason: 'statement_budget_exceeded' });
}

describe('buildTrustChain: Statement 本文量の予算', () => {
  // [形状, 1 通あたりの pad]。どれも 1 通は MAX_DOCUMENT_BYTES（1 MiB）に収まるが、9 通の総量は予算を超える。
  it.each([
    ['少数の巨大な文字列（約 0.9 MB × 9）', () => 'x'.repeat(650_000)],
    ['多数の中型な文字列（約 0.3 MB × 9）', () => 'x'.repeat(230_000)],
    [
      '空オブジェクトの巨大配列（約 0.6 MB × 9）',
      () => Array.from({ length: 150_000 }, () => ({})),
    ],
    [
      '入れ子の配列（約 0.5 MB × 9）',
      () => Array.from({ length: 12_000 }, () => [[{ a: 1 }], [{ b: [] }]]),
    ],
  ])('%s は予算で拒否され、JSON パース量が予算を超えない', async (_shape, pad) => {
    const responses = buildPaddedChain(pad);
    const largest = Math.max(...[...responses.values()].map((jwt) => jwt.length));
    // 前提: 1 通ごとの上限には収まり、9 通の総量は予算を超える形状である。
    expect(largest).toBeLessThan(1_048_576);
    expect([...responses.values()].reduce((sum, jwt) => sum + jwt.length, 0)).toBeGreaterThan(
      MAX_CHAIN_STATEMENT_CHARS,
    );
    parseSpy = spyJsonParse();
    await expectBudgetExceeded(responses);
    expect(parseSpy.totalChars()).toBeLessThanOrEqual(MAX_CHAIN_STATEMENT_CHARS);
  });

  it('予算内の 9 通は通り、各 Statement の JSON パースは 1 回だけ（二重パースしない）', async () => {
    const responses = buildPaddedChain(() => 'x'.repeat(110_000));
    const total = [...responses.values()].reduce((sum, jwt) => sum + jwt.length, 0);
    expect(total).toBeLessThanOrEqual(MAX_CHAIN_STATEMENT_CHARS);
    parseSpy = spyJsonParse();
    const chain = await build(responses);
    expect(chain.valid).toBe(true);
    // Leaf EC + Subordinate Statement 4 通 + Anchor EC。
    expect(chain.length).toBe(CHAIN_LENGTH + 1);
    // payload は 9 通ぶんを 1 回ずつ。以前は自己署名の Entity Configuration を 2 回ずつパースしていた。
    expect(parseSpy.bigParses()).toBe(CHAIN_LENGTH * 2 - 1);
  });

  it('ピン留め付きでも Anchor Entity Configuration のパースは 1 回ぶんだけ増える', async () => {
    const responses = buildPaddedChain(() => 'x'.repeat(100_000));
    const anchorJwks = { keys: [toJwk(entityKey(CHAIN_LENGTH - 1))] };
    parseSpy = spyJsonParse();
    const chain = await buildTrustChain(
      entityId(0),
      entityId(CHAIN_LENGTH - 1),
      { fetchFn: makeFetchMock(responses), now: nowFn },
      { trustAnchorJwks: anchorJwks },
    );
    expect(chain.anchorPinned).toBe(true);
    expect(parseSpy.bigParses()).toBe(CHAIN_LENGTH * 2 - 1 + 1);
  });
});
