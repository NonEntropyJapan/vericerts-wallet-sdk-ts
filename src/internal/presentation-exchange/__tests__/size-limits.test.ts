/**
 * Presentation Definition の件数上限（DCQL 側は）。
 *
 * 記述子 D 件 × 保有 VC H 件ぶんの `CredentialMatch` を評価が確保するため、1 MiB 未満の PD に
 * `fields: []`（全 VC に一致）の記述子を 2 万件並べると RSS が数 GB になった。実時間・RSS ではなく
 * 決定的なカウンタ（要素の読み出し回数・確保された一致件数・例外の種別）で pin する。
 */

import { describe, expect, it } from 'bun:test';
import type { QueryableCredential } from '../../auth/dcql/dcql.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { createPexBudget } from '../budget.js';
import {
  evaluatePresentationDefinition,
  evaluatePresentationDefinitionWithBudget,
  type InputDescriptor,
  type PresentationDefinition,
  parsePresentationDefinition,
} from '../index.js';
import { MAX_INPUT_DESCRIPTORS, MAX_PEX_MATCHES } from '../limits.js';

const descriptor = (i: number) => ({ id: `d${i}`, constraints: { fields: [] } });

/** 添字読み出しを数える配列（`Array.isArray` は `true`）。要素を 1 件も読まずに拒否できるかの検証用。 */
function countingArray(length: number, make: (i: number) => unknown) {
  const counter = { reads: 0 };
  const array = new Proxy(
    Array.from({ length }, (_, i) => make(i)),
    {
      get(target, key, receiver) {
        if (typeof key === 'string' && /^\d+$/.test(key)) {
          counter.reads += 1;
        }
        return Reflect.get(target, key, receiver);
      },
    },
  );
  return { array, counter };
}

function expectRejected(fn: () => unknown, reason: string): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect((err as VericertsError).context).toMatchObject({ reason });
    return;
  }
  throw new Error('should have thrown');
}

const held = (count: number): QueryableCredential[] =>
  Array.from({ length: count }, (_, i) => ({
    id: `c${i}`,
    format: 'jwt_vc_json',
    claims: { a: 1 },
  })) as unknown as QueryableCredential[];

const handBuilt = (descriptors: unknown[]): PresentationDefinition =>
  ({ id: 'p', input_descriptors: descriptors }) as unknown as PresentationDefinition;

describe('parsePresentationDefinition: input_descriptors 件数上限', () => {
  it('上限ちょうどまで受理し、超えると 8030（too_many_input_descriptors）', () => {
    const at = Array.from({ length: MAX_INPUT_DESCRIPTORS }, (_, i) => descriptor(i));
    const parsed = parsePresentationDefinition({ id: 'p', input_descriptors: at });
    expect(parsed.input_descriptors).toHaveLength(MAX_INPUT_DESCRIPTORS);
    expectRejected(
      () =>
        parsePresentationDefinition({
          id: 'p',
          input_descriptors: [...at, descriptor(at.length)],
        }),
      'too_many_input_descriptors',
    );
  });

  it('1 MiB 未満の 2 万件の記述子は 1 件も読まずに拒否する（修正前は全件パースして受理）', () => {
    const text = `{"id":"p","input_descriptors":[${Array.from({ length: 20_000 }, (_, i) => JSON.stringify(descriptor(i))).join(',')}]}`;
    expect(text.length).toBeLessThan(1_048_576);
    expectRejected(
      () => parsePresentationDefinition(parseJsonWithoutPrototype(text) as Record<string, unknown>),
      'too_many_input_descriptors',
    );
    const { array, counter } = countingArray(20_000, descriptor);
    expectRejected(
      () =>
        parsePresentationDefinition({ id: 'p', input_descriptors: array } as unknown as Record<
          string,
          unknown
        >),
      'too_many_input_descriptors',
    );
    expect(counter.reads).toBe(0);
  });
});

describe('evaluatePresentationDefinition: 手組みの PD も件数で拒否', () => {
  it('記述子が上限を超えると、記述子を 1 件も評価せず（一致を確保せず）8030', () => {
    const { array, counter } = countingArray(20_000, descriptor);
    const pd = handBuilt(array);
    expectRejected(
      () => evaluatePresentationDefinition(pd, held(100)),
      'too_many_input_descriptors',
    );
    expectRejected(
      () => evaluatePresentationDefinitionWithBudget(pd, held(100), createPexBudget()),
      'too_many_input_descriptors',
    );
    expect(counter.reads).toBe(0);
  });

  it('上限ちょうどの記述子数は評価でき、一致件数は 記述子数 × 保有数 で頭打ちになる', () => {
    const descriptors = Array.from({ length: MAX_INPUT_DESCRIPTORS }, (_, i) =>
      descriptor(i),
    ) as unknown as InputDescriptor[];
    const matches = evaluatePresentationDefinition(handBuilt(descriptors), held(5));
    expect(matches).toHaveLength(MAX_INPUT_DESCRIPTORS * 5);
  });

  it('一致件数が MAX_PEX_MATCHES を超える評価は切り捨てず 8030（too_many_matches）', () => {
    // 記述子数は上限内でも、保有数に比例して一致が増える。上限ちょうどまでは返り、1 件超えると拒否する。
    const descriptors = Array.from({ length: MAX_INPUT_DESCRIPTORS }, (_, i) => descriptor(i));
    const perDescriptor = Math.floor(MAX_PEX_MATCHES / MAX_INPUT_DESCRIPTORS);
    const pd = handBuilt(descriptors);
    const atLimit = evaluatePresentationDefinition(pd, held(perDescriptor));
    expect(atLimit.length).toBeLessThanOrEqual(MAX_PEX_MATCHES);
    expectRejected(
      () => evaluatePresentationDefinition(pd, held(perDescriptor + 1)),
      'too_many_matches',
    );
  });
});
