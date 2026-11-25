/**
 * Credential Chain 走査量の上限テスト。
 *
 * `maxDepth` だけでは親の fan-out による指数展開（親 4 件・深さ 10 で `resolveCredential` 約 140 万回）を
 * 止められなかった。実時間ではなく `resolveCredential` の呼び出し回数（決定的カウンタ）で上限を pin する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import { verifyCredentialChain } from '../index.js';
import { MAX_CHAIN_NODES, MAX_CHAIN_PARENT_EDGES, MAX_CHAIN_VISITS } from '../limits.js';

const V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

function vcWith(id: string, derivedFrom?: readonly string[]): VerifiableCredential {
  return {
    '@context': [V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id,
    ...(derivedFrom !== undefined ? { derivedFrom: [...derivedFrom] } : {}),
  } as VerifiableCredential;
}

/** `resolveCredential` の呼び出し回数を数える DI（`parentsOf` が各 VC の親 ID を決める）。 */
function counting(parentsOf: (id: string) => readonly string[]) {
  const counter = { calls: 0 };
  return {
    counter,
    deps: {
      resolveCredential: async (id: string) => {
        counter.calls += 1;
        return vcWith(id, parentsOf(id));
      },
      verifyLink: () => true,
      resolveStatus: async () => undefined,
    },
  };
}

async function rejection(promise: Promise<unknown>): Promise<VericertsError> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    return err as VericertsError;
  }
  throw new Error('should have thrown');
}

function expectTooLarge(err: VericertsError): void {
  expect(err.code).toBe(ErrorCodes.CHAIN_TOO_DEEP);
  expect(err.context).toMatchObject({ reason: 'chain_too_large' });
}

const fanOut = (width: number) => (id: string) =>
  Array.from({ length: width }, (_, i) => `${id}.${i}`);

describe('verifyCredentialChain: 走査量の上限', () => {
  it('各 VC が親 4 件を並べても、解決は MAX_CHAIN_NODES 回で打ち切られる（従来は約 140 万回）', async () => {
    const { counter, deps } = counting(fanOut(4));
    expectTooLarge(await rejection(verifyCredentialChain('r', deps)));
    expect(counter.calls).toBe(MAX_CHAIN_NODES);
  });

  it('親 2 件の二分木でもノード数上限で拒否する', async () => {
    const { counter, deps } = counting(fanOut(2));
    expectTooLarge(await rejection(verifyCredentialChain('r', deps)));
    expect(counter.calls).toBe(MAX_CHAIN_NODES);
  });

  it('親エッジが MAX_CHAIN_PARENT_EDGES を超える VC は、親を 1 件も解決せず拒否する', async () => {
    const { counter, deps } = counting((id) =>
      id === 'r' ? fanOut(MAX_CHAIN_PARENT_EDGES + 1)(id) : [],
    );
    expectTooLarge(await rejection(verifyCredentialChain('r', deps)));
    expect(counter.calls).toBe(1);
  });

  it('巨大な親配列は要素を走査する前に件数だけで拒否する', async () => {
    const { counter, deps } = counting(() => []);
    const huge = Array.from({ length: 1_000_000 }, (_, i) => `p${i}`);
    const resolveCredential = async (id: string) => {
      counter.calls += 1;
      return vcWith(id, id === 'r' ? huge : []);
    };
    expectTooLarge(await rejection(verifyCredentialChain('r', { ...deps, resolveCredential })));
    expect(counter.calls).toBe(1);
  });

  it('合流（DAG）で訪問が膨らむチェーンは、ノード数が少なくても訪問数上限で拒否する', async () => {
    // 100 ノードの前方 DAG: n_i は n_{i+1} … n_{i+16} を親に持つ。到達経路数は深さとともに爆発する。
    const nodes = 100;
    const { counter, deps } = counting((id) => {
      const i = Number(id.slice(1));
      return Array.from({ length: MAX_CHAIN_PARENT_EDGES }, (_, k) => `n${i + 1 + k}`).filter(
        (p) => Number(p.slice(1)) < nodes,
      );
    });
    expectTooLarge(await rejection(verifyCredentialChain('n0', { ...deps, maxDepth: 100 })));
    expect(counter.calls).toBeLessThanOrEqual(nodes);
    expect(MAX_CHAIN_VISITS).toBeGreaterThan(MAX_CHAIN_NODES);
  });

  it('通常のチェーン（直列 10 段・親 2 件の木 4 段・親 MAX 件の 1 段）は従来どおり成立する', async () => {
    const linear = counting((id) => {
      const n = Number(id.slice(1));
      return n < 10 ? [`n${n + 1}`] : [];
    });
    const linearResult = await verifyCredentialChain('n0', linear.deps);
    expect(linearResult.valid).toBe(true);
    expect(linearResult.depth).toBe(10);
    expect(linearResult.chain).toHaveLength(11);

    const tree = counting((id) => (id.length < 1 + 4 * 2 ? fanOut(2)(id) : []));
    const treeResult = await verifyCredentialChain('r', tree.deps);
    expect(treeResult.valid).toBe(true);
    expect(treeResult.chain).toHaveLength(31);

    const wide = counting((id) => (id === 'r' ? fanOut(MAX_CHAIN_PARENT_EDGES)(id) : []));
    const wideResult = await verifyCredentialChain('r', wide.deps);
    expect(wideResult.valid).toBe(true);
    expect(wideResult.chain).toHaveLength(MAX_CHAIN_PARENT_EDGES + 1);
  });
});
