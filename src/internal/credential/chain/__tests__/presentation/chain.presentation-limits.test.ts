/**
 * `verifyCredentialChainOnPresentation` の VP 全体の走査量予算テスト。
 *
 *  `MAX_CHAIN_*` は 1 チェーンごとにリセットされるため、VP の要素数 N に比例して N 倍へ増幅した
 * （1MB の VP で `resolveCredential` 768 万回）。実時間ではなく `resolveCredential` の呼び出し回数
 * （決定的カウンタ）で VP 全体の上限を pin する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import {
  MAX_PRESENTATION_CREDENTIALS,
  newPresentationWorkBudget,
  PRESENTATION_WORK_LIMITS,
} from '../../../../primitives/presentation-work-budget.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import { verifyCredentialChainOnPresentation } from '../../index.js';
import { MAX_CHAIN_NODES } from '../../limits.js';

const MAX_PRESENTATION_CHAIN_ENTRIES = MAX_PRESENTATION_CREDENTIALS;
const MAX_PRESENTATION_CHAIN_NODES = PRESENTATION_WORK_LIMITS.chainNodes;

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

/** 各要素 `k<n>:0` から `perChain` 個のノードを持つ（親 16 件ずつの）チェーンを返し、`resolveCredential` の呼び出しを数える DI。 */
function chainsOf(perChain: number) {
  const counter = { calls: 0 };
  return {
    counter,
    opts: {
      extractVcId: (entry: string | Readonly<Record<string, unknown>>) =>
        typeof entry === 'object' && typeof entry.id === 'string' ? entry.id : undefined,
      resolveCredential: async (id: string) => {
        counter.calls += 1;
        const [k, i] = id.slice(1).split(':').map(Number) as [number, number];
        const parents: string[] = [];
        for (let c = 16 * i + 1; c <= 16 * i + 16 && c < perChain; c++) {
          parents.push(`k${k}:${c}`);
        }
        return vcWith(id, parents.length > 0 ? parents : undefined);
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

const entries = (n: number) => Array.from({ length: n }, (_, k) => ({ id: `k${k}:0` }));

describe('verifyCredentialChainOnPresentation: VP 全体の走査量予算', () => {
  it('要素数が MAX_PRESENTATION_CHAIN_ENTRIES を超える VP は、1 件も解決せず拒否する', async () => {
    const { counter, opts } = chainsOf(1);
    const vp = { verifiableCredential: entries(MAX_PRESENTATION_CHAIN_ENTRIES + 1) };
    expectTooLarge(await rejection(verifyCredentialChainOnPresentation(vp, opts)));
    expect(counter.calls).toBe(0);
  });

  it('各要素が 1 チェーン上限いっぱいでも、解決は VP 全体で MAX_PRESENTATION_CHAIN_NODES 回に収まる', async () => {
    const { counter, opts } = chainsOf(MAX_CHAIN_NODES);
    const vp = { verifiableCredential: entries(MAX_PRESENTATION_CHAIN_ENTRIES) };
    expectTooLarge(await rejection(verifyCredentialChainOnPresentation(vp, opts)));
    // 従来は MAX_PRESENTATION_CHAIN_ENTRIES * MAX_CHAIN_NODES 回まで増幅した。
    expect(MAX_PRESENTATION_CHAIN_ENTRIES * MAX_CHAIN_NODES).toBeGreaterThan(
      MAX_PRESENTATION_CHAIN_NODES,
    );
    expect(counter.calls).toBe(MAX_PRESENTATION_CHAIN_NODES);
  });

  it('同一 ID の重複要素は 1 度だけ解決し、結果は要素数ぶん同一の内容で返る', async () => {
    const { counter, opts } = chainsOf(3);
    const vp = { verifiableCredential: [{ id: 'k0:0' }, { id: 'k0:0' }, { id: 'k0:0' }] };
    const results = await verifyCredentialChainOnPresentation(vp, opts);
    expect(counter.calls).toBe(3);
    expect(results).toHaveLength(3);
    expect(results.every((r) => r.valid && r.chain.length === 3)).toBe(true);
  });

  it('ID を抽出できない要素はスキップし、通常の VP（複数要素・短いチェーン）は従来どおり成立する', async () => {
    const { counter, opts } = chainsOf(4);
    const vp = { verifiableCredential: [{ id: 'k0:0' }, {}, { id: 'k1:0' }] };
    const results = await verifyCredentialChainOnPresentation(vp, opts);
    expect(results).toHaveLength(2);
    expect(results.every((r) => r.valid)).toBe(true);
    expect(counter.calls).toBe(8);
  });

  it('VP 全体の共有予算（workBudget）を渡すと、解決はその残りから消費され、尽きた時点で 4051 になる', async () => {
    const { counter, opts } = chainsOf(4);
    const budget = newPresentationWorkBudget();
    const vp = { verifiableCredential: [{ id: 'k0:0' }, { id: 'k1:0' }] };
    await verifyCredentialChainOnPresentation(vp, { ...opts, workBudget: budget });
    // 4 ノード × 2 チェーンの解決が chainNodes と合計に積み上がる。
    expect(counter.calls).toBe(8);
    expect(PRESENTATION_WORK_LIMITS.chainNodes - budget.chainNodes).toBe(8);
    const spentTotal = PRESENTATION_WORK_LIMITS.total - budget.total;
    expect(spentTotal).toBe(
      PRESENTATION_WORK_LIMITS.chainNodes -
        budget.chainNodes +
        (PRESENTATION_WORK_LIMITS.chainVisits - budget.chainVisits),
    );

    // 他の仕事（署名検証など）で合計を使い切っていれば、chain は 1 件も解決せずに拒否する。
    const spent = newPresentationWorkBudget();
    spent.total = 0;
    const fresh = chainsOf(4);
    expectTooLarge(
      await rejection(
        verifyCredentialChainOnPresentation(vp, { ...fresh.opts, workBudget: spent }),
      ),
    );
    expect(fresh.counter.calls).toBe(0);
  });

  it('少数の巨大チェーン（1 要素・深さ 4 のノード 128 件）と多数の極小チェーン（64 要素・各 1 ノード）で消費の単位が揃う', async () => {
    const big = chainsOf(MAX_CHAIN_NODES);
    const bigBudget = newPresentationWorkBudget();
    await verifyCredentialChainOnPresentation(
      { verifiableCredential: [{ id: 'k0:0' }] },
      { ...big.opts, workBudget: bigBudget },
    );
    const small = chainsOf(1);
    const smallBudget = newPresentationWorkBudget();
    await verifyCredentialChainOnPresentation(
      { verifiableCredential: entries(MAX_PRESENTATION_CREDENTIALS) },
      { ...small.opts, workBudget: smallBudget },
    );
    // どちらの形でも「解決回数 = chainNodes の減少分」で、要素数やチェーン形状に依らない。
    expect(PRESENTATION_WORK_LIMITS.chainNodes - bigBudget.chainNodes).toBe(big.counter.calls);
    expect(PRESENTATION_WORK_LIMITS.chainNodes - smallBudget.chainNodes).toBe(small.counter.calls);
    expect(small.counter.calls).toBe(MAX_PRESENTATION_CREDENTIALS);
  });
});
