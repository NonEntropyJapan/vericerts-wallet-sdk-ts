/**
 * `ChainRelation` 4 値の親エッジ探索と失効伝搬のテスト。
 *
 * 親との関係種別によって、子へ失効が伝わるかどうかが決まる。
 * - `derivedFrom`: 親 VC を根拠として派生（失効伝搬対象）
 * - `basedOn`: 参考に過ぎない（失効伝搬しない）
 * - `supersedes`: 親 VC の置換。親は論理的に廃止済み（失効伝搬しない）
 * - `amends`: 親 VC の部分訂正。親は生きている（失効伝搬対象）
 *
 * 伝搬しない関係でも、親の失効は `warnings` に残す（黙って捨てない）。
 * 祖先の署名不正は関係種別に依らずチェーン全体を無効化する（改ざん / 不正発行）。
 */

import { describe, expect, it } from 'bun:test';
import type { StatusCheckResult } from '../../sdjwt/status.js';
import type { CredentialStatus, VerifiableCredential } from '../../vc/vc.js';
import {
  buildDerivedCredential,
  type ChainVerifyOptions,
  verifyCredentialChain,
} from '../index.js';

const V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

const STATUS_REF: CredentialStatus = {
  id: 'https://issuer.example/status/1#0',
  type: 'BitstringStatusListEntry',
};
const VALID_STATUS: StatusCheckResult = { valid: true, purpose: 'revocation', value: 0 };
const REVOKED_STATUS: StatusCheckResult = { valid: false, purpose: 'revocation', value: 1 };

/** 親エッジの種別を指定して最小 VC を作る。 */
function makeVc(
  id: string,
  opts: {
    derivedFrom?: string;
    basedOn?: string;
    supersedes?: string;
    amends?: string;
    status?: CredentialStatus;
  } = {},
): VerifiableCredential {
  return {
    '@context': [V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id,
    ...(opts.derivedFrom !== undefined ? { derivedFrom: opts.derivedFrom } : {}),
    ...(opts.basedOn !== undefined ? { basedOn: opts.basedOn } : {}),
    ...(opts.supersedes !== undefined ? { supersedes: opts.supersedes } : {}),
    ...(opts.amends !== undefined ? { amends: opts.amends } : {}),
    ...(opts.status !== undefined ? { credentialStatus: opts.status } : {}),
  };
}

function storeOf(...vcs: VerifiableCredential[]): Map<string, VerifiableCredential> {
  return new Map(vcs.map((vc) => [vc.id as string, vc]));
}

/** 親のみ失効している DI を作る。 */
function depsWithRevokedParent(
  store: Map<string, VerifiableCredential>,
  parentId: string,
): ChainVerifyOptions {
  return {
    resolveCredential: async (id) => store.get(id),
    verifyLink: () => true,
    resolveStatus: async (vc): Promise<StatusCheckResult> =>
      vc.id === parentId ? REVOKED_STATUS : VALID_STATUS,
  };
}

describe('親エッジ探索: 4 値すべてを親として辿る', () => {
  const edgeCases = [
    { field: 'derivedFrom', relation: 'derivedFrom' },
    { field: 'basedOn', relation: 'basedOn' },
    { field: 'supersedes', relation: 'supersedes' },
    { field: 'amends', relation: 'amends' },
  ] as const;

  for (const { field, relation } of edgeCases) {
    it(`${field} を親エッジとして辿り relation に反映する`, async () => {
      const parent = makeVc('urn:vc:parent');
      const leaf = makeVc('urn:vc:leaf', { [field]: 'urn:vc:parent' });
      const result = await verifyCredentialChain('urn:vc:leaf', {
        resolveCredential: async (id) => storeOf(parent, leaf).get(id),
        verifyLink: () => true,
        resolveStatus: async (): Promise<StatusCheckResult> => VALID_STATUS,
      });
      expect(result.chain).toHaveLength(2);
      expect(result.chain[1]?.vcId).toBe('urn:vc:parent');
      expect(result.chain[1]?.relation).toBe(relation);
      expect(result.depth).toBe(1);
    });
  }
});

describe('失効伝搬: 関係種別ごとの意味論', () => {
  const propagating = [{ field: 'derivedFrom' }, { field: 'amends' }] as const;
  const nonPropagating = [{ field: 'basedOn' }, { field: 'supersedes' }] as const;

  for (const { field } of propagating) {
    it(`${field}: 親の失効はチェーン全体へ伝搬する（strict）`, async () => {
      const parent = makeVc('urn:vc:parent', { status: STATUS_REF });
      const leaf = makeVc('urn:vc:leaf', { [field]: 'urn:vc:parent' });
      const result = await verifyCredentialChain('urn:vc:leaf', {
        ...depsWithRevokedParent(storeOf(parent, leaf), 'urn:vc:parent'),
        policy: 'strict',
      });
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('ancestor-revoked');
    });
  }

  for (const { field } of nonPropagating) {
    it(`${field}: 親の失効は伝搬せず警告に留まる（strict でも）`, async () => {
      const parent = makeVc('urn:vc:parent', { status: STATUS_REF });
      const leaf = makeVc('urn:vc:leaf', { [field]: 'urn:vc:parent' });
      const result = await verifyCredentialChain('urn:vc:leaf', {
        ...depsWithRevokedParent(storeOf(parent, leaf), 'urn:vc:parent'),
        policy: 'strict',
      });
      expect(result.valid).toBe(true);
      expect(result.warnings).toContain('ancestor-revoked');
      expect(result.chain[1]?.valid).toBe(false);
    });
  }

  it('非伝搬エッジを経由した先の祖先失効も伝搬しない', async () => {
    // leaf --supersedes--> mid --derivedFrom--> root(失効)
    const root = makeVc('urn:vc:root', { status: STATUS_REF });
    const mid = makeVc('urn:vc:mid', { derivedFrom: 'urn:vc:root' });
    const leaf = makeVc('urn:vc:leaf', { supersedes: 'urn:vc:mid' });
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...depsWithRevokedParent(storeOf(root, mid, leaf), 'urn:vc:root'),
      policy: 'strict',
    });
    expect(result.valid).toBe(true);
    expect(result.warnings).toContain('ancestor-revoked');
  });

  it('伝搬エッジのみの経路では従来どおり伝搬する（amends → derivedFrom）', async () => {
    const root = makeVc('urn:vc:root', { status: STATUS_REF });
    const mid = makeVc('urn:vc:mid', { derivedFrom: 'urn:vc:root' });
    const leaf = makeVc('urn:vc:leaf', { amends: 'urn:vc:mid' });
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...depsWithRevokedParent(storeOf(root, mid, leaf), 'urn:vc:root'),
      policy: 'strict',
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('祖先の署名不正は関係種別に依らずチェーン全体を無効化する', async () => {
    const parent = makeVc('urn:vc:parent');
    const leaf = makeVc('urn:vc:leaf', { supersedes: 'urn:vc:parent' });
    const store = storeOf(parent, leaf);
    const result = await verifyCredentialChain('urn:vc:leaf', {
      resolveCredential: async (id) => store.get(id),
      verifyLink: (vc) => vc.id !== 'urn:vc:parent',
      resolveStatus: async (): Promise<StatusCheckResult> => VALID_STATUS,
      policy: 'permissive',
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-signature-invalid');
  });
});

describe('buildDerivedCredential は入力に残った親エッジを落とす', () => {
  it('derivedFrom 以外の親エッジ（basedOn / supersedes / amends）も取り除く', () => {
    const parent = makeVc('urn:vc:real-parent');
    // 型上は Omit されるが、実行時に混入するとチェーン検証で親エッジとして辿られてしまう。
    const staleInput = {
      ...makeVc('urn:vc:child'),
      derivedFrom: 'urn:vc:stale-derived',
      basedOn: ['urn:vc:stale-based'],
      supersedes: 'urn:vc:stale-superseded',
      amends: 'urn:vc:stale-amended',
    };
    const child = buildDerivedCredential(parent, staleInput);
    expect(child.derivedFrom).toBe('urn:vc:real-parent');
    expect(child.basedOn).toBeUndefined();
    expect(child.supersedes).toBeUndefined();
    expect(child.amends).toBeUndefined();
  });
});
