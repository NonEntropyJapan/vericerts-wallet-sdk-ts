/**
 * 複数親（N:1 来歴）のチェーン検証テスト。
 *
 * チェーン検証は `derivedFrom` と `basedOn` の**すべて**の親を辿る。
 * `basedOn` は単数と配列の両方を受け付ける。
 *
 * 検証内容:
 * - `basedOn` 配列の各要素を親として辿る（単数指定との後方互換も維持）
 * - 1 つの VC が複数種別の親エッジを同時に持つ場合の走査
 * - 共通の祖先を持つダイヤモンド構造を循環（4050）と誤検出しない
 * - 循環（4050）/ 深さ上限（4051）が分岐先でも機能する
 * - 複数親のうち 1 つが失効した場合の伝搬（関係種別ごと）
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { StatusCheckResult } from '../../../sdjwt/status.js';
import type { CredentialStatus, VerifiableCredential } from '../../../vc/vc.js';
import { type ChainVerifyOptions, verifyCredentialChain } from '../../index.js';

const V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

const STATUS_REF: CredentialStatus = {
  id: 'https://issuer.example/status/1#0',
  type: 'BitstringStatusListEntry',
};
const VALID_STATUS: StatusCheckResult = { valid: true, purpose: 'revocation', value: 0 };
const REVOKED_STATUS: StatusCheckResult = { valid: false, purpose: 'revocation', value: 1 };

function makeVc(
  id: string,
  opts: {
    derivedFrom?: string;
    basedOn?: string | readonly string[];
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

function baseDeps(store: Map<string, VerifiableCredential>): ChainVerifyOptions {
  return {
    resolveCredential: async (id) => store.get(id),
    verifyLink: () => true,
    resolveStatus: async (): Promise<StatusCheckResult> => VALID_STATUS,
  };
}

function storeOf(...vcs: VerifiableCredential[]): Map<string, VerifiableCredential> {
  return new Map(vcs.map((vc) => [vc.id as string, vc]));
}

describe('basedOn の単数・複数指定', () => {
  it('basedOn 配列の全要素を親として辿る', async () => {
    const ref1 = makeVc('urn:vc:ref1');
    const ref2 = makeVc('urn:vc:ref2');
    const leaf = makeVc('urn:vc:leaf', { basedOn: ['urn:vc:ref1', 'urn:vc:ref2'] });
    const result = await verifyCredentialChain('urn:vc:leaf', baseDeps(storeOf(ref1, ref2, leaf)));
    expect(result.valid).toBe(true);
    expect(result.chain.map((n) => n.vcId)).toEqual(['urn:vc:leaf', 'urn:vc:ref1', 'urn:vc:ref2']);
    expect(result.chain[1]?.relation).toBe('basedOn');
    expect(result.chain[2]?.relation).toBe('basedOn');
    expect(result.depth).toBe(1);
  });

  it('basedOn 単数指定は従来どおり動く（後方互換）', async () => {
    const ref = makeVc('urn:vc:ref');
    const leaf = makeVc('urn:vc:leaf', { basedOn: 'urn:vc:ref' });
    const result = await verifyCredentialChain('urn:vc:leaf', baseDeps(storeOf(ref, leaf)));
    expect(result.chain.map((n) => n.relation)).toEqual(['derivedFrom', 'basedOn']);
  });

  it('空配列の basedOn は親なしとして扱う', async () => {
    const leaf = makeVc('urn:vc:leaf', { basedOn: [] });
    const result = await verifyCredentialChain('urn:vc:leaf', baseDeps(storeOf(leaf)));
    expect(result.chain).toHaveLength(1);
    expect(result.depth).toBe(0);
  });
});

describe('N:1 来歴（複数の親エッジを同時に持つ）', () => {
  it('derivedFrom と basedOn 配列を同時に辿る', async () => {
    const parent = makeVc('urn:vc:parent');
    const ref1 = makeVc('urn:vc:ref1');
    const ref2 = makeVc('urn:vc:ref2');
    const leaf = makeVc('urn:vc:leaf', {
      derivedFrom: 'urn:vc:parent',
      basedOn: ['urn:vc:ref1', 'urn:vc:ref2'],
    });
    const result = await verifyCredentialChain(
      'urn:vc:leaf',
      baseDeps(storeOf(parent, ref1, ref2, leaf)),
    );
    expect(result.chain).toHaveLength(4);
    expect(result.chain[1]).toEqual({
      vcId: 'urn:vc:parent',
      relation: 'derivedFrom',
      valid: true,
    });
    expect(result.chain.map((n) => n.vcId)).toContain('urn:vc:ref1');
    expect(result.chain.map((n) => n.vcId)).toContain('urn:vc:ref2');
  });

  it('各親の先の祖先も辿り depth は最長経路になる', async () => {
    const root = makeVc('urn:vc:root');
    const mid = makeVc('urn:vc:mid', { derivedFrom: 'urn:vc:root' });
    const ref = makeVc('urn:vc:ref');
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:mid', basedOn: ['urn:vc:ref'] });
    const result = await verifyCredentialChain(
      'urn:vc:leaf',
      baseDeps(storeOf(root, mid, ref, leaf)),
    );
    expect(result.chain).toHaveLength(4);
    expect(result.depth).toBe(2);
  });

  it('共通の祖先（ダイヤモンド）を循環と誤検出せず 1 ノードにまとめる', async () => {
    const root = makeVc('urn:vc:root');
    const a = makeVc('urn:vc:a', { derivedFrom: 'urn:vc:root' });
    const b = makeVc('urn:vc:b', { derivedFrom: 'urn:vc:root' });
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:a', basedOn: ['urn:vc:b'] });
    const result = await verifyCredentialChain('urn:vc:leaf', baseDeps(storeOf(root, a, b, leaf)));
    expect(result.valid).toBe(true);
    expect(result.chain.map((n) => n.vcId)).toEqual([
      'urn:vc:leaf',
      'urn:vc:a',
      'urn:vc:b',
      'urn:vc:root',
    ]);
    expect(result.chain.filter((n) => n.vcId === 'urn:vc:root')).toHaveLength(1);
  });

  it('同じ親 ID を複数の関係で指しても 1 ノードとして扱う', async () => {
    const parent = makeVc('urn:vc:parent');
    const leaf = makeVc('urn:vc:leaf', {
      derivedFrom: 'urn:vc:parent',
      basedOn: ['urn:vc:parent'],
    });
    const result = await verifyCredentialChain('urn:vc:leaf', baseDeps(storeOf(parent, leaf)));
    expect(result.chain).toHaveLength(2);
    expect(result.chain[1]?.relation).toBe('derivedFrom');
  });

  it('各ノードの署名検証は 1 回だけ行う（重複解決しない）', async () => {
    const root = makeVc('urn:vc:root');
    const a = makeVc('urn:vc:a', { derivedFrom: 'urn:vc:root' });
    const b = makeVc('urn:vc:b', { derivedFrom: 'urn:vc:root' });
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:a', basedOn: ['urn:vc:b'] });
    const verified: string[] = [];
    await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(storeOf(root, a, b, leaf)),
      verifyLink: (vc) => {
        verified.push(vc.id as string);
        return true;
      },
    });
    expect(verified).toHaveLength(4);
    expect(verified.filter((id) => id === 'urn:vc:root')).toHaveLength(1);
  });
});

describe('構造エラーは分岐先でも機能する', () => {
  it('複数親の一方に循環があると CHAIN_CYCLE(4050)', async () => {
    const ok = makeVc('urn:vc:ok');
    const loop = makeVc('urn:vc:loop', { derivedFrom: 'urn:vc:leaf' });
    const leaf = makeVc('urn:vc:leaf', {
      derivedFrom: 'urn:vc:ok',
      basedOn: ['urn:vc:loop'],
    });
    await expect(
      verifyCredentialChain('urn:vc:leaf', baseDeps(storeOf(ok, loop, leaf))),
    ).rejects.toThrow(new VericertsError(ErrorCodes.CHAIN_CYCLE));
  });

  it('複数親の一方が深すぎると CHAIN_TOO_DEEP(4051)', async () => {
    const store = new Map<string, VerifiableCredential>();
    for (let i = 0; i <= 4; i += 1) {
      const vc = makeVc(`urn:vc:d${i}`, i === 4 ? {} : { derivedFrom: `urn:vc:d${i + 1}` });
      store.set(vc.id as string, vc);
    }
    const shallow = makeVc('urn:vc:shallow');
    store.set('urn:vc:shallow', shallow);
    const leaf = makeVc('urn:vc:leaf', {
      derivedFrom: 'urn:vc:shallow',
      basedOn: ['urn:vc:d0'],
    });
    store.set('urn:vc:leaf', leaf);
    await expect(
      verifyCredentialChain('urn:vc:leaf', { ...baseDeps(store), maxDepth: 2 }),
    ).rejects.toThrow(new VericertsError(ErrorCodes.CHAIN_TOO_DEEP));
  });

  it('複数親の一方が解決できないと CHAIN_PARENT_UNRESOLVABLE(4052)', async () => {
    const ok = makeVc('urn:vc:ok');
    const leaf = makeVc('urn:vc:leaf', {
      derivedFrom: 'urn:vc:ok',
      basedOn: ['urn:vc:missing'],
    });
    await expect(verifyCredentialChain('urn:vc:leaf', baseDeps(storeOf(ok, leaf)))).rejects.toThrow(
      new VericertsError(ErrorCodes.CHAIN_PARENT_UNRESOLVABLE),
    );
  });
});

describe('複数親の失効伝搬', () => {
  it('derivedFrom の親が 1 つでも失効すればチェーンは無効（strict）', async () => {
    const parent = makeVc('urn:vc:parent', { status: STATUS_REF });
    const ref = makeVc('urn:vc:ref');
    const leaf = makeVc('urn:vc:leaf', {
      derivedFrom: 'urn:vc:parent',
      basedOn: ['urn:vc:ref'],
    });
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(storeOf(parent, ref, leaf)),
      policy: 'strict',
      resolveStatus: async (vc): Promise<StatusCheckResult> =>
        vc.id === 'urn:vc:parent' ? REVOKED_STATUS : VALID_STATUS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('basedOn の親だけが失効した場合は警告に留まる', async () => {
    const parent = makeVc('urn:vc:parent');
    const ref = makeVc('urn:vc:ref', { status: STATUS_REF });
    const leaf = makeVc('urn:vc:leaf', {
      derivedFrom: 'urn:vc:parent',
      basedOn: ['urn:vc:ref'],
    });
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(storeOf(parent, ref, leaf)),
      policy: 'strict',
      resolveStatus: async (vc): Promise<StatusCheckResult> =>
        vc.id === 'urn:vc:ref' ? REVOKED_STATUS : VALID_STATUS,
    });
    expect(result.valid).toBe(true);
    expect(result.warnings).toContain('ancestor-revoked');
  });

  it('伝搬経路と非伝搬経路の両方から到達する祖先は伝搬側を優先する', async () => {
    // leaf --basedOn--> b --derivedFrom--> shared(失効)
    // leaf --derivedFrom--> a --derivedFrom--> shared
    const shared = makeVc('urn:vc:shared', { status: STATUS_REF });
    const a = makeVc('urn:vc:a', { derivedFrom: 'urn:vc:shared' });
    const b = makeVc('urn:vc:b', { derivedFrom: 'urn:vc:shared' });
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:a', basedOn: ['urn:vc:b'] });
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(storeOf(shared, a, b, leaf)),
      policy: 'strict',
      resolveStatus: async (vc): Promise<StatusCheckResult> =>
        vc.id === 'urn:vc:shared' ? REVOKED_STATUS : VALID_STATUS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });
});
