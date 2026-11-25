/**
 * Credential Chain 構築・再帰検証・VP 検証のユニット/統合テスト。
 *
 * buildDerivedCredential（構築）、verifyCredentialChain（再帰検証・depth・循環4050/深度4051/解決不能4052）、
 * verifyCredentialChainOnPresentation（VP 内 VC 検証）を検証する。失効伝搬とキャッシュは
 * chain.propagation.test.ts を参照。DI スタブで実 I/O は行わない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { StatusCheckResult } from '../../sdjwt/status.js';
import type { CredentialStatus, VerifiableCredential } from '../../vc/vc.js';
import {
  buildDerivedCredential,
  type ChainPolicy,
  type ChainVerifyOptions,
  DEFAULT_MAX_CHAIN_DEPTH,
  verifyCredentialChain,
  verifyCredentialChainOnPresentation,
} from '../index.js';

const V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

/** 指定 id / derivedFrom / basedOn / credentialStatus / policy を持つ最小 VC を作る。 */
function makeVc(
  id: string,
  opts: {
    derivedFrom?: string;
    basedOn?: string;
    status?: CredentialStatus;
    revocationPropagation?: ChainPolicy;
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
    ...(opts.status !== undefined ? { credentialStatus: opts.status } : {}),
    ...(opts.revocationPropagation !== undefined
      ? { revocationPropagation: opts.revocationPropagation }
      : {}),
  };
}

const STATUS_REF: CredentialStatus = {
  id: 'https://issuer.example/status/1#0',
  type: 'BitstringStatusListEntry',
};

const VALID_STATUS: StatusCheckResult = { valid: true, purpose: 'revocation', value: 0 };
const REVOKED_STATUS: StatusCheckResult = { valid: false, purpose: 'revocation', value: 1 };

/** 全ノード有効・全リンク署名 OK のベースライン DI を作る（store から VC を解決）。 */
function baseDeps(store: Map<string, VerifiableCredential>): ChainVerifyOptions {
  return {
    resolveCredential: async (id) => store.get(id),
    verifyLink: () => true,
    resolveStatus: async (): Promise<StatusCheckResult> => VALID_STATUS,
  };
}

/** VC 群を id キーの store に格納する。 */
function storeOf(...vcs: VerifiableCredential[]): Map<string, VerifiableCredential> {
  return new Map(vcs.map((vc) => [vc.id as string, vc]));
}

describe('buildDerivedCredential（チェーン構築）', () => {
  it('親 ID を derivedFrom にセットした子 VC を構築する', () => {
    const parent = makeVc('urn:vc:parent');
    const child = buildDerivedCredential(parent, {
      '@context': [V2_CONTEXT],
      type: ['VerifiableCredential', 'DerivedCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:holder' },
      issuanceDate: '2026-02-01T00:00:00Z',
      id: 'urn:vc:child',
    });
    expect(child.derivedFrom).toBe('urn:vc:parent');
    expect(child.id).toBe('urn:vc:child');
    expect(child.type).toContain('DerivedCredential');
    expect(child.revocationPropagation).toBeUndefined();
  });

  it('revocationPropagation を子 VC に埋め込む', () => {
    const parent = makeVc('urn:vc:parent');
    const child = buildDerivedCredential(parent, makeVc('urn:vc:child'), 'strict');
    expect(child.derivedFrom).toBe('urn:vc:parent');
    expect(child.revocationPropagation).toBe('strict');
  });

  it('入力に残った親エッジを親 ID で上書きする', () => {
    const parent = makeVc('urn:vc:real-parent');
    // 型上 derivedFrom / basedOn は Omit されるが、実行時に混入しても親 ID で上書きされることを確認する。
    const staleInput = { ...makeVc('urn:vc:child'), derivedFrom: 'urn:vc:stale' };
    const child = buildDerivedCredential(parent, staleInput);
    expect(child.derivedFrom).toBe('urn:vc:real-parent');
  });

  it('親 VC に id が無い場合は VC_SCHEMA_INVALID(3002)', () => {
    const parent = { ...makeVc('x'), id: undefined } as VerifiableCredential;
    expect(() => buildDerivedCredential(parent, makeVc('urn:vc:child'))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });
});

describe('verifyCredentialChain 構築・検証ロジック', () => {
  it('親エッジの無い単一 VC を 1 ノード・depth 0 として検証する', async () => {
    const leaf = makeVc('urn:vc:leaf');
    const result = await verifyCredentialChain('urn:vc:leaf', baseDeps(storeOf(leaf)));
    expect(result.valid).toBe(true);
    expect(result.vcId).toBe('urn:vc:leaf');
    expect(result.depth).toBe(0);
    expect(result.chain).toHaveLength(1);
    expect(result.chain[0]).toEqual({ vcId: 'urn:vc:leaf', relation: 'derivedFrom', valid: true });
  });

  it('親子 2 段を起点→根順に検証し depth 1 を返す', async () => {
    const parent = makeVc('urn:vc:parent');
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:parent' });
    const result = await verifyCredentialChain('urn:vc:leaf', baseDeps(storeOf(parent, leaf)));
    expect(result.valid).toBe(true);
    expect(result.depth).toBe(1);
    expect(result.chain.map((n) => n.vcId)).toEqual(['urn:vc:leaf', 'urn:vc:parent']);
  });

  it('basedOn エッジも親として辿り relation に反映する', async () => {
    const parent = makeVc('urn:vc:base');
    const leaf = makeVc('urn:vc:leaf', { basedOn: 'urn:vc:base' });
    const result = await verifyCredentialChain('urn:vc:leaf', baseDeps(storeOf(parent, leaf)));
    expect(result.chain.map((n) => n.relation)).toEqual(['derivedFrom', 'basedOn']);
    expect(result.chain[1]?.vcId).toBe('urn:vc:base');
  });

  it('各リンクで verifyLink を呼ぶ（多段）', async () => {
    const gp = makeVc('urn:vc:gp');
    const p = makeVc('urn:vc:p', { derivedFrom: 'urn:vc:gp' });
    const leaf = makeVc('urn:vc:l', { derivedFrom: 'urn:vc:p' });
    const verified: string[] = [];
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(gp, p, leaf)),
      verifyLink: (vc) => {
        verified.push(vc.id as string);
        return true;
      },
    };
    const result = await verifyCredentialChain('urn:vc:l', deps);
    expect(result.chain).toHaveLength(3);
    expect(verified).toEqual(['urn:vc:l', 'urn:vc:p', 'urn:vc:gp']);
  });

  it('起点 VC の署名無効は valid=false（reason=leaf-signature-invalid）', async () => {
    const leaf = makeVc('urn:vc:leaf');
    const deps: ChainVerifyOptions = { ...baseDeps(storeOf(leaf)), verifyLink: () => false };
    const result = await verifyCredentialChain('urn:vc:leaf', deps);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('leaf-signature-invalid');
    expect(result.chain[0]?.valid).toBe(false);
  });

  it('祖先の署名無効はポリシーに関わらず全体を無効化する', async () => {
    const parent = makeVc('urn:vc:parent');
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:parent' });
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(parent, leaf)),
      policy: 'permissive',
      verifyLink: (vc) => vc.id !== 'urn:vc:parent',
    };
    const result = await verifyCredentialChain('urn:vc:leaf', deps);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-signature-invalid');
  });

  it('起点 VC が解決できないと CHAIN_PARENT_UNRESOLVABLE(4052)', async () => {
    await expect(verifyCredentialChain('urn:vc:missing', baseDeps(new Map()))).rejects.toThrow(
      new VericertsError(ErrorCodes.CHAIN_PARENT_UNRESOLVABLE),
    );
  });

  it('親が解決できない（チェーン破断）と CHAIN_PARENT_UNRESOLVABLE(4052)', async () => {
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:missing' });
    await expect(verifyCredentialChain('urn:vc:leaf', baseDeps(storeOf(leaf)))).rejects.toThrow(
      new VericertsError(ErrorCodes.CHAIN_PARENT_UNRESOLVABLE),
    );
  });

  it('親エッジの循環参照を検出して CHAIN_CYCLE(4050)', async () => {
    // a → b → a の循環。
    const a = makeVc('urn:vc:a', { derivedFrom: 'urn:vc:b' });
    const b = makeVc('urn:vc:b', { derivedFrom: 'urn:vc:a' });
    await expect(verifyCredentialChain('urn:vc:a', baseDeps(storeOf(a, b)))).rejects.toThrow(
      new VericertsError(ErrorCodes.CHAIN_CYCLE),
    );
  });

  it('深さ 10 のチェーンは検証成功する', async () => {
    const store = new Map<string, VerifiableCredential>();
    for (let i = 0; i <= DEFAULT_MAX_CHAIN_DEPTH; i += 1) {
      const isRoot = i === DEFAULT_MAX_CHAIN_DEPTH;
      const vc = makeVc(`urn:vc:n${i}`, isRoot ? {} : { derivedFrom: `urn:vc:n${i + 1}` });
      store.set(vc.id as string, vc);
    }
    const result = await verifyCredentialChain('urn:vc:n0', baseDeps(store));
    expect(result.valid).toBe(true);
    expect(result.depth).toBe(DEFAULT_MAX_CHAIN_DEPTH);
    expect(result.chain).toHaveLength(DEFAULT_MAX_CHAIN_DEPTH + 1);
  });

  it('深さ上限を超えるチェーンは CHAIN_TOO_DEEP(4051)', async () => {
    const store = new Map<string, VerifiableCredential>();
    // maxDepth=2 に対し 4 段のチェーンを作る。
    for (let i = 0; i <= 4; i += 1) {
      const vc = makeVc(`urn:vc:d${i}`, i === 4 ? {} : { derivedFrom: `urn:vc:d${i + 1}` });
      store.set(vc.id as string, vc);
    }
    await expect(
      verifyCredentialChain('urn:vc:d0', { ...baseDeps(store), maxDepth: 2 }),
    ).rejects.toThrow(new VericertsError(ErrorCodes.CHAIN_TOO_DEEP));
  });
});

describe('verifyCredentialChainOnPresentation（VP 内 VC の再帰検証）', () => {
  it('VP 内の各 VC のチェーンを検証し結果配列を返す', async () => {
    const parent = makeVc('urn:vc:parent');
    const leaf1 = makeVc('urn:vc:leaf1', { derivedFrom: 'urn:vc:parent' });
    const leaf2 = makeVc('urn:vc:leaf2');
    const vp = { verifiableCredential: ['jwt-leaf1', 'jwt-leaf2'] };
    const idByEntry: Record<string, string> = {
      'jwt-leaf1': 'urn:vc:leaf1',
      'jwt-leaf2': 'urn:vc:leaf2',
    };
    const results = await verifyCredentialChainOnPresentation(vp, {
      ...baseDeps(storeOf(parent, leaf1, leaf2)),
      extractVcId: (entry) => idByEntry[entry as string],
    });
    expect(results).toHaveLength(2);
    expect(results[0]?.vcId).toBe('urn:vc:leaf1');
    expect(results[0]?.depth).toBe(1);
    expect(results[1]?.vcId).toBe('urn:vc:leaf2');
    expect(results[1]?.depth).toBe(0);
  });

  it('ID を抽出できない VC 要素はスキップする', async () => {
    const leaf = makeVc('urn:vc:leaf');
    const vp = { verifiableCredential: ['jwt-leaf', 'opaque-no-id'] };
    const results = await verifyCredentialChainOnPresentation(vp, {
      ...baseDeps(storeOf(leaf)),
      extractVcId: (entry) => (entry === 'jwt-leaf' ? 'urn:vc:leaf' : undefined),
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.vcId).toBe('urn:vc:leaf');
  });

  it('VP 内 VC の親失効を strict で伝搬する', async () => {
    const parent = makeVc('urn:vc:parent', { status: STATUS_REF });
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:parent' });
    const vp = { verifiableCredential: ['jwt-leaf'] };
    const results = await verifyCredentialChainOnPresentation(vp, {
      ...baseDeps(storeOf(parent, leaf)),
      policy: 'strict',
      resolveStatus: async (vc): Promise<StatusCheckResult> =>
        vc.id === 'urn:vc:parent' ? REVOKED_STATUS : VALID_STATUS,
      extractVcId: () => 'urn:vc:leaf',
    });
    expect(results[0]?.valid).toBe(false);
    expect(results[0]?.reason).toBe('ancestor-revoked');
  });
});
