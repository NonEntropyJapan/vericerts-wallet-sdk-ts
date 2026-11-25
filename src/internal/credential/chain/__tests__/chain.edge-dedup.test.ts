/**
 * 親エッジの重複排除の回帰テスト。
 *
 * `parentEdges()` は `(関係種別, 親 ID)` の組で重複排除する。親 ID だけで先勝ち dedup すると、
 * 同じ親を `supersedes`（非伝搬）と `amends`（伝搬）の両方で宣言した VC で伝搬する関係が黙って
 * 捨てられ、失効が伝搬しなくなる（fail-open）。伝搬経路が一つでもあれば失効することを検証する。
 */

import { describe, expect, it } from 'bun:test';
import type { StatusCheckResult } from '../../sdjwt/status.js';
import type { CredentialStatus, VerifiableCredential } from '../../vc/vc.js';
import { type ChainPolicy, type ChainVerifyOptions, verifyCredentialChain } from '../index.js';

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
    supersedes?: string;
    amends?: string;
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
    ...(opts.supersedes !== undefined ? { supersedes: opts.supersedes } : {}),
    ...(opts.amends !== undefined ? { amends: opts.amends } : {}),
    ...(opts.status !== undefined ? { credentialStatus: opts.status } : {}),
    ...(opts.revocationPropagation !== undefined
      ? { revocationPropagation: opts.revocationPropagation }
      : {}),
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

/** 指定 ID の VC だけを失効扱いにする `resolveStatus`。 */
function revoke(id: string): ChainVerifyOptions['resolveStatus'] {
  return async (vc): Promise<StatusCheckResult> => (vc.id === id ? REVOKED_STATUS : VALID_STATUS);
}

describe('同じ親を複数の関係で宣言した場合（親エッジ dedup の回帰）', () => {
  it('supersedes と amends で同じ親を指すと伝搬する amends が生き残る', async () => {
    // 親 ID だけで先勝ち dedup すると非伝搬の supersedes だけが残り、失効が伝搬しなくなる。
    const store = storeOf(
      makeVc('urn:vc:parent', { status: STATUS_REF }),
      makeVc('urn:vc:leaf', {
        supersedes: 'urn:vc:parent',
        amends: 'urn:vc:parent',
        revocationPropagation: 'strict',
      }),
    );
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      resolveStatus: revoke('urn:vc:parent'),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('検証者指定の policy=strict も同条件で迂回されない', async () => {
    const store = storeOf(
      makeVc('urn:vc:parent', { status: STATUS_REF }),
      makeVc('urn:vc:leaf', { supersedes: 'urn:vc:parent', amends: 'urn:vc:parent' }),
    );
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      policy: 'strict',
      resolveStatus: revoke('urn:vc:parent'),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('重複しても chain には 1 ノードだけ載り解決も 1 回だけ', async () => {
    const store = storeOf(
      makeVc('urn:vc:parent'),
      makeVc('urn:vc:leaf', { supersedes: 'urn:vc:parent', amends: 'urn:vc:parent' }),
    );
    const resolved: string[] = [];
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      resolveCredential: async (id) => {
        resolved.push(id);
        return store.get(id);
      },
    });
    expect(result.chain).toHaveLength(2);
    expect(resolved.filter((id) => id === 'urn:vc:parent')).toHaveLength(1);
  });

  it('chain[] には伝搬する関係を報告する（valid=false と矛盾させない）', async () => {
    // 到達順では非伝搬の supersedes が先。伝搬経路から再到達したら報告を amends へ引き上げる。
    const store = storeOf(
      makeVc('urn:vc:parent', { status: STATUS_REF }),
      makeVc('urn:vc:leaf', { supersedes: 'urn:vc:parent', amends: 'urn:vc:parent' }),
    );
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      policy: 'strict',
      resolveStatus: revoke('urn:vc:parent'),
    });
    expect(result.valid).toBe(false);
    expect(result.chain).toHaveLength(2);
    // 伝搬しない supersedes を報告すると、利用側が chain[].relation から
    // 「伝搬しないはず」と誤読して fail-open 側の答えを得る。
    expect(result.chain[1]?.relation).toBe('amends');
  });

  it('伝搬経路が無ければ最初に到達した関係のまま報告する', async () => {
    const store = storeOf(
      makeVc('urn:vc:parent', { status: STATUS_REF }),
      makeVc('urn:vc:leaf', { supersedes: 'urn:vc:parent' }),
    );
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      policy: 'strict',
      resolveStatus: revoke('urn:vc:parent'),
    });
    expect(result.valid).toBe(true);
    expect(result.chain[1]?.relation).toBe('supersedes');
  });
});
