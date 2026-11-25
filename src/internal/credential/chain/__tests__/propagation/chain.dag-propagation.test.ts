/**
 * DAG 走査における失効伝搬の取りこぼし回帰テスト。
 *
 * `traverse.ts` は同じ VC の解決・評価をメモ化する。素朴に「2 度目の到達は親を再走査しない」と
 * すると、**非伝搬経路（`basedOn` / `supersedes`）が合流ノードへ先に到達した場合**、その先の祖先が
 * `propagating: false` のまま固定され、伝搬経路から見た失効が伝搬しない fail-open になる。
 * spec は「伝搬経路が 1 本でもあれば伝搬する（保守的側に倒す）」と定めているのでこれは違反。
 * 同じ理由で `depth` の過小報告と `maxDepth` の未強制も起きる。
 *
 * 併せて `revocationPropagation` の所有者も検証する。この属性は親エッジを**宣言した子 VC** に
 * 埋め込まれる。各再帰段でこの宣言を読むため、ポリシー解決と `customHandler` の `child` 引数は祖先ノード自身では
 * なく子 VC でなければならない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { StatusCheckResult } from '../../../sdjwt/status.js';
import type { CredentialStatus, VerifiableCredential } from '../../../vc/vc.js';
import { type ChainPolicy, type ChainVerifyOptions, verifyCredentialChain } from '../../index.js';

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

/**
 * 非伝搬経路が合流ノードへ先着する DAG を作る。
 *
 * ```
 * leaf --derivedFrom--> mid --derivedFrom--> shared --derivedFrom--> root
 *   \--basedOn---------------------------------^
 * ```
 *
 * 幅優先＋エッジ順（derivedFrom → supersedes → amends → basedOn）により `shared` へは
 * 非伝搬の `basedOn`（depth 1）が、伝搬する `mid` 経由（depth 2）より先に到達する。
 * よって `shared` の親 `root` は、再展開しないと `propagating: false` でしか評価されない。
 */
function mergeDag(): Map<string, VerifiableCredential> {
  // 全ノードに credentialStatus を付ける（無いノードは失効評価自体がスキップされるため）。
  return storeOf(
    makeVc('urn:vc:root', { status: STATUS_REF }),
    makeVc('urn:vc:shared', { derivedFrom: 'urn:vc:root', status: STATUS_REF }),
    makeVc('urn:vc:mid', { derivedFrom: 'urn:vc:shared', status: STATUS_REF }),
    makeVc('urn:vc:leaf', {
      derivedFrom: 'urn:vc:mid',
      basedOn: ['urn:vc:shared'],
      status: STATUS_REF,
    }),
  );
}

describe('合流ノードの先の祖先への失効伝搬（fail-open 回帰）', () => {
  it('非伝搬経路が合流ノードへ先着しても、伝搬経路の先の祖先の失効は伝搬する', async () => {
    // 再展開しないとこのケースは valid: true（fail-open）になる。
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(mergeDag()),
      policy: 'strict',
      resolveStatus: revoke('urn:vc:root'),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('合流ノード自身の失効も伝搬経路から到達すれば伝搬する', async () => {
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(mergeDag()),
      policy: 'strict',
      resolveStatus: revoke('urn:vc:shared'),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('合流ノード経由のより長い経路も数え、depth を過小報告しない', async () => {
    const result = await verifyCredentialChain('urn:vc:leaf', baseDeps(mergeDag()));
    // root への最長経路は leaf → mid → shared → root の 3 段。
    expect(result.depth).toBe(3);
    expect(result.chain.map((n) => n.vcId)).toEqual([
      'urn:vc:leaf',
      'urn:vc:mid',
      'urn:vc:shared',
      'urn:vc:root',
    ]);
  });

  it('合流ノード経由で maxDepth を超える経路があれば CHAIN_TOO_DEEP(4051)', async () => {
    await expect(
      verifyCredentialChain('urn:vc:leaf', { ...baseDeps(mergeDag()), maxDepth: 2 }),
    ).rejects.toThrow(new VericertsError(ErrorCodes.CHAIN_TOO_DEEP));
  });

  it('非伝搬経路しか無ければ従来どおり伝搬せず警告に留まる', async () => {
    // leaf --basedOn--> shared --derivedFrom--> root(失効)。伝搬経路が 1 本も無い。
    const store = storeOf(
      makeVc('urn:vc:root', { status: STATUS_REF }),
      makeVc('urn:vc:shared', { derivedFrom: 'urn:vc:root' }),
      makeVc('urn:vc:leaf', { basedOn: ['urn:vc:shared'] }),
    );
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      policy: 'strict',
      resolveStatus: revoke('urn:vc:root'),
    });
    expect(result.valid).toBe(true);
    expect(result.warnings).toContain('ancestor-revoked');
  });

  it('再展開しても解決・評価はノードごとに 1 回だけ（メモ化は維持）', async () => {
    const resolved: string[] = [];
    const verified: string[] = [];
    const store = mergeDag();
    await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      resolveCredential: async (id) => {
        resolved.push(id);
        return store.get(id);
      },
      verifyLink: (vc) => {
        verified.push(vc.id as string);
        return true;
      },
    });
    expect(resolved.filter((id) => id === 'urn:vc:shared')).toHaveLength(1);
    expect(resolved.filter((id) => id === 'urn:vc:root')).toHaveLength(1);
    expect(verified).toHaveLength(4);
  });
});

describe('revocationPropagation は親エッジを宣言した子 VC が持つ', () => {
  it('子の revocationPropagation=permissive がその親エッジの伝搬を緩める', async () => {
    // 祖先ノード（parent）側には revocationPropagation を置かない。子（leaf）の指定が効くこと。
    const store = storeOf(
      makeVc('urn:vc:parent', { status: STATUS_REF }),
      makeVc('urn:vc:leaf', {
        derivedFrom: 'urn:vc:parent',
        revocationPropagation: 'permissive',
      }),
    );
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      resolveStatus: revoke('urn:vc:parent'),
    });
    expect(result.valid).toBe(true);
    expect(result.warnings).toContain('ancestor-revoked');
  });

  it('ポリシーはエッジごとに宣言元の子 VC で決まる', async () => {
    // leaf(既定=strict) → mid(permissive) → root(失効)。効くのは mid の permissive。
    const store = storeOf(
      makeVc('urn:vc:root', { status: STATUS_REF }),
      makeVc('urn:vc:mid', {
        derivedFrom: 'urn:vc:root',
        revocationPropagation: 'permissive',
      }),
      makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:mid' }),
    );
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      resolveStatus: revoke('urn:vc:root'),
    });
    expect(result.valid).toBe(true);
    expect(result.warnings).toContain('ancestor-revoked');
  });

  it('VC 埋め込みの宣言は opts.policy より優先される（検証者が緩められない）', async () => {
    // Issuer が strict を宣言した VC は、検証者が policy: 'permissive' を渡しても伝搬する。
    // 逆順（opts.policy 優先）だと署名済みの失効伝搬宣言を検証者が無効化できる fail-open になる。
    const store = storeOf(
      makeVc('urn:vc:parent', { status: STATUS_REF }),
      makeVc('urn:vc:leaf', {
        derivedFrom: 'urn:vc:parent',
        revocationPropagation: 'strict',
      }),
    );
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      policy: 'permissive',
      resolveStatus: revoke('urn:vc:parent'),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('opts.policy は宣言を持たない VC の既定値として働く', async () => {
    const store = storeOf(
      makeVc('urn:vc:parent', { status: STATUS_REF }),
      makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:parent' }), // 宣言なし
    );
    const result = await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      policy: 'permissive',
      resolveStatus: revoke('urn:vc:parent'),
    });
    expect(result.valid).toBe(true);
    expect(result.warnings).toContain('ancestor-revoked');
  });

  it('customHandler の child 引数は祖先ではなくエッジを宣言した子 VC', async () => {
    const store = storeOf(
      makeVc('urn:vc:root', { status: STATUS_REF }),
      makeVc('urn:vc:mid', { derivedFrom: 'urn:vc:root' }),
      makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:mid' }),
    );
    const seen: Array<{ parent: string; child: string }> = [];
    await verifyCredentialChain('urn:vc:leaf', {
      ...baseDeps(store),
      policy: 'custom',
      customHandler: (parent, child) => {
        seen.push({ parent: parent.vcId, child: child.id as string });
        return true;
      },
      resolveStatus: revoke('urn:vc:root'),
    });
    // 失効した root への到達は mid が宣言した derivedFrom エッジ経由。
    expect(seen).toEqual([{ parent: 'urn:vc:root', child: 'urn:vc:mid' }]);
  });
});
