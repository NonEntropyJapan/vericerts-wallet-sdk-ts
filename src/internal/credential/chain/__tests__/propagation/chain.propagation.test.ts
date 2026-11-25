/**
 * Credential Chain 失効伝搬・検証結果キャッシュのユニット/統合テスト。
 *
 * strict / permissive / custom の失効伝搬を検証する。キャッシュの TTL は 5 分で、親 VC の失効時に無効化する。
 * 構築・再帰検証・VP 検証は chain.verify.test.ts を参照。DI スタブで実 I/O は行わない。
 */

import { describe, expect, it } from 'bun:test';
import type { StatusCheckResult } from '../../../sdjwt/status.js';
import type { CredentialStatus, VerifiableCredential } from '../../../vc/vc.js';
import {
  CHAIN_CACHE_TTL_MS,
  type ChainPolicy,
  ChainVerificationCache,
  type ChainVerifyOptions,
  verifyCredentialChain,
} from '../../index.js';

const NOW = Date.parse('2026-07-01T00:00:00Z');
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

describe('失効伝搬（統合）', () => {
  /** 親のみ失効する resolveStatus を作る。 */
  function parentRevoked(parentId: string): ChainVerifyOptions['resolveStatus'] {
    return async (vc): Promise<StatusCheckResult> =>
      vc.id === parentId ? REVOKED_STATUS : VALID_STATUS;
  }

  it('strict: 親 VC 失効時は葉が有効でもチェーン全体を無効化（reason=ancestor-revoked）', async () => {
    const parent = makeVc('urn:vc:parent', { status: STATUS_REF });
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:parent', status: STATUS_REF });
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(parent, leaf)),
      policy: 'strict',
      resolveStatus: parentRevoked('urn:vc:parent'),
    };
    const result = await verifyCredentialChain('urn:vc:leaf', deps);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
    expect(result.chain[1]?.valid).toBe(false);
  });

  it('VC の revocationPropagation=strict を既定ポリシーとして使う', async () => {
    const parent = makeVc('urn:vc:parent', { status: STATUS_REF });
    const leaf = makeVc('urn:vc:leaf', {
      derivedFrom: 'urn:vc:parent',
      revocationPropagation: 'strict',
    });
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(parent, leaf)),
      resolveStatus: parentRevoked('urn:vc:parent'),
    };
    const result = await verifyCredentialChain('urn:vc:leaf', deps);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('permissive: 親失効を警告に留めチェーンは有効のまま', async () => {
    const parent = makeVc('urn:vc:parent', { status: STATUS_REF });
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:parent' });
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(parent, leaf)),
      policy: 'permissive',
      resolveStatus: parentRevoked('urn:vc:parent'),
    };
    const result = await verifyCredentialChain('urn:vc:leaf', deps);
    expect(result.valid).toBe(true);
    expect(result.warnings).toContain('ancestor-revoked');
  });

  it('custom: ハンドラが false を返すと親失効を伝搬して無効化', async () => {
    const parent = makeVc('urn:vc:parent', { status: STATUS_REF });
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:parent' });
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(parent, leaf)),
      policy: 'custom',
      customHandler: () => false,
      resolveStatus: parentRevoked('urn:vc:parent'),
    };
    const result = await verifyCredentialChain('urn:vc:leaf', deps);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('custom: ハンドラが true を返すと親失効を許容してチェーン有効', async () => {
    const parent = makeVc('urn:vc:parent', { status: STATUS_REF });
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:parent' });
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(parent, leaf)),
      policy: 'custom',
      customHandler: () => true,
      resolveStatus: parentRevoked('urn:vc:parent'),
    };
    const result = await verifyCredentialChain('urn:vc:leaf', deps);
    expect(result.valid).toBe(true);
  });

  it('credentialStatus の無いノードは失効評価をスキップする', async () => {
    const parent = makeVc('urn:vc:parent'); // status なし
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:parent' });
    let statusCalls = 0;
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(parent, leaf)),
      resolveStatus: async (): Promise<StatusCheckResult> => {
        statusCalls += 1;
        return VALID_STATUS;
      },
    };
    const result = await verifyCredentialChain('urn:vc:leaf', deps);
    expect(result.valid).toBe(true);
    expect(statusCalls).toBe(0);
  });
});

describe('ChainVerificationCache（5 分 TTL・親失効バスト）', () => {
  it('TTL 内はキャッシュヒットし再検証しない', async () => {
    const cache = new ChainVerificationCache();
    const leaf = makeVc('urn:vc:leaf');
    let verifyCalls = 0;
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(leaf)),
      cache,
      now: NOW,
      verifyLink: () => {
        verifyCalls += 1;
        return true;
      },
    };
    await verifyCredentialChain('urn:vc:leaf', deps);
    await verifyCredentialChain('urn:vc:leaf', { ...deps, now: NOW + CHAIN_CACHE_TTL_MS - 1 });
    expect(verifyCalls).toBe(1); // 2 回目はキャッシュヒットで verifyLink 不呼び出し。
  });

  it('TTL 経過後は再検証する', async () => {
    const cache = new ChainVerificationCache();
    const leaf = makeVc('urn:vc:leaf');
    let verifyCalls = 0;
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(leaf)),
      cache,
      now: NOW,
      verifyLink: () => {
        verifyCalls += 1;
        return true;
      },
    };
    await verifyCredentialChain('urn:vc:leaf', deps);
    await verifyCredentialChain('urn:vc:leaf', { ...deps, now: NOW + CHAIN_CACHE_TTL_MS });
    expect(verifyCalls).toBe(2);
  });

  it('親 VC 失効通知（invalidateChain）でチェーンキャッシュをバストする', async () => {
    const cache = new ChainVerificationCache();
    const parent = makeVc('urn:vc:parent');
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:parent' });
    let verifyCalls = 0;
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(parent, leaf)),
      cache,
      now: NOW,
      verifyLink: () => {
        verifyCalls += 1;
        return true;
      },
    };
    await verifyCredentialChain('urn:vc:leaf', deps); // leaf + parent = 2 リンク検証。
    expect(verifyCalls).toBe(2);
    cache.invalidateChain('urn:vc:parent', NOW); // 親失効通知 → バスト。
    await verifyCredentialChain('urn:vc:leaf', { ...deps, now: NOW + 1 });
    expect(verifyCalls).toBe(4); // 再検証で leaf + parent をもう一度。
  });

  it('invalidated 記録は保持期間（TTL の 3 倍）経過後に掃除され、以降は通常の TTL キャッシュとして再ヒットする（無制限メモリ増加の防止）', async () => {
    const ttlMs = 1_000;
    const cache = new ChainVerificationCache(ttlMs);
    const parent = makeVc('urn:vc:parent');
    const leaf = makeVc('urn:vc:leaf', { derivedFrom: 'urn:vc:parent' });
    let verifyCalls = 0;
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(parent, leaf)),
      cache,
      now: NOW,
      verifyLink: () => {
        verifyCalls += 1;
        return true;
      },
    };

    await verifyCredentialChain('urn:vc:leaf', deps); // 初回はキャッシュ無しなので検証してキャッシュに格納。
    expect(verifyCalls).toBe(2);
    cache.invalidateChain('urn:vc:parent', NOW); // 親失効通知 → 無効化を記録（バスト自体は即時）。

    // 保持期間（ttlMs * 3）を過ぎた時点で再検証する。この再検証結果は「現在の失効状態を反映済み」
    // なので、以降キャッシュヒットして構わない。
    const afterRetention = NOW + ttlMs * 3 + 1;
    await verifyCredentialChain('urn:vc:leaf', { ...deps, now: afterRetention });
    expect(verifyCalls).toBe(4); // 直前の invalidateChain でバストされているため再検証する。

    // 修正前は `invalidated` が Set のまま無期限に保持され、`urn:vc:parent` を含む限り
    // 何度 set し直してもこの get で即バストされ続けていた（プロセス生存中ずっと再検証が走る =
    // メモリと再ヒットの両方が失われる）。修正後は保持期間超過で記録が掃除されているため、
    // TTL 内であればここはキャッシュヒットし verifyLink を再度呼ばない。
    await verifyCredentialChain('urn:vc:leaf', { ...deps, now: afterRetention + 1 });
    expect(verifyCalls).toBe(4);
  });

  it('clear で全キャッシュと無効化記録を消す', async () => {
    const cache = new ChainVerificationCache();
    const leaf = makeVc('urn:vc:leaf');
    let verifyCalls = 0;
    const deps: ChainVerifyOptions = {
      ...baseDeps(storeOf(leaf)),
      cache,
      now: NOW,
      verifyLink: () => {
        verifyCalls += 1;
        return true;
      },
    };
    await verifyCredentialChain('urn:vc:leaf', deps);
    cache.clear();
    await verifyCredentialChain('urn:vc:leaf', { ...deps, now: NOW + 1 });
    expect(verifyCalls).toBe(2);
  });
});
