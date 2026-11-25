/**
 * チェーン検証（失効伝搬）の `Object.prototype` 汚染耐性テスト。
 *
 * `opts.policy` / `child.revocationPropagation` / `opts.customHandler` / `opts.maxDepth` を
 * プロトタイプ鎖で読むと、これらを**省略した**正当な検証でも失効伝搬が permissive 側へ落ち、
 * 失効した祖先があっても `valid` が true のまま残る（fail-open）。
 *
 * あわせて `POLICY_RANK` が素のオブジェクトリテラルであることによる迂回も検証する。
 * `revocationPropagation: "constructor"` のような**列挙外の文字列**を VC に埋めると
 * `POLICY_RANK['constructor']` が `Object.prototype.constructor`（関数）にヒットし、
 * `rankOf` の「未知は strict」フォールバック（`?? POLICY_RANK.strict`）を非 undefined として
 * すり抜ける。その結果 `rankOf(declared) >= rankOf(requested)` が関数との比較で必ず false になり、
 * 検証者側の `policy: "permissive"` が無条件に勝って失効伝搬を回避できてしまう。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
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
    status?: CredentialStatus;
    revocationPropagation?: string;
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
    ...(opts.status !== undefined ? { credentialStatus: opts.status } : {}),
    ...(opts.revocationPropagation !== undefined
      ? { revocationPropagation: opts.revocationPropagation as ChainPolicy }
      : {}),
  };
}

/** 子（leaf）→ 親（root、失効済み）の 2 段チェーンを組む。 */
function revokedAncestorChain(childOverrides: { revocationPropagation?: string } = {}): {
  opts: ChainVerifyOptions;
} {
  const leaf = makeVc('urn:uuid:leaf', { derivedFrom: 'urn:uuid:root', ...childOverrides });
  const root = makeVc('urn:uuid:root', { status: STATUS_REF });
  const store = new Map<string, VerifiableCredential>([
    [leaf.id as string, leaf],
    [root.id as string, root],
  ]);
  return {
    opts: {
      resolveCredential: async (id) => store.get(id),
      verifyLink: () => true,
      resolveStatus: async (vc): Promise<StatusCheckResult> =>
        vc.id === 'urn:uuid:root' ? REVOKED_STATUS : VALID_STATUS,
    },
  };
}

describe('チェーン失効伝搬の Object.prototype 汚染耐性', () => {
  it('継承した policy: permissive は実効ポリシーにならない（strict のまま無効化する）', async () => {
    const { opts } = revokedAncestorChain();
    const result = await withPollutedPrototypeAsync({ policy: 'permissive' }, () =>
      verifyCredentialChain('urn:uuid:leaf', opts),
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('継承した revocationPropagation: permissive は VC の宣言として採用しない', async () => {
    const { opts } = revokedAncestorChain();
    const result = await withPollutedPrototypeAsync({ revocationPropagation: 'permissive' }, () =>
      verifyCredentialChain('urn:uuid:leaf', opts),
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('継承した customHandler は伝搬判定に使わない', async () => {
    const { opts } = revokedAncestorChain();
    let handlerCalls = 0;
    const result = await withPollutedPrototypeAsync(
      {
        customHandler: (): boolean => {
          handlerCalls += 1;
          return true;
        },
      },
      () => verifyCredentialChain('urn:uuid:leaf', { ...opts, policy: 'custom' }),
    );
    expect(handlerCalls).toBe(0);
    // `custom` かつハンドラ未指定は strict と同じく無効化に倒れる。
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('列挙外の revocationPropagation は strict 扱いになり permissive に勝たせない', async () => {
    // `POLICY_RANK` が素のオブジェクトリテラルだと `constructor` が Object.prototype に当たり、
    // 「未知は strict」フォールバックをすり抜けて `opts.policy: permissive` が勝つ。
    const { opts } = revokedAncestorChain({ revocationPropagation: 'constructor' });
    const result = await verifyCredentialChain('urn:uuid:leaf', {
      ...opts,
      policy: 'permissive',
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('継承した maxDepth は深さ制限を緩めない', async () => {
    // 既定 maxDepth は 10。**それより深い**チェーンでないと、汚染値 Infinity を拾っても
    // 走査結果が変わらず、修正前でも pass するトートロジーになる。12 段のチェーンを組み、
    // 深さ超過（4051）が汚染下でも送出されることで検出する。
    const store = new Map<string, VerifiableCredential>();
    const depth = 12;
    for (let i = 0; i < depth; i += 1) {
      const id = `urn:uuid:n${i}`;
      const vc = i === depth - 1 ? makeVc(id) : makeVc(id, { derivedFrom: `urn:uuid:n${i + 1}` });
      store.set(id, vc);
    }
    const deepOpts: ChainVerifyOptions = {
      resolveCredential: async (id) => store.get(id),
      verifyLink: () => true,
      resolveStatus: async (): Promise<StatusCheckResult> => VALID_STATUS,
    };

    let caught: unknown;
    try {
      await withPollutedPrototypeAsync({ maxDepth: Number.POSITIVE_INFINITY }, () =>
        verifyCredentialChain('urn:uuid:n0', deepOpts),
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.CHAIN_TOO_DEEP);
  });

  it('明示的に渡した maxDepth は従来どおり深さ制限を広げる（正常系）', async () => {
    const store = new Map<string, VerifiableCredential>();
    const depth = 12;
    for (let i = 0; i < depth; i += 1) {
      const id = `urn:uuid:m${i}`;
      const vc = i === depth - 1 ? makeVc(id) : makeVc(id, { derivedFrom: `urn:uuid:m${i + 1}` });
      store.set(id, vc);
    }
    const result = await verifyCredentialChain('urn:uuid:m0', {
      resolveCredential: async (id) => store.get(id),
      verifyLink: () => true,
      resolveStatus: async (): Promise<StatusCheckResult> => VALID_STATUS,
      maxDepth: 20,
    });
    expect(result.valid).toBe(true);
  });

  it('継承した verifyLink / resolveStatus は判定器として採用しない（fail-closed）', async () => {
    const leaf = makeVc('urn:uuid:solo', { status: STATUS_REF });
    const store = new Map<string, VerifiableCredential>([[leaf.id as string, leaf]]);
    let verifyCalls = 0;
    let statusCalls = 0;

    const result = await withPollutedPrototypeAsync(
      {
        verifyLink: (): boolean => {
          verifyCalls += 1;
          return true;
        },
        resolveStatus: async (): Promise<StatusCheckResult> => {
          statusCalls += 1;
          return VALID_STATUS;
        },
      },
      () =>
        // `verifyLink` / `resolveStatus` を渡していない呼び出し。汚染値を拾えば攻撃者の関数が
        // チェーンの署名・失効判定を下し、任意の VC を有効にできる。
        verifyCredentialChain('urn:uuid:solo', {
          resolveCredential: async (id: string) => store.get(id),
        } as unknown as ChainVerifyOptions),
    );

    expect(verifyCalls).toBe(0);
    expect(statusCalls).toBe(0);
    // 判定器が無い以上「有効」とは主張しない。
    expect(result.valid).toBe(false);
  });

  it('明示的に渡した policy: permissive は従来どおり伝搬を抑止する（正常系）', async () => {
    const { opts } = revokedAncestorChain();
    const result = await verifyCredentialChain('urn:uuid:leaf', { ...opts, policy: 'permissive' });
    expect(result.valid).toBe(true);
    expect(result.warnings).toContain('ancestor-revoked');
  });

  it('明示的に宣言した revocationPropagation: permissive は従来どおり尊重される（正常系）', async () => {
    const { opts } = revokedAncestorChain({ revocationPropagation: 'permissive' });
    const result = await verifyCredentialChain('urn:uuid:leaf', opts);
    expect(result.valid).toBe(true);
    expect(result.warnings).toContain('ancestor-revoked');
  });
});
