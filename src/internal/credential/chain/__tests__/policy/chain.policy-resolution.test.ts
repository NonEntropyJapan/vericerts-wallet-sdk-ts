/**
 * 失効伝搬ポリシーの決定規則のテスト。
 *
 * VC 埋め込みの宣言（Issuer 側）と `opts.policy`（検証者側）の**より保守的な方**を採る
 * （`permissive` < `custom` < `strict`）。どちらか一方を無条件に優先すると逆向きの fail-open が出る:
 *
 * - `opts.policy` を優先 → Issuer が埋めた `strict` を検証者が `permissive` で無効化できる。
 * - VC の宣言を優先 → Issuer が宣言した `permissive` に対し検証者が `strict` を強制できない。
 */

import { describe, expect, it } from 'bun:test';
import type { StatusCheckResult } from '../../../sdjwt/status.js';
import type { CredentialStatus, VerifiableCredential } from '../../../vc/vc.js';
import {
  type ChainPolicy,
  ChainVerificationCache,
  type ChainVerifyOptions,
  verifyCredentialChain,
} from '../../index.js';

const V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
const STATUS_REF: CredentialStatus = {
  id: 'https://issuer.example/status/1#0',
  type: 'BitstringStatusListEntry',
};
const VALID_STATUS: StatusCheckResult = { valid: true, purpose: 'revocation', value: 0 };
const REVOKED_STATUS: StatusCheckResult = { valid: false, purpose: 'revocation', value: 1 };

/** 失効した親を 1 つ持つ最小チェーン（leaf --derivedFrom--> parent）。 */
function chainWith(declared: ChainPolicy | undefined): Map<string, VerifiableCredential> {
  const base = {
    '@context': [V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2026-01-01T00:00:00Z',
  };
  const parent = { ...base, id: 'urn:vc:parent', credentialStatus: STATUS_REF };
  const leaf = {
    ...base,
    id: 'urn:vc:leaf',
    derivedFrom: 'urn:vc:parent',
    ...(declared !== undefined ? { revocationPropagation: declared } : {}),
  };
  return new Map<string, VerifiableCredential>([
    ['urn:vc:parent', parent as VerifiableCredential],
    ['urn:vc:leaf', leaf as VerifiableCredential],
  ]);
}

function deps(store: Map<string, VerifiableCredential>, policy?: ChainPolicy): ChainVerifyOptions {
  return {
    resolveCredential: async (id) => store.get(id),
    verifyLink: () => true,
    resolveStatus: async (vc): Promise<StatusCheckResult> =>
      vc.id === 'urn:vc:parent' ? REVOKED_STATUS : VALID_STATUS,
    ...(policy !== undefined ? { policy } : {}),
  };
}

describe('保守的な方のポリシーを採る', () => {
  it('宣言 strict + 要求 permissive → strict（検証者が緩められない）', async () => {
    const r = await verifyCredentialChain('urn:vc:leaf', deps(chainWith('strict'), 'permissive'));
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('ancestor-revoked');
  });

  it('宣言 permissive + 要求 strict → strict（検証者が締められる）', async () => {
    const r = await verifyCredentialChain('urn:vc:leaf', deps(chainWith('permissive'), 'strict'));
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('ancestor-revoked');
  });

  it('宣言 permissive + 要求なし → permissive（Issuer の意図を尊重）', async () => {
    const r = await verifyCredentialChain('urn:vc:leaf', deps(chainWith('permissive')));
    expect(r.valid).toBe(true);
    expect(r.warnings).toContain('ancestor-revoked');
  });

  it('宣言なし + 要求 permissive → permissive（検証者の既定値として働く）', async () => {
    const r = await verifyCredentialChain('urn:vc:leaf', deps(chainWith(undefined), 'permissive'));
    expect(r.valid).toBe(true);
    expect(r.warnings).toContain('ancestor-revoked');
  });

  it('宣言なし + 要求なし → strict（fail-closed 既定）', async () => {
    const r = await verifyCredentialChain('urn:vc:leaf', deps(chainWith(undefined)));
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('ancestor-revoked');
  });
});

describe('custom は permissive と strict の中間', () => {
  it('宣言 permissive + 要求 custom → custom（customHandler が呼ばれる）', async () => {
    let called = false;
    const r = await verifyCredentialChain('urn:vc:leaf', {
      ...deps(chainWith('permissive'), 'custom'),
      customHandler: () => {
        called = true;
        return true; // 許容する
      },
    });
    expect(called).toBe(true);
    expect(r.valid).toBe(true);
  });

  it('宣言 strict + 要求 custom → strict（customHandler は呼ばれない）', async () => {
    let called = false;
    const r = await verifyCredentialChain('urn:vc:leaf', {
      ...deps(chainWith('strict'), 'custom'),
      customHandler: () => {
        called = true;
        return true;
      },
    });
    expect(called).toBe(false);
    expect(r.valid).toBe(false);
  });

  it('custom を解決したが customHandler 未指定なら strict に倒す', async () => {
    const r = await verifyCredentialChain('urn:vc:leaf', deps(chainWith('custom')));
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('ancestor-revoked');
  });
});

describe('列挙外の revocationPropagation は最も保守的に扱う', () => {
  it('未知の宣言 + 要求 permissive でも伝搬する（細工 VC で緩められない）', async () => {
    // VC 本文は非信頼入力。列挙外の値を最小ランク扱いにすると、細工した VC に
    // 未知の文字列を入れるだけで opts.policy: 'permissive' を勝たせられる。
    const store = chainWith('bogus' as ChainPolicy);
    const r = await verifyCredentialChain('urn:vc:leaf', deps(store, 'permissive'));
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('ancestor-revoked');
  });

  it('未知の宣言のみ（要求なし）でも strict に倒す', async () => {
    const r = await verifyCredentialChain('urn:vc:leaf', deps(chainWith('bogus' as ChainPolicy)));
    expect(r.valid).toBe(false);
  });
});

describe('キャッシュキーは結果を左右するオプションを含む', () => {
  it('permissive の結果が後続の strict 呼び出しにヒットしない', async () => {
    // 起点 VC ID だけをキーにすると、permissive で得た valid: true が TTL（5 分）の間
    // strict の呼び出しに配られ、失効した親を持つチェーンが有効と判定される（fail-open）。
    const cache = new ChainVerificationCache();
    const store = chainWith(undefined);
    const permissive = await verifyCredentialChain('urn:vc:leaf', {
      ...deps(store, 'permissive'),
      cache,
      now: 1000,
    });
    expect(permissive.valid).toBe(true);

    const strict = await verifyCredentialChain('urn:vc:leaf', {
      ...deps(store, 'strict'),
      cache,
      now: 1000,
    });
    expect(strict.valid).toBe(false);
    expect(strict.reason).toBe('ancestor-revoked');
  });

  it('同じオプションなら従来どおりキャッシュヒットする', async () => {
    const cache = new ChainVerificationCache();
    const store = chainWith(undefined);
    let calls = 0;
    const withCount = (): ChainVerifyOptions => ({
      ...deps(store, 'permissive'),
      cache,
      now: 1000,
      verifyLink: () => {
        calls += 1;
        return true;
      },
    });
    await verifyCredentialChain('urn:vc:leaf', withCount());
    const before = calls;
    await verifyCredentialChain('urn:vc:leaf', withCount());
    expect(calls).toBe(before); // 2 回目はヒットして再検証しない
  });

  it('maxDepth 違いでもキャッシュを共有しない', async () => {
    const cache = new ChainVerificationCache();
    const store = chainWith(undefined);
    const ok = await verifyCredentialChain('urn:vc:leaf', {
      ...deps(store, 'permissive'),
      cache,
      now: 1000,
      maxDepth: 10,
    });
    expect(ok.valid).toBe(true);
    await expect(
      verifyCredentialChain('urn:vc:leaf', {
        ...deps(store, 'permissive'),
        cache,
        now: 1000,
        maxDepth: 0,
      }),
    ).rejects.toThrow();
  });

  it('customHandler 違いでもキャッシュを共有しない', async () => {
    // policy: 'custom' は判定そのものを customHandler に委ねるため、許容する handler の
    // valid: true が、拒否する handler の呼び出しに配られると fail-open になる。
    const cache = new ChainVerificationCache();
    const store = chainWith(undefined);
    const allow = await verifyCredentialChain('urn:vc:leaf', {
      ...deps(store, 'custom'),
      cache,
      now: 1000,
      customHandler: () => true,
    });
    expect(allow.valid).toBe(true);

    const deny = await verifyCredentialChain('urn:vc:leaf', {
      ...deps(store, 'custom'),
      cache,
      now: 1000,
      customHandler: () => false,
    });
    expect(deny.valid).toBe(false);
    expect(deny.reason).toBe('ancestor-revoked');
  });
});
