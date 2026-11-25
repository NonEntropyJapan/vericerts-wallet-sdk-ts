/**
 * チェーン失効伝搬の null プロトタイプ耐性テスト。
 *
 * `applyPolicy` は VC 本文の `revocationPropagation` を cast だけで読み、以前は
 * `POLICY_RANK[policy]` の**計算プロパティキー**で保守度を引いていた。キーへの変換
 * （`ToPropertyKey`）は `ToPrimitive` を伴うため、パース境界（`parseJsonWithoutPrototype`）を
 * 通った型不正な宣言（`toString` / `valueOf` を持たない）は `TypeError: No default value` になる。
 *
 * この例外は「未知の値は `strict`」という **fail-closed のフォールバック（`?? POLICY_RANK.strict`）
 * 自体を迂回**し、`verifyCredentialChain` が結果（`valid: false` / `reason`）ではなく生の例外を
 * 漏らす。`opts.policy` を渡した検証（`requested !== undefined`）でのみ保守度比較に到達する。
 *
 * **素のオブジェクトリテラルでは再現しない**（`'[object Object]'` というキーで引かれて
 * `undefined` → `?? strict` に落ちる）ため、必ず JSON 文字列を通した VC で検証すること。
 */

import { describe, expect, it } from 'bun:test';
import { parseJsonWithoutPrototype } from '../../../../prototype-safety/parse-json.js';
import type { StatusCheckResult } from '../../../sdjwt/status.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import { type ChainVerifyOptions, verifyCredentialChain } from '../../index.js';

const VALID_STATUS: StatusCheckResult = { valid: true, purpose: 'revocation', value: 0 };
const REVOKED_STATUS: StatusCheckResult = { valid: false, purpose: 'revocation', value: 1 };

/** VC を**パース境界経由**で作る（`revocationPropagation` に任意の値を載せられる）。 */
function nullProtoVc(id: string, extra: Record<string, unknown>): VerifiableCredential {
  return parseJsonWithoutPrototype(
    JSON.stringify({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:holder' },
      issuanceDate: '2026-01-01T00:00:00Z',
      id,
      ...extra,
    }),
  ) as VerifiableCredential;
}

/**
 * 子（leaf、`revocationPropagation` を宣言）→ 親（root、失効済み）の 2 段チェーンを組む。
 *
 * `verifyCredentialChain` は起点 VC ID とオプションでキャッシュするため、ケースごとに ID を分ける。
 */
function revokedAncestorChain(
  caseId: string,
  revocationPropagation: unknown,
): { leafId: string; opts: ChainVerifyOptions } {
  const leafId = `urn:uuid:leaf-${caseId}`;
  const rootId = `urn:uuid:root-${caseId}`;
  const leaf = nullProtoVc(leafId, { derivedFrom: rootId, revocationPropagation });
  const root = nullProtoVc(rootId, {
    credentialStatus: { id: 'https://issuer.example/status/1#0', type: 'BitstringStatusListEntry' },
  });
  // 前提: パース境界を通った宣言値は toString / valueOf を持たない。
  const declared = (leaf as unknown as Record<string, unknown>).revocationPropagation;
  if (typeof declared === 'object' && declared !== null) {
    expect(Object.getPrototypeOf(declared)).toBeNull();
  }
  const store = new Map<string, VerifiableCredential>([
    [leafId, leaf],
    [rootId, root],
  ]);
  return {
    leafId,
    opts: {
      resolveCredential: async (id) => store.get(id),
      verifyLink: () => true,
      resolveStatus: async (vc): Promise<StatusCheckResult> =>
        vc.id === rootId ? REVOKED_STATUS : VALID_STATUS,
    },
  };
}

describe('revocationPropagation の許可集合検証', () => {
  it('型不正な revocationPropagation でも TypeError にならず strict 扱いで無効化する', async () => {
    const { leafId, opts } = revokedAncestorChain('malformed-strict', {});

    // `requested !== undefined` でないと保守度比較（計算プロパティキー）に到達しない。
    const result = await verifyCredentialChain(leafId, { ...opts, policy: 'strict' });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('型不正な宣言は permissive に勝たせない（fail-closed のフォールバックを維持）', async () => {
    // 列挙外の値を「宣言なし」に倒すと検証者の permissive が無条件に勝つ（fail-open）。
    // 最も保守的な strict として扱い、permissive より優先されることを固定する。
    const { leafId, opts } = revokedAncestorChain('malformed-permissive', {});

    const result = await verifyCredentialChain(leafId, { ...opts, policy: 'permissive' });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ancestor-revoked');
  });

  it('妥当な permissive 宣言は従来どおり警告に留まる（正常系）', async () => {
    const { leafId, opts } = revokedAncestorChain('declared-permissive', 'permissive');

    const result = await verifyCredentialChain(leafId, { ...opts, policy: 'permissive' });

    expect(result.valid).toBe(true);
    expect(result.warnings).toContain('ancestor-revoked');
  });
});
