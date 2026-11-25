/**
 * Status List 解決器の fail-open 経路の `Object.prototype` 汚染耐性テスト。
 *
 * `failsafe-policy/gate.ts` 側を `ownProperty` 化しても、**呼び出し側が継承値を新しいオブジェクト
 * リテラルへ詰め直して渡す**と own プロパティに化けてしまい、ゲートの own 限定読み取りが
 * 無意味になる（`own-property.ts` の JSDoc が警告している失敗様式そのもの）。
 *
 * `decideFetchFailure` が `opts.failSafePolicy` / `requestConsent` / `onPolicyEvent` /
 * `auditContext` をプロトタイプ鎖で読んで `resolveFailOpen` へ詰め直していたため、
 * fail-safe オプションを**一切渡していない**解決器でも、汚染下では Status List の取得失敗が
 * fail-open で通過し（＝ 失効未確認のまま `valid: true`）、監査レコードが攻撃者のシンクへ渡っていた。
 *
 * これは本番で唯一の fail-open 経路なので、ゲート単体のテストだけでは検出できない。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { createStatusListResolver } from '../../status-list-resolver.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);

function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));
const URI = 'https://issuer.example/status/revocation';
const REF = { status_list: { idx: 0, uri: URI } };

/** fail-safe オプションを一切渡さない、取得が必ず失敗する解決器。 */
function failingResolver() {
  return createStatusListResolver({
    fetchToken: async () => {
      throw new Error('network down');
    },
    issuerPublicKey: ISSUER_JWK,
    purpose: 'revocation',
  });
}

describe('createStatusListResolver の fail-open 経路の汚染耐性', () => {
  it('継承した onPolicyEvent / requestConsent で取得失敗を fail-open させない', async () => {
    const leaked: unknown[] = [];
    let consentCalls = 0;

    const outcome = await withPollutedPrototypeAsync(
      {
        onPolicyEvent: (record: unknown) => {
          leaked.push(record);
        },
        requestConsent: (): boolean => {
          consentCalls += 1;
          return true;
        },
      },
      async () => {
        const resolver = failingResolver();
        try {
          return { ok: true as const, result: await resolver.resolve(REF) };
        } catch (error) {
          return { ok: false as const, error };
        }
      },
    );

    // 監査シンクも同意コールバックも渡していない以上、fail-open は成立しない（fail-closed）。
    expect(outcome.ok).toBe(false);
    // 攻撃者のシンクが監査レコードを受け取っていないこと。
    expect(leaked).toEqual([]);
    // 攻撃者の同意コールバックが呼ばれていないこと。
    expect(consentCalls).toBe(0);
  });

  it('継承した failSafePolicy は実効ポリシーにならない', async () => {
    // 監査シンクと同意コールバックは **own で明示的に渡す**。渡さないと `sink === undefined` の
    // 早期 return が先に効いて必ず fail-closed になり、`failSafePolicy` の汚染有無を
    // 区別できない（修正前でも pass するトートロジーになる）。
    const records: unknown[] = [];
    const outcome = await withPollutedPrototypeAsync(
      // 継承値を拾うと `escalate` で FO-1 が deny に格上げされ、fail-open が成立しなくなる。
      { failSafePolicy: { escalate: ['FO-1'] } },
      async () => {
        const resolver = createStatusListResolver({
          fetchToken: async () => {
            throw new Error('network down');
          },
          issuerPublicKey: ISSUER_JWK,
          purpose: 'revocation',
          requestConsent: () => true,
          onPolicyEvent: (record) => {
            records.push(record);
          },
        });
        try {
          return { ok: true as const, result: await resolver.resolve(REF) };
        } catch (error) {
          return { ok: false as const, error };
        }
      },
    );
    // 汚染した escalate を拾わない ＝ 既定どおり fail-open が成立し、監査記録が残る。
    expect(outcome.ok).toBe(true);
    expect(records).toHaveLength(1);
  });

  it('明示的に渡した fail-safe オプションは従来どおり fail-open を成立させる（正常系）', async () => {
    const records: unknown[] = [];
    const resolver = createStatusListResolver({
      fetchToken: async () => {
        throw new Error('network down');
      },
      issuerPublicKey: ISSUER_JWK,
      purpose: 'revocation',
      requestConsent: () => true,
      onPolicyEvent: (record) => {
        records.push(record);
      },
    });
    const result = await resolver.resolve(REF);
    // 監査記録つきで fail-open が成立する。
    expect(result.valid).toBe(true);
    expect(records).toHaveLength(1);
  });
});
