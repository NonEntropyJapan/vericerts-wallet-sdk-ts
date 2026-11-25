/**
 * `verifyPresentation`（同期プリミティブ）のシグネチャ契約を固定する回帰テスト。
 *
 * 同期関数が文字列の JWT と必須の `opts` を受け取ることを確認する。ファサードが
 * `Promise<VerifiedPresentation>` を返すことは `wallet/__tests__/wallet.presentation.test.ts` が担う。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { issuePresentation } from '../issue.js';
import { verifyPresentation } from '../presentation.js';
import { FIXTURES, sampleVp, signerFor } from './presentation.fixtures.js';

const fx = FIXTURES.ES256;

/** 検証が通る JWT-VP と、その検証に必要な最小オプション。 */
function validCall(): { jwt: string; opts: Parameters<typeof verifyPresentation>[1] } {
  return {
    jwt: issuePresentation(sampleVp(), signerFor('ES256')),
    opts: { key: { publicKeyJwk: fx.jwk }, allowUnbound: true },
  };
}

describe('verifyPresentation のシグネチャ契約', () => {
  it('同期関数であり Promise を返さない', () => {
    const { jwt, opts } = validCall();
    const result: unknown = verifyPresentation(jwt, opts);

    // `await` 可能な値（thenable）を返していないこと。Promise 化は破壊的変更になる。
    expect(result).not.toBeInstanceOf(Promise);
    expect(typeof (result as { then?: unknown }).then).toBe('undefined');
    // 戻り値は同期的に VerifiedPresentation のフィールドを持つ（`credentialKey` を
    // 渡していないため内包 VC は fail-closed で `valid: false` になる）。
    expect((result as { holderDID: string }).holderDID).toBe('did:example:holder');
    expect((result as { credentialResults: readonly unknown[] }).credentialResults).toHaveLength(1);
    expect((result as { valid: boolean }).valid).toBe(false);
  });

  it('async function として宣言されていない', () => {
    // `AsyncFunction` になった時点で戻り値は Promise であり、同期契約を満たさない。
    expect(verifyPresentation.constructor.name).toBe('Function');
  });

  it('展開済みオブジェクトの VP は受理せず 3010 に正規化する（コンパクト JWT-VP 文字列のみ）', () => {
    // `vp: string | object` と読める記述に対する fail-close の固定。オブジェクトを渡しても
    // 「検証済み」にはならず、署名検証不成立（3010）として拒否される。
    const { opts } = validCall();
    const asObject = sampleVp() as unknown as string;

    expect(() => verifyPresentation(asObject, opts)).toThrow(VericertsError);
    try {
      verifyPresentation(asObject, opts);
    } catch (error) {
      expect((error as VericertsError).code).toBe(ErrorCodes.SIG_INVALID);
    }
  });

  it('opts は必須引数であり、省略した呼び出しは TypeError で fail-close する', () => {
    const { jwt } = validCall();
    expect(() => (verifyPresentation as unknown as (jwt: string) => unknown)(jwt)).toThrow(
      TypeError,
    );
  });
});
