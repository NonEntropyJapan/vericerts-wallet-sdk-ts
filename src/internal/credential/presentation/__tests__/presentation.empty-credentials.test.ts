/**
 * 内包 VC ゼロの VP を `valid: true` にしない回帰テスト。
 *
 * 修正前の `buildPresentationVerificationFields` は `credentialResults.every((r) => r.valid)` だけで
 * `valid` を決めていた。`every([])` は**空真**なので、envelope 署名・`aud` / `nonce` 束縛・時刻
 * クレームをすべて満たした `verifiableCredential: []` の holder 署名済み VP が
 * `{ valid: true, credentialResults: [] }` を返し、しかも `errors` キーは省略されていた。
 *
 * 契約上 `valid: true` は「VP envelope が正当」**かつ**「全内包 VC が有効」の連言であり、
 * 文書化どおり `if (result.valid)` だけを見る RP は、**「提示者がある DID を保有している」以外を
 * 何も証明しない提示**で権限を与えてしまう（`errors` も無いため異常のシグナルが一つも無い）。
 *
 * 本ファイルはその空真を塞いだことを固定する。修正前は下の 2 ケースがいずれも失敗する。
 *
 * 実鍵のみを使う（モック禁止）。
 */

import { describe, expect, it } from 'bun:test';
import { issuePresentation } from '../issue.js';
import { verifyPresentation } from '../presentation.js';
import { FIXTURES, sampleVp, signerFor } from './presentation.fixtures.js';

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const HOLDER_ALG = 'ES256' as const;
const BOUND = { audience: 'https://verifier.example', nonce: 'n-empty-1' } as const;

/** VP 署名の検証に必要な最小オプション（holder 公開鍵）。 */
const holderKey = { key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk } } as const;

/** `verifiableCredential: []` の VP を holder 鍵で正しく署名する。 */
function emptyVp(opts: { readonly bound: boolean }): string {
  return issuePresentation(sampleVp({ verifiableCredential: [] }), signerFor(HOLDER_ALG), {
    nowSeconds: NOW,
    ...(opts.bound ? BOUND : {}),
  });
}

describe('内包 VC ゼロの VP（every([]) の空真）', () => {
  it('正しく署名された verifiableCredential: [] の VP は valid: false になる', () => {
    const jwt = emptyVp({ bound: false });

    const result = verifyPresentation(jwt, {
      ...holderKey,
      allowUnbound: true,
      nowSeconds: NOW,
    });

    // envelope 自体は正当（署名・時刻は通っている）。落とすのは「証明すべき VC が無い」ため。
    expect(result.presentation.holder).toBe('did:example:holder');
    expect(result.holderDID).toBe('did:example:holder');
    expect(result.credentialResults).toEqual([]);
    expect(result.valid).toBe(false);
    // `errors` が省略されると異常のシグナルが一つも残らない。必ず理由を返す。
    expect(result.errors).toEqual(['3002']);
  });

  it('aud / nonce を正しく束縛した空 VP でも valid: false（envelope の成立は許可にならない）', () => {
    const jwt = emptyVp({ bound: true });

    const result = verifyPresentation(jwt, {
      ...holderKey,
      expectedAudience: BOUND.audience,
      expectedNonce: BOUND.nonce,
      nowSeconds: NOW,
    });

    expect(result.payload.aud).toBe(BOUND.audience);
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual(['3002']);
  });
});
