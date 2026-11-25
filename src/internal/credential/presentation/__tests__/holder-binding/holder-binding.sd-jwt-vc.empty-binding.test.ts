/**
 * 実効バインド値が**空文字**のときの fail-closed 回帰テスト。
 *
 * `hasEffectiveBinding`（`credential-entry/holder-binding.ts`）は当初 `!== undefined` で判定していたため、
 * **空文字は「指定あり」**として通り、委譲先へ `audience: ''` / `nonce: ''` が渡っていた。KB-JWT 側も
 * `aud` / `nonce` が空文字なら単純な値比較で「一致」してしまうため、突合を要求しているのに
 * 素通りする迂回経路があった。委譲先 `verifySdJwt`と規則を揃えて非空文字列を要求する
 * ことで塞いだ範囲を固定する。
 *
 * `holder-binding.sd-jwt-vc.test.ts` から独立させているのは、同ファイルが 300 行上限に達したため。
 *
 * 実鍵のみを使う（モック禁止）。VP holder / KB-JWT は ES256、SD-JWT VC の issuer は ES256K。
 */

import { describe, expect, it } from 'bun:test';
import { computeSdHash, KB_JWT_TYP } from '../../../sdjwt/key-binding.js';
import { createSdJwt } from '../../../sdjwt/sdjwt.js';
import type { EmbeddedCredentialKeyResolver } from '../../credential-results.js';
import { issuePresentation } from '../../issue.js';
import { verifyPresentation } from '../../presentation.js';
import { FIXTURES, sampleVp, signerFor } from '../presentation.fixtures.js';

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const HOLDER_ALG = 'ES256' as const;
const ISSUER_ALG = 'ES256K' as const;
const ISSUER_DID = 'did:example:issuer';
const VCT = 'https://example.com/credentials/identity';
const NONCE = 'nonce-from-verifier';

/** 内包 VC の正しい発行者鍵（ES256K）を常に返す DI。 */
const issuerKeyResolver: EmbeddedCredentialKeyResolver = () => ({
  publicKeyJwk: FIXTURES[ISSUER_ALG].jwk,
});

/**
 * 任意の `aud` / `nonce` を載せた KB-JWT を手組みして `cnf` 付き SD-JWT VC に付ける。
 *
 * `addKeyBinding` は空文字の `audience` / `nonce` を拒否するため、「空 `aud` / `nonce` の KB-JWT」は
 * 正規 API では作れない。空文字を「未指定」と同じ扱いにするガードは、この手組み提示が無いと
 * **修正前も修正後も 3012**（期待値と実測値が単に不一致）になり、分岐を固定できない。
 */
function withRawKeyBinding(audience: string, nonce: string): string {
  const presentation = createSdJwt(signerFor(ISSUER_ALG), {
    vct: VCT,
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
    issuer: ISSUER_DID,
    nowSeconds: NOW,
    cnf: { jwk: FIXTURES[HOLDER_ALG].jwk },
  });
  const b64uText = (text: string): string => Buffer.from(text).toString('base64url');
  const header = b64uText(JSON.stringify({ alg: HOLDER_ALG, typ: KB_JWT_TYP }));
  const payload = b64uText(
    JSON.stringify({ aud: audience, nonce, sd_hash: computeSdHash(presentation), iat: NOW }),
  );
  const signingInput = `${header}.${payload}`;
  const sig = signerFor(HOLDER_ALG).sign(new TextEncoder().encode(signingInput));
  return `${presentation}${signingInput}.${Buffer.from(sig).toString('base64url')}`;
}

/** 指定の aud / nonce に束縛した JWT-VP を holder 鍵で署名する。 */
function vpBoundTo(entries: readonly string[], audience: string, nonce: string): string {
  return issuePresentation(sampleVp({ verifiableCredential: entries }), signerFor(HOLDER_ALG), {
    nowSeconds: NOW,
    audience,
    nonce,
  });
}

describe('実効バインド値が空文字の requireHolderBinding', () => {
  /**
   * `expectedAudience` / `expectedNonce` は VP レベルの束縛照合にも使われるため、VP 自身も空文字に
   * 束縛して VP レベルを通過させ、**内包 SD-JWT VC の層だけ**を評価対象にする。
   */
  const unbound = {
    key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk },
    allowUnbound: true,
    expectedAudience: '',
    expectedNonce: '',
  } as const;

  it('前提: 空 aud / nonce の KB-JWT は署名も sd_hash も正当（値比較なら一致してしまう）', () => {
    // 突合を要求しない既定の呼び出しでは、この提示は従来どおり受理される（後方互換）。
    const result = verifyPresentation(vpBoundTo([withRawKeyBinding('', '')], '', ''), {
      ...unbound,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(true);
    expect(result.credentialResults[0]).toMatchObject({ valid: true });
  });

  it('空文字の実効バインド値では 3012 で fail-closed（修正前は valid: true）', () => {
    const result = verifyPresentation(vpBoundTo([withRawKeyBinding('', '')], '', ''), {
      ...unbound,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('nonce だけ非空でも audience が空文字なら 3012（両方が非空でなければ照合成立と見なさない）', () => {
    const result = verifyPresentation(vpBoundTo([withRawKeyBinding('', NONCE)], '', NONCE), {
      key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk },
      allowUnbound: true,
      expectedAudience: '',
      expectedNonce: NONCE,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('audience だけ非空でも nonce が空文字なら 3012（逆方向も固定する）', () => {
    // `hasEffectiveBinding` の片側条件だけを落としても緑にならないよう、両方向を押さえる。
    const audience = 'https://verifier.example.com';
    const result = verifyPresentation(vpBoundTo([withRawKeyBinding(audience, '')], audience, ''), {
      key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk },
      allowUnbound: true,
      expectedAudience: audience,
      expectedNonce: '',
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });
});
