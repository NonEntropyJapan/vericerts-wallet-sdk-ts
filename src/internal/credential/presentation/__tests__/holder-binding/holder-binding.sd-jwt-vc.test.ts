/**
 * 内包 SD-JWT VC への `audience` / `nonce` / `requireKeyBinding` 中継の回帰テスト。
 *
 * **修正前の欠陥**: `credential-results.ts` の SD-JWT 経路は `verifySdJwt` へ `audience` /
 * `nonce` / `requireKeyBinding` を一切渡していなかった（配線漏れ）。その結果、
 *
 * - `cnf` を持つ内包 SD-JWT VC に付いた KB-JWT が**別の Verifier / 別セッション宛でも素通り**した
 * - `cnf` も KB-JWT も無い SD-JWT VC が、所有者性を要求した検証でも受理された
 *
 * KB-JWT が証明するのは `cnf.jwk` の鍵保持までで、その鍵と `vp.holder` DID の同一性は別途確認が必要になる。
 *
 * `verifySdJwt` / `assertKeyBinding` は `expectedAudience` /
 * `expectedNonce` が `undefined` のとき照合を**丸ごとスキップ**する。そのため
 * `{ allowUnbound: true, requireHolderBinding: true }`（実効バインド値なし）では、KB-JWT の鍵保持
 * だけを確かめて `valid: true` を返しており、別 Verifier 宛・別セッション nonce の KB-JWT が
 * 素通りしていた。照合できない入力は `3012` で fail-closed にする（末尾の describe）。
 *
 * 実鍵のみを使う（モック禁止）。VP holder / KB-JWT は ES256、SD-JWT VC の issuer は ES256K。
 */

import { describe, expect, it } from 'bun:test';
import { createSdJwt } from '../../../sdjwt/sdjwt.js';
import { addKeyBinding } from '../../../sdjwt/verify.js';
import type { EmbeddedCredentialKeyResolver } from '../../credential-results.js';
import { issuePresentation } from '../../issue.js';
import { verifyPresentation } from '../../presentation.js';
import { FIXTURES, sampleVp, signerFor } from '../presentation.fixtures.js';

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const HOLDER_ALG = 'ES256' as const;
const ISSUER_ALG = 'ES256K' as const;
const ISSUER_DID = 'did:example:issuer';
const VCT = 'https://example.com/credentials/identity';
const AUDIENCE = 'https://verifier.example.com';
const NONCE = 'nonce-from-verifier';

/** 内包 VC の正しい発行者鍵（ES256K）を常に返す DI。 */
const issuerKeyResolver: EmbeddedCredentialKeyResolver = () => ({
  publicKeyJwk: FIXTURES[ISSUER_ALG].jwk,
});

/** VP 署名の検証鍵と、この提示の Verifier バインド（束縛モード）。 */
const verifierBinding = {
  key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk },
  expectedAudience: AUDIENCE,
  expectedNonce: NONCE,
} as const;

/** SD-JWT VC を発行する（`withCnf` 時は holder 鍵を `cnf` に載せる）。 */
function issueSdJwt(withCnf: boolean): string {
  return createSdJwt(signerFor(ISSUER_ALG), {
    vct: VCT,
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
    issuer: ISSUER_DID,
    nowSeconds: NOW,
    ...(withCnf ? { cnf: { jwk: FIXTURES[HOLDER_ALG].jwk } } : {}),
  });
}

/** `cnf` 付き SD-JWT VC に、指定の aud / nonce で KB-JWT を付ける。 */
function withKeyBinding(audience: string, nonce: string): string {
  return addKeyBinding(issueSdJwt(true), signerFor(HOLDER_ALG), {
    audience,
    nonce,
    iatSeconds: NOW,
  });
}

/** 指定の VC 群を内包し、この提示の aud / nonce を持つ JWT-VP を holder 鍵で署名する。 */
function vpWith(entries: readonly string[]): string {
  return issuePresentation(sampleVp({ verifiableCredential: entries }), signerFor(HOLDER_ALG), {
    nowSeconds: NOW,
    audience: AUDIENCE,
    nonce: NONCE,
  });
}

describe('内包 SD-JWT VC の KB-JWT 検証', () => {
  it('この提示の aud / nonce に束縛された KB-JWT は requireHolderBinding: true でも通る', () => {
    const result = verifyPresentation(vpWith([withKeyBinding(AUDIENCE, NONCE)]), {
      ...verifierBinding,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(true);
    expect(result.credentialResults[0]).toMatchObject({ valid: true, format: 'dc+sd-jwt' });
  });

  it('別 Verifier 宛の KB-JWT は 3012 で弾かれる（audience 中継の配線是正）', () => {
    // 中継前は `verifySdJwt` に audience が渡らず、他所向けの KB-JWT がそのまま受理されていた。
    const result = verifyPresentation(vpWith([withKeyBinding('https://attacker.example', NONCE)]), {
      ...verifierBinding,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('別セッションの nonce に束縛された KB-JWT は 3012 で弾かれる（nonce 中継の配線是正）', () => {
    const result = verifyPresentation(
      vpWith([withKeyBinding(AUDIENCE, 'nonce-from-other-session')]),
      {
        ...verifierBinding,
        nowSeconds: NOW,
        credentialKey: issuerKeyResolver,
        requireHolderBinding: true,
      },
    );
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('中継は配線是正なので requireHolderBinding 未指定でも効く（KB-JWT がある場合）', () => {
    // KB-JWT が同梱されている限り、既定でも `cnf` 鍵での署名検証は従来から行っていた。
    // 足りていなかったのは aud / nonce の照合だけであり、そこだけが厳格化される。
    const result = verifyPresentation(vpWith([withKeyBinding('https://attacker.example', NONCE)]), {
      ...verifierBinding,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('cnf も KB-JWT も無い SD-JWT VC は requireHolderBinding: true で拒否される', () => {
    const result = verifyPresentation(vpWith([issueSdJwt(false)]), {
      ...verifierBinding,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('cnf を持つのに KB-JWT を付けていない提示も requireHolderBinding: true で拒否される', () => {
    const result = verifyPresentation(vpWith([issueSdJwt(true)]), {
      ...verifierBinding,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('既定では KB-JWT を持たない SD-JWT VC は従来どおり受理される（後方互換）', () => {
    const result = verifyPresentation(vpWith([issueSdJwt(false)]), {
      ...verifierBinding,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(true);
  });
});

describe('実効バインド値が無い requireHolderBinding（allowUnbound: true）', () => {
  /**
   * JWT-VC 側のテストと同じく `allowUnbound: true` で VP レベルの束縛照合を外した検証。
   * `expectedAudience` / `expectedNonce` を渡さないため、内包 SD-JWT VC へ中継される実効
   * バインド値は両方 `undefined` になる。
   */
  const unbound = {
    key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk },
    allowUnbound: true,
  } as const;

  it('別 Verifier / 別セッションの KB-JWT が 3012 で弾かれる（本指摘の PoC）', () => {
    // 修正前はこの提示が valid: true で返っていた。KB-JWT の署名（＝ cnf 鍵の保持）は正当なので
    // 委譲先が通し、aud / nonce は期待値 undefined で照合ごとスキップされていたため。
    const result = verifyPresentation(
      vpWith([withKeyBinding('https://attacker.example', 'nonce-from-other-session')]),
      { ...unbound, nowSeconds: NOW, credentialKey: issuerKeyResolver, requireHolderBinding: true },
    );
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('KB-JWT の束縛先が正しくても実効バインド値が無ければ 3012（照合できない入力は拒否）', () => {
    // 「たまたま正しい」提示も受理しない。実効値が無い時点で正しさを検査できていないため。
    const result = verifyPresentation(vpWith([withKeyBinding(AUDIENCE, NONCE)]), {
      ...unbound,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('allowUnbound: true でも expectedAudience / expectedNonce を渡せば通る', () => {
    const result = verifyPresentation(vpWith([withKeyBinding(AUDIENCE, NONCE)]), {
      ...unbound,
      expectedAudience: AUDIENCE,
      expectedNonce: NONCE,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
      requireHolderBinding: true,
    });
    expect(result.valid).toBe(true);
    expect(result.credentialResults[0]).toMatchObject({ valid: true, format: 'dc+sd-jwt' });
  });

  it('requireHolderBinding 未指定なら allowUnbound: true でも従来どおり受理される（後方互換）', () => {
    // fail-closed は突合を要求したときだけ効かせる。既定は「渡された値があるときだけ照合」。
    const result = verifyPresentation(vpWith([withKeyBinding(AUDIENCE, NONCE)]), {
      ...unbound,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(true);
  });
});
