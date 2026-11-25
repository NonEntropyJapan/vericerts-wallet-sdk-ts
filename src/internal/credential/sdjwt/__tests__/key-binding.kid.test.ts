/**
 * KB-JWT ヘッダへの `kid` 伝播のユニットテスト（実鍵・モック禁止）。
 *
 * KB-JWT の JWS ヘッダに `CredentialSigner.kid` が含まれ、キー順が維持されることを検証する。
 *
 * `addKeyBinding` が `buildJwsHeader` を経由せず、`signer.kid` が設定されていても
 * KB-JWT ヘッダから `kid` が脱落していた。KMS / HSM 運用では `kid` が検証側へ鍵を伝える唯一の
 * 手段になるため、Holder が複数鍵を持つ構成で Verifier が検証鍵を特定できなくなる。
 */

import { describe, expect, it } from 'bun:test';
import type { CredentialSigner } from '../../vc/signer.js';
import { attachKeyBindingSignature, createKeyBindingTemplate } from '../key-binding.js';
import { parseSdJwt, selectDisclosures } from '../sdjwt.js';
import { addKeyBinding, verifySdJwt } from '../verify.js';
import {
  AUD,
  IAT,
  ISSUER_JWK,
  issue,
  NONCE,
  SESSION_ALG,
  SESSION_SIGNER,
  signAsSession,
  VCT,
} from './key-binding.fixtures.js';

describe('KB-JWT ヘッダの kid 伝播', () => {
  /** `kid` を持つ Agent Session 署名鍵（KMS / HSM 運用で verification method ID を伝える構成）。 */
  const KID = 'did:example:agent#session-1';
  const KEYED_SESSION_SIGNER: CredentialSigner = { ...SESSION_SIGNER, kid: KID };

  /** SD-JWT presentation の末尾 KB-JWT から、デコード済みヘッダと生セグメントを取り出す。 */
  function kbHeaderOf(presentation: string): { raw: string; decoded: unknown } {
    const keyBinding = parseSdJwt(presentation).keyBinding;
    if (keyBinding === undefined) {
      throw new Error('KB-JWT が付与されていない');
    }
    const raw = keyBinding.split('.')[0] as string;
    return { raw, decoded: JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) };
  }

  it('signer.kid 設定時に KB-JWT ヘッダへ kid が載る', () => {
    const presentation = addKeyBinding(selectDisclosures(issue(), ['name']), KEYED_SESSION_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    // キー順は buildJwsHeader が定める alg → kid → typ に固定される。
    expect(kbHeaderOf(presentation).decoded).toEqual({
      alg: SESSION_ALG,
      kid: KID,
      typ: 'kb+jwt',
    });
  });

  it('kid 未設定時のヘッダは従来どおりのバイト列と一致する（後方互換）', () => {
    const presentation = addKeyBinding(selectDisclosures(issue(), ['name']), SESSION_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    const expected = Buffer.from(JSON.stringify({ alg: SESSION_ALG, typ: 'kb+jwt' })).toString(
      'base64url',
    );
    expect(kbHeaderOf(presentation).raw).toBe(expected);
  });

  it('kid 付きの KB-JWT も cnf.jwk で検証を通る（署名対象がヘッダを含むため）', () => {
    const presentation = addKeyBinding(selectDisclosures(issue(), ['name']), KEYED_SESSION_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    const result = verifySdJwt(presentation, {
      issuerKey: ISSUER_JWK,
      audience: AUD,
      nonce: NONCE,
      requireKeyBinding: true,
    });
    expect(result.keyBindingVerified).toBe(true);
    expect(result.vct).toBe(VCT);
  });

  it('分離型テンプレートでも kid を指定でき、合成した KB-JWT に反映される', () => {
    const template = createKeyBindingTemplate(issue(), {
      alg: SESSION_ALG,
      kid: KID,
      nonce: NONCE,
      audience: AUD,
      disclosedClaims: ['name'],
      iatSeconds: IAT,
    });
    expect(template.header).toEqual({ alg: SESSION_ALG, kid: KID, typ: 'kb+jwt' });

    const presentation = attachKeyBindingSignature(template, signAsSession(template.signingInput));
    // 統合構成（addKeyBinding）と分離構成が同一バイト列を生成することを確認する。
    expect(presentation).toBe(
      addKeyBinding(selectDisclosures(issue(), ['name']), KEYED_SESSION_SIGNER, {
        nonce: NONCE,
        audience: AUD,
        iatSeconds: IAT,
      }),
    );
  });
});
