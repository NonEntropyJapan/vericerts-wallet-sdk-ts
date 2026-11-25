/**
 * SIOPv2 Pseudonym ログインの統合テスト。
 *
 * 検証観点:
 * - ID Token に nonce / aud(client_id) / sub(urn:pseudonym:<hash(pub)>) が設定される。
 * - 署名が派生公開鍵で検証できる（sub_jwk バインド）。
 * - 同一 RP 再訪問（別 nonce）で同一 sub を提示する（継続性）。
 * - 異なる RP には相関不能な別 sub を提示する（相関不能性）。
 * - 必須フィールド欠落は RP_IDENTIFIER_INVALID (10201)。
 * - 派生秘密鍵は正常系・例外系のいずれでも使用後にゼロフィルされる。
 */

import { describe, expect, spyOn, test } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { VericertsError } from '../../../errors.js';
import { getP256PublicKey, verifyP256 } from '../../../keymanager/signer.js';
import * as deriveModule from '../derive.js';
import { derivePseudonym } from '../derive.js';
import { type PresentPseudonymOptions, presentPseudonym } from '../siop.js';
import type { SiopRequest } from '../types.js';

/** テスト用マスター種。 */
const MASTER_SEED = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
const NOW = 1_700_000_000;

/** JWT の payload / signingInput / signature を取り出す。 */
function decodeJwt(jwt: string): {
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Uint8Array;
} {
  const parts = jwt.split('.');
  const [h, p, s] = parts;
  if (h === undefined || p === undefined || s === undefined) {
    throw new Error('malformed jwt');
  }
  return {
    payload: JSON.parse(new TextDecoder().decode(base64urlnopad.decode(p))),
    signingInput: `${h}.${p}`,
    signature: base64urlnopad.decode(s),
  };
}

describe('presentPseudonym', () => {
  test('ID Token に nonce / aud / sub を設定する', () => {
    const key = derivePseudonym('rp-a.example', MASTER_SEED);
    const request: SiopRequest = { clientId: 'rp-a.example', nonce: 'nonce_a' };
    const result = presentPseudonym(request, 'rp-a.example', MASTER_SEED, { nowSeconds: NOW });
    const { payload } = decodeJwt(result.idToken);
    expect(payload.sub).toBe(key.subject);
    expect(result.subject).toBe(key.subject);
    expect(payload.aud).toBe('rp-a.example');
    expect(payload.nonce).toBe('nonce_a');
    // SIOPv2: self-issued は iss === sub（固定値 self-issued.me では RP が self-issued と判定できない）。
    expect(payload.iss).toBe(key.subject);
    expect(payload.iat).toBe(NOW);
    expect(payload.exp).toBe(NOW + 5 * 60);
  });

  test('署名は派生公開鍵で検証できる（sub_jwk バインド）', () => {
    const key = derivePseudonym('rp-a.example', MASTER_SEED);
    const request: SiopRequest = { clientId: 'rp-a.example', nonce: 'nonce_a' };
    const { signingInput, signature } = decodeJwt(
      presentPseudonym(request, 'rp-a.example', MASTER_SEED, { nowSeconds: NOW }).idToken,
    );
    const digest = sha256(new TextEncoder().encode(signingInput));
    expect(verifyP256(digest, signature, getP256PublicKey(key.privateKey, false))).toBe(true);
  });

  test('同一 RP 再訪問（別 nonce）で同一 sub を提示する（継続性）', () => {
    const first = presentPseudonym(
      { clientId: 'rp-a.example', nonce: 'nonce_a1' },
      'rp-a.example',
      MASTER_SEED,
      { nowSeconds: NOW },
    );
    const second = presentPseudonym(
      { clientId: 'rp-a.example', nonce: 'nonce_a2' },
      'rp-a.example',
      MASTER_SEED,
      { nowSeconds: NOW + 100 },
    );
    expect(second.subject).toBe(first.subject);
    // nonce は各リクエストの値を反映する（リプレイ防止）。
    expect(decodeJwt(first.idToken).payload.nonce).toBe('nonce_a1');
    expect(decodeJwt(second.idToken).payload.nonce).toBe('nonce_a2');
  });

  test('異なる RP には相関不能な別 sub を提示する（相関不能性）', () => {
    const a = presentPseudonym(
      { clientId: 'rp-a.example', nonce: 'nonce_a' },
      'rp-a.example',
      MASTER_SEED,
      { nowSeconds: NOW },
    );
    const b = presentPseudonym(
      { clientId: 'another.example', nonce: 'nonce_b' },
      'another.example',
      MASTER_SEED,
      { nowSeconds: NOW },
    );
    expect(a.subject).not.toBe(b.subject);
  });

  test('sub_jwk に派生公開鍵の EC JWK を含む', () => {
    const result = presentPseudonym(
      { clientId: 'rp-a.example', nonce: 'nonce_a' },
      'rp-a.example',
      MASTER_SEED,
      { nowSeconds: NOW },
    );
    const jwk = decodeJwt(result.idToken).payload.sub_jwk as { kty: string; crv: string };
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
  });

  test.each([
    { clientId: '', nonce: 'n' },
    { clientId: 'rp-a.example', nonce: '' },
  ])('必須フィールド欠落は RP_IDENTIFIER_INVALID (10201)', (request) => {
    try {
      presentPseudonym(request as SiopRequest, 'rp-a.example', MASTER_SEED, { nowSeconds: NOW });
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10201');
    }
  });

  // derivePseudonym が返す派生秘密鍵は attestation.ts / siop.ts が唯一の呼び出し元で
  // あり、署名後に消去する責務を負う。derivePseudonym を spy し、内部で使われた実オブジェクトの
  // privateKey 参照を捕捉して、関数を抜けた後にゼロフィルされているかを検証する。
  test('署名完了後に派生秘密鍵をゼロフィルする', () => {
    const spy = spyOn(deriveModule, 'derivePseudonym');
    const request: SiopRequest = { clientId: 'rp-a.example', nonce: 'nonce_a' };
    presentPseudonym(request, 'rp-a.example', MASTER_SEED, { nowSeconds: NOW });
    const derivedKey = spy.mock.results[0]?.value as { privateKey: Uint8Array } | undefined;
    spy.mockRestore();
    expect(derivedKey).toBeDefined();
    expect(Array.from(derivedKey?.privateKey ?? []).every((b) => b === 0)).toBe(true);
  });

  test('例外発生時（nowSeconds 欠落）でも派生秘密鍵をゼロフィルする', () => {
    const spy = spyOn(deriveModule, 'derivePseudonym');
    const request: SiopRequest = { clientId: 'rp-a.example', nonce: 'nonce_a' };
    // nowSeconds を意図的に欠落させ、鍵派生後・署名前の RP_IDENTIFIER_INVALID (10201) 経路を通す。
    const invalidOpts = {} as unknown as PresentPseudonymOptions;
    expect(() => presentPseudonym(request, 'rp-a.example', MASTER_SEED, invalidOpts)).toThrow(
      VericertsError,
    );
    const derivedKey = spy.mock.results[0]?.value as { privateKey: Uint8Array } | undefined;
    spy.mockRestore();
    expect(derivedKey).toBeDefined();
    expect(Array.from(derivedKey?.privateKey ?? []).every((b) => b === 0)).toBe(true);
  });
});
