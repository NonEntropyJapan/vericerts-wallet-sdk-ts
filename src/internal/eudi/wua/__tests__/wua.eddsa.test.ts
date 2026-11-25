/**
 * WUA の EdDSA（Ed25519）経路のテスト（実鍵・モック禁止）。
 *
 * ES256 経路は `wua.test.ts` / `proof.test.ts` が担当し、本ファイルは
 * 受理するようになった EdDSA / OKP 固有の差異のみを検証する。
 *
 * 検証内容:
 * - Wallet Provider が EdDSA で署名した WUA を解析・署名検証できる。
 * - 回帰: Ed25519 の `cnf.jwk` で WSCD バインド検証が成功する。
 *   かつて比較フィールドが `['kty','crv','x','y']` 固定だったため、OKP は `y` を持たず
 *   （RFC 8037）同一鍵同士でも常に 10102 で失敗していた。
 * - 別の Ed25519 鍵 / EC 鍵との取り違えは 10102 で拒否する（fail-closed の維持）。
 * - EdDSA の WUA-PoP を生成・検証できる（cnf バインド込み）。
 */

import { describe, expect, test } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { verifyWithJwk } from '../../../credential/vc/jws.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { VericertsError } from '../../../errors.js';
import { buildWuaProofOfPossession } from '../proof.js';
import {
  parseWalletUnitAttestation,
  verifyWalletUnitAttestation,
  verifyWscdBinding,
} from '../wua.js';
import {
  ED_OTHER_PRIVATE_KEY,
  ED_WSCD_PRIVATE_KEY,
  makeWuaJwt,
  toEd25519Jwk,
  toP256Jwk,
  WSCD_PRIVATE_KEY,
} from './wua-fixtures.js';

/** Wallet Provider の Ed25519 署名鍵。 */
const PROVIDER_KEY = new Uint8Array(32).fill(17);
const PROVIDER_JWK = toEd25519Jwk(PROVIDER_KEY);
const ED_WSCD_JWK = toEd25519Jwk(ED_WSCD_PRIVATE_KEY);
const NOW = 1_712_400_000; // iat < NOW < exp

/** Ed25519 で署名し、Ed25519 の cnf.jwk にバインドした WUA を作る。 */
function makeEdWua(): string {
  return makeWuaJwt(PROVIDER_KEY, {}, { alg: 'EdDSA', cnfJwk: ED_WSCD_JWK });
}

describe('WUA（EdDSA / Ed25519）', () => {
  test('EdDSA で署名した WUA を解析し Wallet Provider 署名を検証できる', () => {
    const wua = parseWalletUnitAttestation(makeEdWua());
    expect(wua.cnf.jwk).toEqual(ED_WSCD_JWK);
    expect(() => verifyWalletUnitAttestation(wua, PROVIDER_JWK, NOW)).not.toThrow();
  });

  // 回帰: y を無条件に要求していたため、同一 Ed25519 鍵同士でも 10102 で失敗していた。
  test('Ed25519 の cnf.jwk で WSCD バインド検証が成功する', () => {
    const wua = parseWalletUnitAttestation(makeEdWua());
    expect(() => verifyWscdBinding(wua, ED_WSCD_JWK)).not.toThrow();
  });

  test('別の Ed25519 鍵との WSCD バインドは 10102', () => {
    const wua = parseWalletUnitAttestation(makeEdWua());
    try {
      verifyWscdBinding(wua, toEd25519Jwk(ED_OTHER_PRIVATE_KEY));
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10102');
    }
  });

  test('Ed25519 の cnf.jwk に EC 鍵を突き合わせると 10102（kty 取り違えの拒否）', () => {
    const wua = parseWalletUnitAttestation(makeEdWua());
    try {
      verifyWscdBinding(wua, toP256Jwk(WSCD_PRIVATE_KEY));
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10102');
    }
  });

  test('EC の cnf.jwk に Ed25519 鍵を突き合わせると 10102（逆方向も fail-closed）', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(new Uint8Array(32).fill(3)));
    try {
      verifyWscdBinding(wua, ED_WSCD_JWK);
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10102');
    }
  });

  test('Ed25519 の WSCD 鍵で WUA-PoP を生成し cnf.jwk で検証できる', () => {
    const wua = parseWalletUnitAttestation(makeEdWua());
    const signer = createPrivateKeySigner(ED_WSCD_PRIVATE_KEY, 'EdDSA');
    const pop = buildWuaProofOfPossession(
      wua,
      { aud: 'https://as.example', nonce: 'n-ed', jti: 'e6b3d9a1-2f47-4a85-b1c6-0d8e4a7f5b23' },
      signer,
      NOW,
    );
    const [headerSeg, payloadSeg, sigSeg] = pop.split('.');
    const signingInput = new TextEncoder().encode(`${headerSeg}.${payloadSeg}`);
    const signature = base64urlnopad.decode(sigSeg ?? '');
    expect(verifyWithJwk('EdDSA', { signingInput, signature }, wua.cnf.jwk)).toBe(true);
  });

  test('Ed25519 の cnf.jwk に別の Ed25519 鍵で PoP を作ると 10104', () => {
    const wua = parseWalletUnitAttestation(makeEdWua());
    const wrongSigner = createPrivateKeySigner(ED_OTHER_PRIVATE_KEY, 'EdDSA');
    try {
      buildWuaProofOfPossession(wua, { aud: 'https://as.example', nonce: 'n' }, wrongSigner, NOW);
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10104');
    }
  });
});
