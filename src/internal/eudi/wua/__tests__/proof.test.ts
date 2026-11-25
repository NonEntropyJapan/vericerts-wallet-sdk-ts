/**
 * WUA-PoP 生成・OAuth2 client_assertion 組み立てのテスト。
 *
 * - OAuth2 Attestation-Based Client Authentication 添付のテスト
 * - WUA-PoP JWT 構造 / cnf バインド署名鍵の検証
 */

import { describe, expect, test } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { verifyWithJwk } from '../../../credential/vc/jws.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { VericertsError } from '../../../errors.js';
import { buildClientAttestation, buildWuaProofOfPossession } from '../proof.js';
import { WUA_CLIENT_ASSERTION_TYPE } from '../types.js';
import { parseWalletUnitAttestation } from '../wua.js';
import { makeWuaJwt, OTHER_PRIVATE_KEY, wscdSigner } from './wua-fixtures.js';

const PROVIDER_KEY = new Uint8Array(32).fill(3);
const NOW = 1_712_400_000;

function decodePayload(jwt: string): Record<string, unknown> {
  const [, payloadSeg] = jwt.split('.');
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(payloadSeg ?? '')));
}

describe('buildWuaProofOfPossession', () => {
  test('WUA-PoP の必須クレームを含む', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const pop = buildWuaProofOfPossession(
      wua,
      {
        aud: 'https://as.example',
        nonce: 'c_nonce_123',
        jti: '9f3c1f0e-6a52-4f8e-9b2d-7c1a5d3e4b10',
      },
      wscdSigner(),
      NOW,
    );
    const claims = decodePayload(pop);
    expect(claims.iss).toBe(decodePayload(wua.jwt).sub);
    expect(claims.aud).toBe('https://as.example');
    expect(claims.nonce).toBe('c_nonce_123');
    expect(claims.jti).toBe('9f3c1f0e-6a52-4f8e-9b2d-7c1a5d3e4b10');
    expect(claims.iat).toBe(NOW);
    expect(claims.exp).toBe(NOW + 300);
  });

  test('WUA-PoP は cnf.jwk に対応する WSCD 鍵で署名され検証できる', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const pop = buildWuaProofOfPossession(
      wua,
      { aud: 'https://as.example', nonce: 'n', jti: 'c4a1e7b2-5d68-4f39-8a10-6e9b2c7d3f58' },
      wscdSigner(),
      NOW,
    );
    const [headerSeg, payloadSeg, sigSeg] = pop.split('.');
    const signingInput = new TextEncoder().encode(`${headerSeg}.${payloadSeg}`);
    const signature = base64urlnopad.decode(sigSeg ?? '');
    expect(verifyWithJwk('ES256', { signingInput, signature }, wua.cnf.jwk)).toBe(true);
  });

  test('署名鍵が cnf.jwk と不一致なら 10104', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const wrongSigner = createPrivateKeySigner(OTHER_PRIVATE_KEY, 'ES256');
    try {
      buildWuaProofOfPossession(wua, { aud: 'https://as.example', nonce: 'n' }, wrongSigner, NOW);
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10104');
    }
  });

  test('walletInstanceId フィールド無しでも wua.jwt の sub から iss を組み立てる（回帰）', () => {
    // WalletUnitAttestation は walletInstanceId を持たない。
    // 修正前は `wua.walletInstanceId` を直接読んでいたため、このフィールドが無いと必ず 10104 だった。
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    expect(Object.hasOwn(wua as unknown as Record<string, unknown>, 'walletInstanceId')).toBe(
      false,
    );
    const pop = buildWuaProofOfPossession(
      wua,
      { aud: 'https://as.example', nonce: 'n', jti: 'c4a1e7b2-5d68-4f39-8a10-6e9b2c7d3f58' },
      wscdSigner(),
      NOW,
    );
    expect(decodePayload(pop).iss).toBe(decodePayload(wua.jwt).sub);
  });

  test('lifetimeSeconds を尊重する', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const pop = buildWuaProofOfPossession(
      wua,
      { aud: 'a', nonce: 'n', lifetimeSeconds: 60, jti: 'c4a1e7b2-5d68-4f39-8a10-6e9b2c7d3f58' },
      wscdSigner(),
      NOW,
    );
    expect(decodePayload(pop).exp).toBe(NOW + 60);
  });
});

describe('buildClientAttestation', () => {
  test('client_assertion は <WUA>~<WUA-PoP> で type は jwt-client-attestation', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const pop = buildWuaProofOfPossession(
      wua,
      { aud: 'a', nonce: 'n', jti: 'c4a1e7b2-5d68-4f39-8a10-6e9b2c7d3f58' },
      wscdSigner(),
      NOW,
    );
    const attestation = buildClientAttestation(wua, pop);
    expect(attestation.clientAssertion).toBe(`${wua.jwt}~${pop}`);
    expect(attestation.clientAssertionType).toBe(WUA_CLIENT_ASSERTION_TYPE);
    expect(WUA_CLIENT_ASSERTION_TYPE).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation',
    );
  });
});
