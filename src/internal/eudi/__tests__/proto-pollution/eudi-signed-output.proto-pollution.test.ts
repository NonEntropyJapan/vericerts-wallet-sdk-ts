/**
 * EUDI 系の署名済み出力への汚染混入テスト。
 *
 * Pseudonym Attestation / SIOPv2 ID Token / WUA-PoP はいずれも組み立てた claims をそのまま
 * 署名する。任意プロパティをプロトタイプ鎖で読むと、それらを**省略した**正当な発行でも
 * 汚染値が **署名済みトークン** に載る:
 *
 * - `lifetimeSeconds`: `exp` が攻撃者の選んだ値になり、**無期限に近い署名済みトークン**になる。
 * - WUA-PoP の `jti`: 継承値だと生成のたびに同じ値へ固定され、jti によるリプレイ検知の前提
 *   （一意性）が失われる。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { issuePseudonymAttestation } from '../../pseudonym/attestation.js';
import { presentPseudonym } from '../../pseudonym/siop.js';
import type { SiopRequest } from '../../pseudonym/types.js';
import { makeWuaJwt, wscdSigner } from '../../wua/__tests__/wua-fixtures.js';
import { buildWuaProofOfPossession } from '../../wua/proof.js';
import { parseWalletUnitAttestation } from '../../wua/wua.js';

const MASTER_SEED = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
const ISSUER = 'urn:wallet-instance:test';
const NOW = 1_700_000_000;
const PROVIDER_KEY = new Uint8Array(32).fill(3);
const WUA_NOW = 1_712_400_000;

/** 100 年（無期限に近い有効期間の汚染値）。 */
const HUNDRED_YEARS = 100 * 365 * 24 * 3600;

function decodePayload(jwt: string): Record<string, unknown> {
  const [, payloadSeg] = jwt.split('.');
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(payloadSeg ?? ''))) as Record<
    string,
    unknown
  >;
}

describe('Pseudonym Attestation の Object.prototype 汚染耐性', () => {
  it('継承した lifetimeSeconds は署名済み Attestation の exp を伸ばさない', () => {
    const { jwt } = withPollutedPrototype({ lifetimeSeconds: HUNDRED_YEARS }, () =>
      issuePseudonymAttestation('https://rp.example', MASTER_SEED, {
        issuer: ISSUER,
        nowSeconds: NOW,
      }),
    );
    const payload = decodePayload(jwt);
    // 既定は 24h。
    expect((payload.exp as number) - (payload.iat as number)).toBe(24 * 3600);
  });

  it('明示的に渡した lifetimeSeconds は従来どおり反映される（正常系）', () => {
    const { jwt } = issuePseudonymAttestation('https://rp.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
      lifetimeSeconds: 600,
    });
    const payload = decodePayload(jwt);
    expect((payload.exp as number) - (payload.iat as number)).toBe(600);
  });
});

describe('SIOPv2 Pseudonym ID Token の Object.prototype 汚染耐性', () => {
  const request: SiopRequest = { clientId: 'rp-a.example', nonce: 'nonce_a' };

  it('継承した lifetimeSeconds は署名済み ID Token の exp を伸ばさない', () => {
    const { idToken } = withPollutedPrototype({ lifetimeSeconds: HUNDRED_YEARS }, () =>
      presentPseudonym(request, 'rp-a.example', MASTER_SEED, { nowSeconds: NOW }),
    );
    const payload = decodePayload(idToken);
    // 既定は 5 分。
    expect((payload.exp as number) - (payload.iat as number)).toBe(300);
  });

  it('明示的に渡した lifetimeSeconds は従来どおり反映される（正常系）', () => {
    const { idToken } = presentPseudonym(request, 'rp-a.example', MASTER_SEED, {
      nowSeconds: NOW,
      lifetimeSeconds: 60,
    });
    const payload = decodePayload(idToken);
    expect((payload.exp as number) - (payload.iat as number)).toBe(60);
  });
});

describe('WUA-PoP の Object.prototype 汚染耐性', () => {
  it('継承した jti は採用せず、生成ごとに一意な jti を使う', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const [first, second] = withPollutedPrototype({ jti: 'attacker-fixed-jti' }, () => [
      buildWuaProofOfPossession(
        wua,
        { aud: 'https://as.example', nonce: 'c_nonce_123' },
        wscdSigner(),
        WUA_NOW,
      ),
      buildWuaProofOfPossession(
        wua,
        { aud: 'https://as.example', nonce: 'c_nonce_123' },
        wscdSigner(),
        WUA_NOW,
      ),
    ]);
    const a = decodePayload(first ?? '').jti;
    const b = decodePayload(second ?? '').jti;
    expect(a).not.toBe('attacker-fixed-jti');
    expect(a).not.toBe(b);
  });

  it('継承した lifetimeSeconds は署名済み PoP の exp を伸ばさない', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const pop = withPollutedPrototype({ lifetimeSeconds: HUNDRED_YEARS }, () =>
      buildWuaProofOfPossession(
        wua,
        { aud: 'https://as.example', nonce: 'c_nonce_123' },
        wscdSigner(),
        WUA_NOW,
      ),
    );
    const claims = decodePayload(pop);
    // 既定は 300 秒。
    expect((claims.exp as number) - (claims.iat as number)).toBe(300);
  });

  it('明示的に渡した jti / lifetimeSeconds は従来どおり反映される（正常系）', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const pop = buildWuaProofOfPossession(
      wua,
      {
        aud: 'https://as.example',
        nonce: 'c_nonce_123',
        jti: '9f3c1f0e-6a52-4f8e-9b2d-7c1a5d3e4b10',
        lifetimeSeconds: 60,
      },
      wscdSigner(),
      WUA_NOW,
    );
    const claims = decodePayload(pop);
    expect(claims.jti).toBe('9f3c1f0e-6a52-4f8e-9b2d-7c1a5d3e4b10');
    expect((claims.exp as number) - (claims.iat as number)).toBe(60);
  });
});
