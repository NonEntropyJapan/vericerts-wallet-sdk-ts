/**
 * `ALG_SPECS[alg].verify` の high-S 既定の固定。
 *
 * - `ES256` は既定で high-S も受理する（RFC 7518 §3.4 は low-S を要求しない）。low-S も受理する。
 * - `ES256` でも `allowHighS: false` を明示すれば low-S 強制になる（DPoP / did:jwt が使う）。
 * - `ES256K` は `allowHighS` に関わらず常に low-S のみ。
 */

import { describe, expect, it } from 'bun:test';
import { ALG_SPECS } from '../../../../identity/jwt/jwk-key.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../../keymanager/signer.js';
import { type EcdsaAlg, flipS, HIGH_S_FIXTURES } from './high-s.fixtures.js';

const SIGNING_INPUT = new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZSJ9');

const PUBLIC_KEYS: Readonly<Record<EcdsaAlg, Uint8Array>> = {
  ES256: getP256PublicKey(new Uint8Array(32).fill(51), false),
  ES256K: getSecp256k1PublicKey(new Uint8Array(32).fill(53), false),
};

function signatures(alg: EcdsaAlg): { low: Uint8Array; high: Uint8Array } {
  const low = HIGH_S_FIXTURES[alg].signer.sign(SIGNING_INPUT);
  return { low, high: flipS(alg, low) };
}

describe('ALG_SPECS.ES256.verify', () => {
  const { low, high } = signatures('ES256');
  const verify = ALG_SPECS.ES256?.verify;
  const publicKey = PUBLIC_KEYS.ES256;

  it('既定で low-S を受理する', () => {
    expect(verify?.(SIGNING_INPUT, low, publicKey)).toBe(true);
  });

  it('既定で high-S も受理する', () => {
    expect(verify?.(SIGNING_INPUT, high, publicKey)).toBe(true);
  });

  it('allowHighS: false を明示すると high-S を拒否し、low-S は受理する', () => {
    expect(verify?.(SIGNING_INPUT, high, publicKey, false)).toBe(false);
    expect(verify?.(SIGNING_INPUT, low, publicKey, false)).toBe(true);
  });

  it('high-S でも別メッセージの署名は拒否する（s の範囲だけを緩める）', () => {
    const other = new TextEncoder().encode('other');
    expect(verify?.(other, high, publicKey)).toBe(false);
  });
});

describe('ALG_SPECS.ES256K.verify', () => {
  const { low, high } = signatures('ES256K');
  const verify = ALG_SPECS.ES256K?.verify;
  const publicKey = PUBLIC_KEYS.ES256K;

  it('low-S を受理する', () => {
    expect(verify?.(SIGNING_INPUT, low, publicKey)).toBe(true);
  });

  it('high-S は既定でも allowHighS: true でも拒否する', () => {
    expect(verify?.(SIGNING_INPUT, high, publicKey)).toBe(false);
    expect(verify?.(SIGNING_INPUT, high, publicKey, true)).toBe(false);
  });
});
