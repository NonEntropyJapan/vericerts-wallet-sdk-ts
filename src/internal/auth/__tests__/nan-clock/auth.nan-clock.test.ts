/**
 * 認証系（DPoP / SIWE / replay window / NonceStore / 一回限り VC / JAR 証明書）の時刻比較が
 * 非有限（NaN / ±Infinity）の現在時刻で fail-open しないことの回帰テスト。
 *
 * `now - iat > window` / `expiresAt > now` / `expirationTime <= now` は `now` が NaN だと常に `false` になり、
 * 期限切れ proof・SIWE・既知 nonce（リプレイ）をそのまま通す。修正前はいずれも例外を出さず落ちる。
 * fail-closed に倒す。
 */

import { describe, expect, it } from 'bun:test';
import { Wallet } from 'ethers';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { ParsedRpAccessCertificate } from '../../../trust/rp-access/cert.js';
import { createDpopProof } from '../../dpop/dpop.js';
import { verifyDpopProof } from '../../dpop/dpop-verify.js';
import { certValidityStatus } from '../../jar/jar-trust-cert-status.js';
import { consumeOneTimeCredential } from '../../nonce/one-time-credential.js';
import { assertWithinReplayWindow } from '../../nonce/replay-window.js';
import { createNonceStore } from '../../nonce/store.js';
import type { NonceContext } from '../../nonce/types.js';
import { generateSiweMessage, parseSiweMessage, validateSiweMessage } from '../../siwe/siwe.js';

const NON_FINITE = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY] as const;
const CLOCK_INVALID = new VericertsError(ErrorCodes.CLOCK_SKEW_OPTION_INVALID);
const NOW = 1_767_225_600;

describe('verifyDpopProof: nowSeconds が非有限でも期限切れ proof を受理しない', () => {
  const signer = createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256');
  const HTM = 'POST';
  const HTU = 'https://api.example.com/mcp';
  // 1 日前の proof（既定 maxAge 30s を大きく超過）。
  const stale = createDpopProof(
    { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW - 86_400 },
    signer,
  );

  it('有限時刻では期限切れ（4082）', () => {
    expect(() => verifyDpopProof(stale, { htm: HTM, htu: HTU, nowSeconds: NOW })).toThrow(
      new VericertsError(ErrorCodes.DPOP_PROOF_EXPIRED),
    );
  });

  for (const bad of NON_FINITE) {
    it(`nowSeconds = ${bad}: 4015（修正前は NaN で受理された）`, () => {
      expect(() => verifyDpopProof(stale, { htm: HTM, htu: HTU, nowSeconds: bad })).toThrow(
        CLOCK_INVALID,
      );
    });
  }
});

describe('validateSiweMessage: Invalid Date の now で期限切れ SIWE を受理しない', () => {
  const wallet = new Wallet('0x0123456789012345678901234567890123456789012345678901234567890123');
  const expired = parseSiweMessage(
    generateSiweMessage({
      domain: 'example.com',
      address: wallet.address,
      uri: 'https://example.com/login',
      nonce: 'abcd1234',
      chainId: 1,
      issuedAt: new Date('2026-07-02T00:00:00.000Z'),
      expirationTime: new Date('2026-07-02T01:00:00.000Z'),
    }),
  );
  const notYet = parseSiweMessage(
    generateSiweMessage({
      domain: 'example.com',
      address: wallet.address,
      uri: 'https://example.com/login',
      nonce: 'abcd1234',
      chainId: 1,
      issuedAt: new Date('2026-07-02T00:00:00.000Z'),
      notBefore: new Date('2099-01-01T00:00:00.000Z'),
    }),
  );

  it('有限時刻では期限切れ / 未発効を拒否する（8041）', () => {
    const later = new Date('2026-07-02T03:00:00.000Z');
    expect(() => validateSiweMessage(expired, 'example.com', later)).toThrow(
      new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID),
    );
    expect(() => validateSiweMessage(notYet, 'example.com', later)).toThrow(
      new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID),
    );
  });

  it('now が Invalid Date（NaN）でも期限切れ・未発効を拒否する（修正前は受理された）', () => {
    const invalid = new Date(Number.NaN);
    expect(() => validateSiweMessage(expired, 'example.com', invalid)).toThrow(
      new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID),
    );
    expect(() => validateSiweMessage(notYet, 'example.com', invalid)).toThrow(
      new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID),
    );
  });
});

describe('assertWithinReplayWindow: nowSeconds が非有限なら窓検査をスキップしない', () => {
  it('有限時刻では窓外の iat を拒否する（4014）', () => {
    expect(() => assertWithinReplayWindow(NOW - 3_600, 'oid4vp', { nowSeconds: NOW })).toThrow(
      new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
    );
  });

  for (const bad of NON_FINITE) {
    it(`nowSeconds = ${bad}: 古い iat（リプレイ）を通さない（4015）`, () => {
      expect(() => assertWithinReplayWindow(NOW - 3_600, 'oid4vp', { nowSeconds: bad })).toThrow(
        CLOCK_INVALID,
      );
    });
  }
});

describe('NonceStore: 注入クロックが非有限なら既知 nonce を「初見」として再受理しない', () => {
  const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
  const CTX: NonceContext = { flow: 'oid4vp', clientId: 'https://verifier.example' };

  for (const bad of NON_FINITE) {
    it(`now() = ${bad}: 消費済み nonce の再消費を通さない`, async () => {
      let current = 1_000_000;
      const store = createNonceStore({ backend: 'memory', now: () => current });
      await store.checkAndUse(NONCE, CTX);
      await expect(store.checkAndUse(NONCE, CTX)).rejects.toMatchObject({
        code: ErrorCodes.REPLAY_DETECTED,
      });
      // 時計が壊れた後の再消費。修正前は `existing.expiresAt > NaN` が false になり再受理された。
      current = bad;
      await expect(store.checkAndUse(NONCE, CTX)).rejects.toThrow(CLOCK_INVALID);
    });
  }
});

describe('consumeOneTimeCredential: 非有限の nowMs / expSeconds で失効 VC を消費記録に乗せない', () => {
  const store = createNonceStore({ backend: 'memory' });
  const base = { jti: 'urn:uuid:jti-otc', issuer: 'did:web:issuer.example' };

  it('有限時刻では失効済み VC は 4011', async () => {
    await expect(
      consumeOneTimeCredential(store, { ...base, expSeconds: 1_000, nowMs: 2_000_000 }),
    ).rejects.toMatchObject({ code: ErrorCodes.NONCE_EXPIRED });
  });

  for (const bad of NON_FINITE) {
    it(`nowMs = ${bad}: 4011 で拒否する（修正前は NaN で消費記録へ乗った）`, async () => {
      await expect(
        consumeOneTimeCredential(store, { ...base, expSeconds: 1_000, nowMs: bad }),
      ).rejects.toMatchObject({ code: ErrorCodes.NONCE_EXPIRED });
    });
  }
});

describe('certValidityStatus: 非有限の now で期限切れ証明書を通さない', () => {
  const cert = {
    serialHex: '01',
    base: { notBefore: 100, notAfter: 200 },
  } as unknown as ParsedRpAccessCertificate;

  it('有限時刻: 期間内は undefined / 期間外は not-found', () => {
    expect(certValidityStatus(cert, undefined, 150)).toBeUndefined();
    expect(certValidityStatus(cert, undefined, 300)).toBe('not-found');
  });

  for (const bad of NON_FINITE) {
    it(`now = ${bad}: not-found（修正前は NaN で undefined = 有効扱い）`, () => {
      expect(certValidityStatus(cert, undefined, bad)).toBe('not-found');
    });
  }
});
