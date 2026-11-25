/**
 * W2W Lend（一時共有）テスト。
 *
 * 期限切れは 4034（W2W_LEND_EXPIRED）で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  createLend,
  expireOverdueLends,
  redeemLend,
  revokeLend,
  scheduleLendExpiryChecks,
  verifyLendSignature,
} from '../lend.js';
import { DEFAULT_LEND_EXPIRY_CHECK_INTERVAL_MS } from '../types.js';
import { OTHER_PRIVATE_KEY, testPublicKeyJwk } from './fixtures.js';
import {
  FUTURE,
  LENDER_DID,
  lender,
  lendToken,
  NOW,
  PAST,
  RECIPIENT_DID,
} from './lend-fixtures.js';

describe('createLend', () => {
  it('creates a signed lend token within validity', () => {
    const token = createLend(
      ['urn:uuid:vc-1'],
      FUTURE,
      RECIPIENT_DID,
      lender(),
      {
        allowPresentationTypes: ['AgeOver18'],
      },
      { now: () => NOW, generateId: () => 'lend-1' },
    );
    expect(token.id).toBe('lend-1');
    expect(token.vc_ids).toEqual(['urn:uuid:vc-1']);
    expect(token.valid_until).toBe(FUTURE);
    expect(token.lender_did).toBe(LENDER_DID);
    expect(token.recipient_did).toBe(RECIPIENT_DID);
    expect(token.allow_presentation_types).toEqual(['AgeOver18']);
    expect(token.lender_signature.length).toBeGreaterThan(0);
  });

  it('rejects a past valid_until (4034)', () => {
    expect(() =>
      createLend(['vc-1'], PAST, RECIPIENT_DID, lender(), {}, { now: () => NOW }),
    ).toThrow(VericertsError);
  });
});

describe('verifyLendSignature', () => {
  it('verifies a token signed by the lender', () => {
    const l = lender();
    const token = createLend(['vc-1'], FUTURE, RECIPIENT_DID, l, {}, { now: () => NOW });
    expect(verifyLendSignature(token, l.signer.publicKeyJwk)).toBe(true);
  });

  it('rejects a token verified with a different key', () => {
    const l = lender();
    const token = createLend(['vc-1'], FUTURE, RECIPIENT_DID, l, {}, { now: () => NOW });
    expect(verifyLendSignature(token, testPublicKeyJwk(OTHER_PRIVATE_KEY))).toBe(false);
  });

  it('rejects a tampered token body', () => {
    const l = lender();
    const token = createLend(['vc-1'], FUTURE, RECIPIENT_DID, l, {}, { now: () => NOW });
    const tampered = { ...token, vc_ids: ['vc-evil'] };
    expect(verifyLendSignature(tampered, l.signer.publicKeyJwk)).toBe(false);
  });

  // jwkToUncompressedPublicKey の統合後も、貸主 JWK 自体が不正な場合は
  // `false` ではなく 2001（INVALID_DID）が送出されることを固定する。
  it.each([
    ['crv 不一致', { ...testPublicKeyJwk(), crv: 'secp256k1' }],
    ['x が base64url でない', { ...testPublicKeyJwk(), x: '!!!' }],
  ])('throws 2001 for a malformed lender jwk (%s)', (_label, jwk) => {
    const l = lender();
    const token = createLend(['vc-1'], FUTURE, RECIPIENT_DID, l, {}, { now: () => NOW });
    try {
      verifyLendSignature(token, jwk);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });
});

describe('redeemLend', () => {
  it('returns vc ids for a valid, in-window, signed token', () => {
    const l = lender();
    const token = createLend(['vc-1', 'vc-2'], FUTURE, RECIPIENT_DID, l, {}, { now: () => NOW });
    const ids = redeemLend(token, {
      lenderPublicKeyJwk: l.signer.publicKeyJwk,
      now: () => NOW,
    });
    expect(ids).toEqual(['vc-1', 'vc-2']);
  });

  it('throws 4034 when the token is expired', () => {
    const l = lender();
    const token = createLend(['vc-1'], FUTURE, RECIPIENT_DID, l, {}, { now: () => NOW });
    expect(() =>
      redeemLend(token, {
        lenderPublicKeyJwk: l.signer.publicKeyJwk,
        now: () => Date.parse('2026-07-01T00:00:00Z'),
      }),
    ).toThrow(VericertsError);
    try {
      redeemLend(token, {
        lenderPublicKeyJwk: l.signer.publicKeyJwk,
        now: () => Date.parse('2026-07-01T00:00:00Z'),
      });
    } catch (e) {
      expect((e as VericertsError).code).toBe('4034');
    }
  });

  it('throws 4034 for an invalid signature', () => {
    const l = lender();
    const token = createLend(['vc-1'], FUTURE, RECIPIENT_DID, l, {}, { now: () => NOW });
    expect(() =>
      redeemLend(token, {
        lenderPublicKeyJwk: testPublicKeyJwk(OTHER_PRIVATE_KEY),
        now: () => NOW,
      }),
    ).toThrow(VericertsError);
  });

  it('throws 4034 for a revoked token', () => {
    const l = lender();
    const token = createLend(['vc-1'], FUTURE, RECIPIENT_DID, l, {}, { now: () => NOW });
    expect(() =>
      redeemLend(token, {
        lenderPublicKeyJwk: l.signer.publicKeyJwk,
        now: () => NOW,
        isRevoked: (id) => id === token.id,
      }),
    ).toThrow(VericertsError);
  });
});

describe('redeemLend: isRevoked の戻り値は false のみ未失効（fail-closed）', () => {
  const deps = (isRevoked: unknown) => {
    const l = lender();
    const token = createLend(['vc-1'], FUTURE, RECIPIENT_DID, l, {}, { now: () => NOW });
    return {
      run: () =>
        redeemLend(token, {
          lenderPublicKeyJwk: l.signer.publicKeyJwk,
          now: () => NOW,
          isRevoked: isRevoked as (id: string) => boolean,
        }),
    };
  };

  it.each([
    ['async 関数（失効済みを Promise<true> で返す）', async () => true],
    ['async 関数（Promise<false> も待てないため拒否）', async () => false],
    ['reject する Promise', () => Promise.reject(new Error('ledger down'))],
    ['undefined を返す', () => undefined],
    ['truthy な非 boolean', () => 1],
  ])('%s は 4034 で拒否する', async (_name, isRevoked) => {
    let thrown: unknown;
    try {
      deps(isRevoked).run();
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VericertsError);
    expect((thrown as VericertsError).code).toBe(ErrorCodes.W2W_LEND_EXPIRED);
    // reject する Promise が未処理 rejection にならない。
    await new Promise((r) => setTimeout(r, 0));
  });

  it('同期で false を返せば引き換えられる', () => {
    expect(deps(() => false).run()).toEqual(['vc-1']);
  });
});

describe('revokeLend', () => {
  it('marks the token revoked via the injected sink', async () => {
    const revoked: string[] = [];
    await revokeLend('lend-1', { markRevoked: (id) => void revoked.push(id) });
    expect(revoked).toEqual(['lend-1']);
  });

  it('redeem fails after revoke is reflected', async () => {
    const l = lender();
    const token = createLend(['vc-1'], FUTURE, RECIPIENT_DID, l, {}, { now: () => NOW });
    const store = new Set<string>();
    await revokeLend(token.id, { markRevoked: (id) => void store.add(id) });
    expect(() =>
      redeemLend(token, {
        lenderPublicKeyJwk: l.signer.publicKeyJwk,
        now: () => NOW,
        isRevoked: (id) => store.has(id),
      }),
    ).toThrow(VericertsError);
  });
});

describe('expireOverdueLends', () => {
  it('revokes only tokens whose valid_until has passed', async () => {
    const store = new Set<string>();
    const expired = await expireOverdueLends(
      [lendToken('overdue', PAST), lendToken('live', FUTURE)],
      { markRevoked: (id) => void store.add(id), now: () => NOW },
    );
    expect(expired).toEqual(['overdue']);
    expect([...store]).toEqual(['overdue']);
  });

  it('leaves in-window tokens untouched', async () => {
    const store = new Set<string>();
    const expired = await expireOverdueLends([lendToken('live', FUTURE)], {
      markRevoked: (id) => void store.add(id),
      now: () => NOW,
    });
    expect(expired).toEqual([]);
    expect(store.size).toBe(0);
  });
});

describe('scheduleLendExpiryChecks', () => {
  /** `schedule` DI のスタブ。tick を手動発火し、停止呼び出しを記録する。 */
  function scheduleStub() {
    const calls: { intervalMs: number }[] = [];
    let task: (() => void) | undefined;
    let stopped = false;
    return {
      calls,
      stopped: () => stopped,
      tick: () => task?.(),
      schedule: (t: () => void, intervalMs: number) => {
        task = t;
        calls.push({ intervalMs });
        return () => {
          stopped = true;
        };
      },
    };
  }

  it('revokes overdue tokens when the scheduled tick fires', async () => {
    const stub = scheduleStub();
    const store = new Set<string>();
    scheduleLendExpiryChecks(() => [lendToken('overdue', PAST), lendToken('live', FUTURE)], {
      markRevoked: (id) => void store.add(id),
      now: () => NOW,
      schedule: stub.schedule,
    });
    stub.tick();
    await Promise.resolve();
    await Promise.resolve();
    expect([...store]).toEqual(['overdue']);
  });

  it('uses the default interval when intervalMs is omitted', () => {
    const stub = scheduleStub();
    scheduleLendExpiryChecks(() => [], {
      markRevoked: () => undefined,
      schedule: stub.schedule,
    });
    expect(stub.calls).toEqual([{ intervalMs: DEFAULT_LEND_EXPIRY_CHECK_INTERVAL_MS }]);
  });

  it('stops the injected scheduler when the returned stop function is called', () => {
    const stub = scheduleStub();
    const stop = scheduleLendExpiryChecks(() => [], {
      markRevoked: () => undefined,
      schedule: stub.schedule,
    });
    expect(stub.stopped()).toBe(false);
    stop();
    expect(stub.stopped()).toBe(true);
  });

  it('reports getTokens rejection through onError', async () => {
    const stub = scheduleStub();
    const errors: unknown[] = [];
    scheduleLendExpiryChecks(() => Promise.reject(new Error('token store down')), {
      markRevoked: () => undefined,
      schedule: stub.schedule,
      onError: (error) => void errors.push(error),
    });
    stub.tick();
    await Promise.resolve();
    await Promise.resolve();
    expect(errors).toHaveLength(1);
    expect((errors[0] as Error).message).toBe('token store down');
  });
});
