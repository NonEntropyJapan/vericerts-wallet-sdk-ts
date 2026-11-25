/**
 * Lend トークンの `Object.prototype` 汚染耐性テスト。
 *
 * `createLend` が組み立てる `unsigned` は Lender の ES256 署名対象になる。任意の依存注入・
 * オプションをプロトタイプ鎖で読むと、それらを**省略した**正当な貸出でも汚染値が
 * **署名済み Lend トークン** に載る:
 *
 * - `allowPresentationTypes`: 貸出時に許可していない提示タイプが署名済みトークンに載る。
 * - `generateId`: トークン ID が攻撃者の関数由来になり、一意性・追跡可能性が壊れる。
 * - `now`: 期限切れ判定（4034）が攻撃者の選んだ時刻で行われる。
 *
 * `redeemLend` 側も同様で、継承した `now` は期限切れトークンを引き換え可能にし、継承した
 * `isRevoked` は失効判定を攻撃者の関数へ委譲する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createLend, redeemLend } from '../../lend.js';
import { testSigner } from '../fixtures.js';

const VC_IDS = ['vc-1', 'vc-2'];
const RECIPIENT = 'did:example:borrower';
const LENDER_DID = 'did:example:lender';

/** 実時刻より十分未来の期限。 */
const FUTURE = new Date(Date.now() + 30 * 86_400_000).toISOString();
/** 実時刻より過去の期限。 */
const PAST = new Date(Date.now() - 30 * 86_400_000).toISOString();

function lender() {
  return { did: LENDER_DID, signer: testSigner() };
}

describe('createLend の Object.prototype 汚染耐性', () => {
  it('継承した allowPresentationTypes は署名済みトークンに載らない', () => {
    const token = withPollutedPrototype({ allowPresentationTypes: ['AttackerType'] }, () =>
      createLend(VC_IDS, FUTURE, RECIPIENT, lender()),
    );
    expect(token.allow_presentation_types).toBeUndefined();
  });

  it('継承した generateId は採用せず、トークンごとに一意な ID を生成する', () => {
    const [first, second] = withPollutedPrototype({ generateId: () => 'attacker-fixed-id' }, () => [
      createLend(VC_IDS, FUTURE, RECIPIENT, lender()),
      createLend(VC_IDS, FUTURE, RECIPIENT, lender()),
    ]);
    expect(first?.id).not.toBe('attacker-fixed-id');
    expect(first?.id).not.toBe(second?.id);
  });

  it('継承した now では期限切れの貸出を成立させない', () => {
    // 汚染値（十分過去の時刻）を拾えば PAST の期限がまだ未来に見えて貸出が成立してしまう。
    expect(() =>
      withPollutedPrototype({ now: () => Date.parse(PAST) - 86_400_000 }, () =>
        createLend(VC_IDS, PAST, RECIPIENT, lender()),
      ),
    ).toThrow(new VericertsError(ErrorCodes.W2W_LEND_EXPIRED));
  });

  it('明示的に渡したオプション・依存注入は従来どおり効く（正常系）', () => {
    const token = createLend(
      VC_IDS,
      FUTURE,
      RECIPIENT,
      lender(),
      { allowPresentationTypes: ['IdentityCredential'] },
      { generateId: () => 'lend-1' },
    );
    expect(token.id).toBe('lend-1');
    expect(token.allow_presentation_types).toEqual(['IdentityCredential']);
    expect(token.lender_did).toBe(LENDER_DID);
    expect(token.recipient_did).toBe(RECIPIENT);
  });
});

describe('redeemLend の Object.prototype 汚染耐性', () => {
  it('継承した now では期限切れトークンを引き換えられない', () => {
    const signer = testSigner();
    // 発行後に `valid_until` を書き換えると署名が壊れ、「期限切れ」と「署名不正」が同じ 4034 に
    // なって区別できない（＝トートロジー）。そこで**過去時点で正当に発行**し、実時刻では
    // 期限切れになっているトークンを作る。
    const issuedAt = Date.now() - 30 * 86_400_000;
    const validUntil = new Date(issuedAt + 86_400_000).toISOString();
    const token = createLend(
      VC_IDS,
      validUntil,
      RECIPIENT,
      { did: LENDER_DID, signer },
      {},
      {
        now: () => issuedAt,
      },
    );

    // 署名は正当であることを先に示す（発行時点の時刻を明示すれば引き換えられる）。
    expect(
      redeemLend(token, { lenderPublicKeyJwk: signer.publicKeyJwk, now: () => issuedAt }),
    ).toEqual(VC_IDS);

    // 汚染した `now` を拾えば「まだ期限内」に見えて引き換えが成立してしまう。
    expect(() =>
      withPollutedPrototype({ now: () => issuedAt }, () =>
        redeemLend(token, { lenderPublicKeyJwk: signer.publicKeyJwk }),
      ),
    ).toThrow(new VericertsError(ErrorCodes.W2W_LEND_EXPIRED));
  });

  it('継承した isRevoked は失効判定に使わない', () => {
    const signer = testSigner();
    const token = createLend(VC_IDS, FUTURE, RECIPIENT, { did: LENDER_DID, signer });
    let revokedCalls = 0;
    const vcIds = withPollutedPrototype(
      {
        isRevoked: (): boolean => {
          revokedCalls += 1;
          return true;
        },
      },
      () => redeemLend(token, { lenderPublicKeyJwk: signer.publicKeyJwk }),
    );
    expect(revokedCalls).toBe(0);
    expect(vcIds).toEqual(VC_IDS);
  });

  it('明示的に渡した isRevoked は従来どおり効く（正常系）', () => {
    const signer = testSigner();
    const token = createLend(VC_IDS, FUTURE, RECIPIENT, { did: LENDER_DID, signer });
    expect(() =>
      redeemLend(token, { lenderPublicKeyJwk: signer.publicKeyJwk, isRevoked: () => true }),
    ).toThrow(new VericertsError(ErrorCodes.W2W_LEND_EXPIRED));
  });
});
