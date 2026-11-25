/**
 * DPoP proof 検証の**照合値**に対する `Object.prototype` 汚染耐性テスト。
 *
 * `options.htm` / `htu` / `nonce`（HTTP 束縛の期待値）と `accessToken` / `expectedJkt`
 * （アクセストークン束縛の期待値）をプロトタイプ鎖で読むと、これらを**省略した**呼び出しでも
 * 汚染値が「期待値」として使われる。
 *
 * - `htm` / `htu`: 攻撃者が自分で選んだ束縛の proof を用意すれば RFC 9449 §4.3 step 8-9 の
 *   照合を通せる（別エンドポイント向け proof の使い回しが成立する）。
 * - `nonce`: `use_dpop_nonce` の運用が攻撃者の制御下に入る。
 * - `accessToken`: `assertAccessTokenKeyBinding` は own 限定で読むため 4085 ガードを素通りし、
 *   そのうえで `ath` 照合だけが有効化されて `ath` を持たない正当な proof が 4084 で落ちる。
 * - `expectedJkt`: 同様に `cnf.jkt` 照合だけが有効化され、正当な proof が 4085 で落ちる。
 *
 * 汚染下でも「明示的に渡した照合値」は従来どおり働くこと（正常系）も併せて固定する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { signCompactJws } from '../../../../credential/vc/compact-jws.js';
import { createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import { ErrorCodes, type VericertsError } from '../../../../errors.js';
import { createDpopProof } from '../../dpop.js';
import { computeAth, toDpopPublicKeyJwk } from '../../dpop-common.js';
import { verifyDpopProof } from '../../dpop-verify.js';

const SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(9), 'ES256');
const HTM = 'POST';
const HTU = 'https://api.example.com/mcp';

/** 攻撃者が選んだ束縛を持つ proof（別エンドポイント向け）。 */
const ATTACKER_HTM = 'GET';
const ATTACKER_HTU = 'https://attacker.example.com/collect';

/** `htm` / `htu` を欠いた options を型検査を迂回して渡す（JS 呼び出し・`as` キャスト相当）。 */
function optionsWithout(partial: Record<string, unknown>): Parameters<typeof verifyDpopProof>[1] {
  return partial as unknown as Parameters<typeof verifyDpopProof>[1];
}

/** 送出されたエラーコードを取り出す。 */
function codeOf(fn: () => unknown): unknown {
  try {
    fn();
  } catch (e) {
    return (e as VericertsError).code;
  }
  return undefined;
}

describe('verifyDpopProof の照合値の汚染耐性', () => {
  it('継承した htm では別メソッドの proof を受理しない', () => {
    const proof = createDpopProof({ htm: ATTACKER_HTM, htu: HTU }, SIGNER);
    const code = withPollutedPrototype({ htm: ATTACKER_HTM }, () =>
      codeOf(() => verifyDpopProof(proof, optionsWithout({ htu: HTU }))),
    );
    expect(code).toBe(ErrorCodes.DPOP_HTTP_BINDING_MISMATCH);
  });

  it('継承した htu では別エンドポイント向けの proof を受理しない', () => {
    const proof = createDpopProof({ htm: HTM, htu: ATTACKER_HTU }, SIGNER);
    const code = withPollutedPrototype({ htu: ATTACKER_HTU }, () =>
      codeOf(() => verifyDpopProof(proof, optionsWithout({ htm: HTM }))),
    );
    expect(code).toBe(ErrorCodes.DPOP_HTTP_BINDING_MISMATCH);
  });

  it('継承した nonce は nonce 検証を有効化しない', () => {
    // nonce を持たない正当な proof。呼び出し側は nonce を指定していない。
    const proof = createDpopProof({ htm: HTM, htu: HTU }, SIGNER);
    const verified = withPollutedPrototype({ nonce: 'attacker-nonce' }, () =>
      verifyDpopProof(proof, { htm: HTM, htu: HTU }),
    );
    expect(verified.nonce).toBeUndefined();
  });

  it('継承した accessToken は ath 照合を有効化しない', () => {
    // ath を持たない正当な proof。呼び出し側は accessToken を渡していない。
    const proof = createDpopProof({ htm: HTM, htu: HTU }, SIGNER);
    const verified = withPollutedPrototype({ accessToken: 'attacker-token' }, () =>
      verifyDpopProof(proof, { htm: HTM, htu: HTU }),
    );
    expect(verified.ath).toBeUndefined();
  });

  it('継承した expectedJkt は cnf.jkt 照合を有効化しない', () => {
    const proof = createDpopProof({ htm: HTM, htu: HTU }, SIGNER);
    const verified = withPollutedPrototype({ expectedJkt: 'attacker-jkt' }, () =>
      verifyDpopProof(proof, { htm: HTM, htu: HTU }),
    );
    expect(verified.jkt).not.toBe('attacker-jkt');
  });

  it('汚染下でも明示的に渡した照合値は従来どおり働く（正常系）', () => {
    const proof = createDpopProof({ htm: HTM, htu: HTU, nonce: 'server-nonce' }, SIGNER);
    const verified = withPollutedPrototype(
      { htm: ATTACKER_HTM, htu: ATTACKER_HTU, nonce: 'attacker-nonce' },
      () => verifyDpopProof(proof, { htm: HTM, htu: HTU, nonce: 'server-nonce' }),
    );
    expect(verified.htm).toBe(HTM);
    expect(verified.htu).toBe(HTU);
    expect(verified.nonce).toBe('server-nonce');
  });

  it('汚染下でも明示的な accessToken / expectedJkt の照合は働く（正常系）', () => {
    const accessToken = 'real-access-token';
    const proof = createDpopProof({ htm: HTM, htu: HTU, accessToken }, SIGNER);
    const { jkt } = verifyDpopProof(proof, { htm: HTM, htu: HTU });
    const verified = withPollutedPrototype(
      { accessToken: 'attacker-token', expectedJkt: 'attacker-jkt' },
      () => verifyDpopProof(proof, { htm: HTM, htu: HTU, accessToken, expectedJkt: jkt }),
    );
    expect(verified.ath).toBeDefined();
    expect(verified.jkt).toBe(jkt);
  });
});

describe('verifyDpopProof の proof クレームの汚染耐性', () => {
  /** header / payload は `JSON.parse` の戻り値であり `Object.prototype` を継承する。 */
  it('継承した ath は ath 照合を素通りさせない', () => {
    // ath を持たない proof（生成時に accessToken を渡していない）。
    const stolenToken = 'stolen-access-token';
    const proof = createDpopProof({ htm: HTM, htu: HTU }, SIGNER);
    const { jkt } = verifyDpopProof(proof, { htm: HTM, htu: HTU });
    // 攻撃者は盗んだトークンの ath を Object.prototype に仕込める。鎖読みだと
    // payload.ath が汚染値を返し、RFC 9449 §4.3 step 11 の ath 照合を素通りできてしまう。
    const code = withPollutedPrototype({ ath: computeAth(stolenToken) }, () =>
      codeOf(() =>
        verifyDpopProof(proof, {
          htm: HTM,
          htu: HTU,
          accessToken: stolenToken,
          expectedJkt: jkt,
        }),
      ),
    );
    expect(code).toBe(ErrorCodes.DPOP_ATH_MISMATCH);
  });

  it('継承した typ は typ 無しの JWT を DPoP proof として受理させない', () => {
    // typ ヘッダを持たない JWS（DPoP proof ではない）。
    const notADpopProof = signCompactJws(
      { alg: 'ES256', jwk: toDpopPublicKeyJwk(SIGNER.publicKeyJwk, 'ES256') },
      { jti: 'jti-1', htm: HTM, htu: HTU, iat: Math.floor(Date.now() / 1000) },
      SIGNER,
    );
    const code = withPollutedPrototype({ typ: 'dpop+jwt' }, () =>
      codeOf(() => verifyDpopProof(notADpopProof, { htm: HTM, htu: HTU })),
    );
    expect(code).toBe(ErrorCodes.DPOP_PROOF_MALFORMED);
  });

  it('汚染下でも正当な proof の ath / typ は従来どおり検証される（正常系）', () => {
    const accessToken = 'real-access-token';
    const proof = createDpopProof({ htm: HTM, htu: HTU, accessToken }, SIGNER);
    const { jkt } = verifyDpopProof(proof, { htm: HTM, htu: HTU });
    const verified = withPollutedPrototype(
      { ath: computeAth('other-token'), typ: 'attacker+jwt' },
      () => verifyDpopProof(proof, { htm: HTM, htu: HTU, accessToken, expectedJkt: jkt }),
    );
    expect(verified.ath).toBe(computeAth(accessToken));
  });
});
