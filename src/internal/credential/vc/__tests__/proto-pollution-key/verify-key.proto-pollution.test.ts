/**
 * JWT-VC 検証鍵の `Object.prototype` 汚染耐性テスト。
 *
 * `verifyCredential` の `opts.key` は**署名検証鍵**である。型上必須だが、型の無い JS から
 * 渡し忘れるとプロトタイプ鎖の汚染値が「渡された鍵」に化け、**攻撃者の鍵で署名が検証される**
 * （＝偽造 JWT-VC が受理される）。`verifySdJwt` の `issuerKey` と同じクラスの欠陥。
 *
 * 既存の時刻オプションのテストは `key` を常に own プロパティとして渡していたため、この経路は
 * カバーされていなかった。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { issueCredential } from '../../issue.js';
import { createPrivateKeySigner } from '../../signer.js';
import type { VerifiableCredential } from '../../vc.js';
import { verifyCredential } from '../../verify.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ATTACKER_KEY = new Uint8Array(32).fill(9);

function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));
const ATTACKER_JWK = toJwk(getP256PublicKey(ATTACKER_KEY, false));
const NOW = Math.floor(Date.now() / 1000);

function makeVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: new Date((NOW - 100) * 1000).toISOString(),
  };
}

/** 攻撃者の鍵で署名した（＝正規 Issuer のものではない）JWT-VC。 */
function forged(): string {
  return issueCredential(makeVc(), createPrivateKeySigner(ATTACKER_KEY, 'ES256'), {
    nowSeconds: NOW,
  });
}

describe('verifyCredential の検証鍵 汚染耐性', () => {
  it('継承した key で偽造 JWT-VC を受理しない', () => {
    const jwt = forged();
    expect(() =>
      // `key` を渡していない呼び出し。汚染値を拾えば攻撃者の鍵で署名検証が通ってしまう。
      withPollutedPrototype({ key: { publicKeyJwk: ATTACKER_JWK } }, () =>
        verifyCredential(jwt, { nowSeconds: NOW } as Parameters<typeof verifyCredential>[1]),
      ),
    ).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('継承した key で VericertsError 以外の例外を漏らさない', () => {
    const jwt = forged();
    let caught: unknown;
    try {
      withPollutedPrototype({ key: { publicKeyJwk: ATTACKER_JWK } }, () =>
        verifyCredential(jwt, {} as Parameters<typeof verifyCredential>[1]),
      );
    } catch (error) {
      caught = error;
    }
    // 生の TypeError（`Object.getOwnPropertyDescriptor(undefined, ...)`）が公開 API から
    // 漏れてはならない。
    expect(caught).toBeInstanceOf(VericertsError);
  });

  it('明示的に渡した正規の key は従来どおり検証できる（正常系）', () => {
    const jwt = issueCredential(makeVc(), createPrivateKeySigner(ISSUER_KEY, 'ES256'), {
      nowSeconds: NOW,
    });
    const result = verifyCredential(jwt, { key: { publicKeyJwk: ISSUER_JWK }, nowSeconds: NOW });
    expect(result.payload.iss).toBe('did:example:issuer');
  });

  it('明示的に渡した別鍵では従来どおり 3010 で拒否される（正常系）', () => {
    expect(() =>
      verifyCredential(forged(), { key: { publicKeyJwk: ISSUER_JWK }, nowSeconds: NOW }),
    ).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
  });
});
