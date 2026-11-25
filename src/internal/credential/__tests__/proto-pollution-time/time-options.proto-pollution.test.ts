/**
 * 時刻オプション経由の有効期限・鮮度検証バイパスの回帰テスト。
 *
 * `nowSeconds` / `now` / `nowMs` をプロトタイプ鎖で読むと、これらを**省略した**正当な検証でも
 * `Object.prototype` の汚染値が「現在時刻」として使われる。攻撃者が過去の時刻を仕込めば、
 * 期限切れ（`exp` 超過）の VC / VP / SD-JWT VC / DPoP proof が**そのまま受理される**。
 *
 * いずれも「汚染下でも実時刻で評価され、期限切れは拒否される」を期待値とする。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { createSdJwt } from '../../sdjwt/sdjwt.js';
import { verifySdJwt } from '../../sdjwt/verify.js';
import { issueCredential } from '../../vc/issue.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import { verifyCredential } from '../../vc/verify.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);

function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const VCT = 'https://example.com/credentials/identity';

/** 実時刻。汚染値（過去）と区別できるよう実際の now を使う。 */
const REAL_NOW = Math.floor(Date.now() / 1000);
/** 攻撃者が「現在時刻」として仕込む過去時刻（VC がまだ有効だった頃）。 */
const ATTACKER_PAST = REAL_NOW - 100_000;

// `exp` は既定クロックスキュー（vc = 120 秒）より十分過去に置く。境界付近だとスキューに
// 吸収されて「期限切れ」にならず、汚染の有無を区別できないため。

describe('SD-JWT VC の nowSeconds 汚染耐性', () => {
  /** 実時刻基準で既に期限切れの SD-JWT VC。 */
  function expiredSdJwt(): string {
    return createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['name'],
      claims: { name: 'Alice', exp: REAL_NOW - 10_000 },
      salts: { name: 'salt-name' },
      nowSeconds: ATTACKER_PAST,
    });
  }

  it('継承した nowSeconds では期限切れ SD-JWT VC を受理しない', () => {
    const sdJwt = expiredSdJwt();
    expect(() =>
      withPollutedPrototype({ nowSeconds: ATTACKER_PAST }, () =>
        // nowSeconds は渡していない。汚染値を拾えば「まだ有効」と判定されてしまう。
        verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK }),
      ),
    ).toThrow(new VericertsError(ErrorCodes.VC_EXPIRED));
  });

  it('明示的に渡した nowSeconds は従来どおり基準時刻になる（正常系）', () => {
    const sdJwt = expiredSdJwt();
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: ATTACKER_PAST });
    expect(result.claims.name).toBe('Alice');
  });
});

describe('JWT-VC の nowSeconds 汚染耐性', () => {
  /** 実時刻基準で既に期限切れの JWT-VC。 */
  function expiredJwtVc(): string {
    const vc: VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:holder' },
      issuanceDate: new Date((REAL_NOW - 200_000) * 1000).toISOString(),
      expirationDate: new Date((REAL_NOW - 10_000) * 1000).toISOString(),
    };
    return issueCredential(vc, ISSUER_SIGNER, { nowSeconds: ATTACKER_PAST });
  }

  it('継承した nowSeconds では期限切れ JWT-VC を受理しない', () => {
    const jwt = expiredJwtVc();
    expect(() =>
      withPollutedPrototype({ nowSeconds: ATTACKER_PAST }, () =>
        verifyCredential(jwt, { key: { publicKeyJwk: ISSUER_JWK } }),
      ),
    ).toThrow(new VericertsError(ErrorCodes.VC_EXPIRED));
  });

  it('明示的に渡した nowSeconds は従来どおり基準時刻になる（正常系）', () => {
    const jwt = expiredJwtVc();
    const result = verifyCredential(jwt, {
      key: { publicKeyJwk: ISSUER_JWK },
      nowSeconds: ATTACKER_PAST,
    });
    expect(result.payload.exp).toBeDefined();
  });
});
