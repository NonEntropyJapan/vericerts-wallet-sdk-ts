/**
 * SD-JWT VC 検証鍵の `Object.prototype` 汚染耐性テスト。
 *
 * `verifySdJwt` の `issuerKey` は Issuer 署名の**検証鍵**である。型上は必須だが、型の無い JS から
 * 渡し忘れるとプロトタイプ鎖の汚染値が「渡された鍵」に化け、**攻撃者の鍵で Issuer 署名が
 * 検証される**（＝任意の偽造 SD-JWT VC が受理される）。`vc/verify.ts` の `key` と同じクラスの欠陥。
 *
 * 汚染下でも「鍵が渡されていない呼び出しは署名不成立（3010）」に倒れることを検証する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { createSdJwt } from '../../sdjwt.js';
import { verifySdJwt } from '../../verify.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ATTACKER_KEY = new Uint8Array(32).fill(9);

function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ATTACKER_JWK = toJwk(getP256PublicKey(ATTACKER_KEY, false));
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));
const VCT = 'https://example.com/credentials/identity';
const NOW = 1_767_225_600;

/** 攻撃者の鍵で署名した（＝正規 Issuer のものではない）SD-JWT VC。 */
function forged(): string {
  return createSdJwt(createPrivateKeySigner(ATTACKER_KEY, 'ES256'), {
    vct: VCT,
    disclosureClaims: ['name'],
    claims: { name: 'Mallory' },
    salts: { name: 'salt-name' },
    nowSeconds: NOW,
  });
}

describe('verifySdJwt の検証鍵 汚染耐性', () => {
  it('継承した issuerKey で偽造 SD-JWT VC を受理しない', () => {
    const sdJwt = forged();
    expect(() =>
      // `issuerKey` を渡していない呼び出し。汚染値を拾えば攻撃者の鍵で署名検証が通ってしまう。
      withPollutedPrototype({ issuerKey: ATTACKER_JWK }, () =>
        verifySdJwt(sdJwt, { nowSeconds: NOW } as Parameters<typeof verifySdJwt>[1]),
      ),
    ).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('明示的に渡した正規の issuerKey は従来どおり検証できる（正常系）', () => {
    const sdJwt = createSdJwt(createPrivateKeySigner(ISSUER_KEY, 'ES256'), {
      vct: VCT,
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
      salts: { name: 'salt-name' },
      nowSeconds: NOW,
    });
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW });
    expect(result.claims.name).toBe('Alice');
  });

  it('明示的に渡した別鍵では従来どおり 3010 で拒否される（正常系）', () => {
    expect(() => verifySdJwt(forged(), { issuerKey: ISSUER_JWK, nowSeconds: NOW })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });
});
