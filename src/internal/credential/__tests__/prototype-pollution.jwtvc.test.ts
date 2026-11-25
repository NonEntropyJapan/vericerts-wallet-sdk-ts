/**
 * `createRemoteSigner` が prototype 継承値を signer の「自身のプロパティ」へ昇格させないことの
 * 回帰テスト。
 *
 * `const { kid, publicKeyJwk } = config` の分割代入はプロトタイプ鎖を辿るため、`config` が
 * `kid` を自身のプロパティとして持たなくても継承値を拾い、それを **signer の自身のプロパティ**
 * として載せていた。`kid` の省略は正当な利用法なので、これは正当な呼び出し側が
 * `Object.prototype` 汚染下で攻撃者の鍵 ID を JWS ヘッダへ載せる経路になる
 * （`buildJwsHeader` の `Object.hasOwn` ガードが素通りする）。
 *
 * 併せて `alg` / `publicKeyJwk` も自身のプロパティのみを読むことを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { createRemoteSigner, type RemoteSignerConfig } from '../../keymanager/jws/remote-signer.js';
import { getP256PublicKey, signP256 } from '../../keymanager/signer.js';
import { issueCredentialAsync } from '../vc/issue.js';
import type { VerifiableCredential } from '../vc/vc.js';

/** 攻撃者が `Object.prototype` 経由で載せようとする鍵 ID。 */
const ATTACKER_KID = 'did:web:attacker.example#key-1';

/** fake KMS が保持する秘密鍵（SDK 側へは渡さない）。 */
const KMS_KEY = new Uint8Array(32).fill(23);

/** テスト用の固定現在時刻。 */
const NOW = 1_767_225_600;

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const KMS_JWK = toJwk(getP256PublicKey(KMS_KEY, false), 'P-256');

/** 攻撃者が仕込んだ別鍵の公開鍵 JWK（publicKeyJwk 昇格の検証用）。 */
const ATTACKER_JWK = toJwk(getP256PublicKey(new Uint8Array(32).fill(7), false), 'P-256');

/** 秘密鍵をクロージャに閉じ込めた fake KMS 署名関数。 */
function fakeKms(message: Uint8Array): Uint8Array {
  return signP256(sha256(message), KMS_KEY);
}

/** サンプル VC を作る。 */
function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2025-12-01T00:00:00Z',
    id: 'urn:uuid:1234',
  };
}

/** JWT のヘッダセグメントをデコードする。 */
function decodeHeader(jwt: string): Record<string, unknown> {
  const headerSeg = jwt.split('.')[0] ?? '';
  return JSON.parse(Buffer.from(headerSeg, 'base64url').toString('utf-8'));
}

/**
 * `proto` をプロトタイプに持つ config を作る（自身のプロパティは alg / publicKeyJwk / sign のみ）。
 *
 * @param proto プロトタイプへ仕込む汚染値。
 * @returns `createRemoteSigner` へ渡す config。
 */
function configWithProto(proto: Record<string, unknown>): RemoteSignerConfig {
  return Object.assign(Object.create(proto) as object, {
    alg: 'ES256',
    publicKeyJwk: KMS_JWK,
    sign: fakeKms,
  }) as RemoteSignerConfig;
}

describe('createRemoteSigner: prototype 継承値を自身のプロパティへ昇格させない', () => {
  it('プロトタイプの kid は signer の自身のプロパティにならない', () => {
    const config = configWithProto({ kid: ATTACKER_KID });
    // 前提: config 自体は kid を自身のプロパティとして持たない。
    expect(Object.hasOwn(config, 'kid')).toBe(false);

    const signer = createRemoteSigner(config);
    expect(Object.hasOwn(signer, 'kid')).toBe(false);
    expect(signer.kid).toBeUndefined();
  });

  it('プロトタイプの kid は発行した JWT-VC のヘッダに載らない', async () => {
    const config = configWithProto({ kid: ATTACKER_KID });
    const jwt = await issueCredentialAsync(sampleVc(), createRemoteSigner(config), {
      nowSeconds: NOW,
    });
    // 汚染が効くとヘッダは {"alg":"ES256","kid":"did:web:attacker.example#key-1","typ":"JWT"} になる。
    expect(decodeHeader(jwt)).toEqual({ alg: 'ES256', typ: 'JWT' });
  });

  it('Object.prototype 汚染下でも kid 省略の JWT-VC ヘッダは従来どおりのバイト列', async () => {
    const polluted = Object.prototype as unknown as Record<string, unknown>;
    polluted.kid = ATTACKER_KID;
    try {
      const signer = createRemoteSigner({ alg: 'ES256', publicKeyJwk: KMS_JWK, sign: fakeKms });
      expect(Object.hasOwn(signer, 'kid')).toBe(false);
      const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
      const expected = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString(
        'base64url',
      );
      expect(jwt.split('.')[0]).toBe(expected);
    } finally {
      delete polluted.kid;
    }
  });

  it('自身のプロパティとして指定した kid は従来どおりヘッダへ載る（後方互換）', async () => {
    const kid = 'kms-key-1';
    const signer = createRemoteSigner({ alg: 'ES256', publicKeyJwk: KMS_JWK, kid, sign: fakeKms });
    expect(Object.hasOwn(signer, 'kid')).toBe(true);
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    expect(decodeHeader(jwt)).toEqual({ alg: 'ES256', kid, typ: 'JWT' });
  });

  it('プロトタイプの publicKeyJwk は signer へ引き継がれない', () => {
    const config = Object.assign(Object.create({ publicKeyJwk: ATTACKER_JWK }) as object, {
      alg: 'ES256',
      sign: fakeKms,
    }) as RemoteSignerConfig;
    const signer = createRemoteSigner(config);
    // 汚染値が昇格すると検証側へ攻撃者の公開鍵が配られる。
    expect(signer.publicKeyJwk).toBeUndefined();
  });

  it('プロトタイプの alg は読まれず UNSUPPORTED_ALGORITHM（1030）で弾かれる', () => {
    const config = Object.assign(Object.create({ alg: 'ES256' }) as object, {
      publicKeyJwk: KMS_JWK,
      sign: fakeKms,
    }) as RemoteSignerConfig;
    expect(() => createRemoteSigner(config)).toThrow(
      new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM),
    );
  });
});
