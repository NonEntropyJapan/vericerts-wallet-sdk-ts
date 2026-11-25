/**
 * verifyCredential が JWT-VC の 2 表現（VC 1.1 系の `vc` ラップ / VC 2.0 系の `vc` 非包み）を
 * 受理すること、および 2 表現の境界で検査が緩まないことの回帰テスト（実鍵・モック禁止）。
 *
 * 2.0 系の payload は walt.id が実際に出すクレーム集合
 * （`iss, sub, @context, id, type, name, issuer, credentialSubject, validFrom, validUntil, jti, exp, iat, nbf`）
 * に揃える。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { issueCredential } from '../issue.js';
import { createPrivateKeySigner } from '../signer.js';
import { verifyCredential } from '../verify.js';

const P256_KEY = new Uint8Array(32).fill(7);
const NOW = 1_767_225_600;
const VALID_FROM_SEC = NOW - 86_400;
const VALID_UNTIL_SEC = NOW + 86_400;
const iso = (sec: number): string => new Date(sec * 1000).toISOString();

const pub = getP256PublicKey(P256_KEY, false);
const enc = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const jwk: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: enc(pub.subarray(1, 33)),
  y: enc(pub.subarray(33, 65)),
};
const signer = createPrivateKeySigner(P256_KEY, 'ES256');

function signPayload(payload: Record<string, unknown>): string {
  const b64u = (text: string): string => base64urlnopad.encode(new TextEncoder().encode(text));
  const signingInput = `${b64u(JSON.stringify({ alg: 'ES256', typ: 'JWT' }))}.${b64u(
    JSON.stringify(payload),
  )}`;
  return `${signingInput}.${base64urlnopad.encode(signer.sign(new TextEncoder().encode(signingInput)))}`;
}

/** walt.id が出す VC 2.0 系 JWT-VC の payload（`vc` で包まない）。 */
function flatPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: 'did:example:issuer',
    sub: 'did:example:subject',
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:1234',
    type: ['VerifiableCredential', 'OpenBadgeCredential'],
    name: 'interop',
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    validFrom: iso(VALID_FROM_SEC),
    validUntil: iso(VALID_UNTIL_SEC),
    jti: 'urn:uuid:1234',
    exp: VALID_UNTIL_SEC,
    iat: VALID_FROM_SEC,
    nbf: VALID_FROM_SEC,
    ...overrides,
  };
}

const verify = (jwt: string) =>
  verifyCredential(jwt, { key: { publicKeyJwk: jwk }, nowSeconds: NOW });
const schemaInvalid = new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);

describe('verifyCredential: VC 1.1 系（vc ラップ + issuanceDate / expirationDate）', () => {
  it('issueCredential が出す形は従来どおり受理する', () => {
    const jwt = issueCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'],
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' },
        issuanceDate: iso(VALID_FROM_SEC),
        expirationDate: iso(VALID_UNTIL_SEC),
      },
      signer,
      { nowSeconds: NOW },
    );
    expect(verify(jwt).payload.iss).toBe('did:example:issuer');
  });

  it('vc 内の validFrom は日付として読まない（issuanceDate 欠落で 3002）', () => {
    const payload = {
      iss: 'did:example:issuer',
      nbf: VALID_FROM_SEC,
      vc: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'],
        issuer: 'did:example:issuer',
        credentialSubject: {},
        validFrom: iso(VALID_FROM_SEC),
      },
    };
    expect(() => verify(signPayload(payload))).toThrow(schemaInvalid);
  });

  it('vc と @context を併せ持つ payload は vc を本体として扱う（2.0 形の検査へ逃がさない）', () => {
    // `vc` が不正（issuanceDate 無し）なら、payload 直下が 2.0 形として正しくても 3002。
    const payload = flatPayload({
      vc: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'],
        issuer: 'did:example:issuer',
        credentialSubject: {},
      },
    });
    expect(() => verify(signPayload(payload))).toThrow(schemaInvalid);
  });
});

describe('verifyCredential: VC 2.0 系（vc 非包み + validFrom / validUntil）', () => {
  it('walt.id の payload 形は受理する（3002 / 3010 にならない）', () => {
    const result = verify(signPayload(flatPayload()));
    expect(result.payload.validFrom).toBe(iso(VALID_FROM_SEC));
  });

  it('validUntil / exp / jti / id が無くても受理する', () => {
    const payload = flatPayload();
    for (const key of ['validUntil', 'exp', 'jti', 'id']) {
      delete payload[key];
    }
    expect(() => verify(signPayload(payload))).not.toThrow();
  });

  it('署名を改竄すると 3010', () => {
    const [h, p, s] = signPayload(flatPayload()).split('.') as [string, string, string];
    const forged = Buffer.from(JSON.stringify(flatPayload({ name: 'forged' }))).toString(
      'base64url',
    );
    expect(() => verify(`${h}.${forged}.${s}`)).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
    expect(p).not.toBe(forged);
  });

  it('iss と issuer の不一致は 3002（confused deputy 対策を 2.0 形でも維持）', () => {
    expect(() => verify(signPayload(flatPayload({ iss: 'did:example:attacker' })))).toThrow(
      schemaInvalid,
    );
  });

  it('sub と credentialSubject.id の不一致は 3002', () => {
    expect(() => verify(signPayload(flatPayload({ sub: 'did:example:other' })))).toThrow(
      schemaInvalid,
    );
  });

  it('jti と id の不一致は 3002', () => {
    expect(() => verify(signPayload(flatPayload({ jti: 'urn:uuid:other' })))).toThrow(
      schemaInvalid,
    );
  });

  it('nbf と validFrom の不一致は 3002', () => {
    expect(() => verify(signPayload(flatPayload({ nbf: VALID_FROM_SEC - 1 })))).toThrow(
      schemaInvalid,
    );
  });

  it('exp と validUntil の不一致は 3002', () => {
    expect(() => verify(signPayload(flatPayload({ exp: VALID_UNTIL_SEC + 1 })))).toThrow(
      schemaInvalid,
    );
  });

  it('validUntil があるのに exp が無いのは 3002', () => {
    const payload = flatPayload();
    delete payload.exp;
    expect(() => verify(signPayload(payload))).toThrow(schemaInvalid);
  });

  it('validFrom が無い（issuanceDate だけ）は 3002: 束縛されない日付は受理しない', () => {
    const payload = flatPayload({ issuanceDate: iso(VALID_FROM_SEC) });
    delete payload.validFrom;
    expect(() => verify(signPayload(payload))).toThrow(schemaInvalid);
  });

  it('VC 2.0 の @context 先頭でなければ 3002', () => {
    const payload = flatPayload({ '@context': ['https://www.w3.org/2018/credentials/v1'] });
    expect(() => verify(signPayload(payload))).toThrow(schemaInvalid);
  });

  it('期限切れ（exp 超過）は 3024、時刻評価は 2.0 形でも効く', () => {
    expect(() =>
      verifyCredential(signPayload(flatPayload()), {
        key: { publicKeyJwk: jwk },
        nowSeconds: VALID_UNTIL_SEC + 1000,
      }),
    ).toThrow(new VericertsError(ErrorCodes.VC_EXPIRED));
  });

  it('@context も vc も無い payload は 3002', () => {
    const payload = flatPayload();
    delete payload['@context'];
    expect(() => verify(signPayload(payload))).toThrow(schemaInvalid);
  });

  it('vc が null / 配列 / 文字列で @context も併せ持つ payload は 2.0 形に倒れず 3002', () => {
    for (const vc of [null, [], 'x', 1]) {
      expect(() => verify(signPayload(flatPayload({ vc })))).toThrow(schemaInvalid);
    }
  });

  it('subject.id が無いのに sub がある / id が無いのに jti がある / nbf が無いのは 3002', () => {
    expect(() =>
      verify(signPayload(flatPayload({ credentialSubject: { name: 'Alice' } }))),
    ).toThrow(schemaInvalid);
    const noId = flatPayload({ jti: 'urn:uuid:orphan' });
    delete noId.id;
    expect(() => verify(signPayload(noId))).toThrow(schemaInvalid);
    const noNbf = flatPayload();
    delete noNbf.nbf;
    expect(() => verify(signPayload(noNbf))).toThrow(schemaInvalid);
  });

  it('validFrom / validUntil が文字列でなければ 3002', () => {
    expect(() => verify(signPayload(flatPayload({ validFrom: VALID_FROM_SEC })))).toThrow(
      schemaInvalid,
    );
    expect(() => verify(signPayload(flatPayload({ validUntil: VALID_UNTIL_SEC })))).toThrow(
      schemaInvalid,
    );
  });

  it('未来の nbf は 3025、スキュー超過の未来 iat は 4014（時刻評価は突合より前に効く）', () => {
    const future = NOW + 10_000;
    const notYet = flatPayload({ nbf: future, validFrom: iso(future) });
    expect(() => verify(signPayload(notYet))).toThrow(
      new VericertsError(ErrorCodes.VC_NOT_YET_VALID),
    );
    expect(() => verify(signPayload(flatPayload({ iat: future })))).toThrow(
      new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
    );
  });

  it('Object.prototype の汚染値は表現判定にも突合にも使われない', () => {
    const proto = Object.prototype as unknown as Record<string, unknown>;
    try {
      // `vc` / `@context` を持たない payload が汚染値で 1.1 / 2.0 に化けない。
      proto.vc = { '@context': ['https://www.w3.org/ns/credentials/v2'] };
      proto['@context'] = ['https://www.w3.org/ns/credentials/v2'];
      const noBody = { iss: 'did:example:issuer', nbf: VALID_FROM_SEC };
      expect(() => verify(signPayload(noBody))).toThrow(schemaInvalid);
    } finally {
      delete proto.vc;
      delete proto['@context'];
    }
    try {
      // 2.0 形で本体の任意メンバ（`id` / `validUntil`）を持たない payload が汚染値を拾って 3002 にならない。
      proto.id = 'urn:uuid:polluted';
      proto.validUntil = iso(VALID_UNTIL_SEC);
      const minimal = flatPayload();
      for (const key of ['id', 'jti', 'validUntil', 'exp']) {
        delete minimal[key];
      }
      expect(() => verify(signPayload(minimal))).not.toThrow();
    } finally {
      delete proto.id;
      delete proto.validUntil;
    }
  });
});
