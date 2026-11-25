/**
 * verifyCredential の envelope↔body 自己整合検証のユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - 正常系ラウンドトリップ成功。
 * - iss/sub/jti/nbf/exp の envelope（JWT claims）と body（vc.*）の不一致・欠落・余剰を
 *   VC_SCHEMA_INVALID（3002）として検出すること。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { issueCredential } from '../issue.js';
import { createPrivateKeySigner } from '../signer.js';
import type { VerifiableCredential } from '../vc.js';
import { verifyCredential } from '../verify.js';

/** テスト用の固定秘密鍵（ES256 / P-256）。 */
const P256_KEY = new Uint8Array(32).fill(7);

/** テスト用の固定現在時刻（2026-01-01T00:00:00Z 近傍）。 */
const NOW = 1_767_225_600;
/** 発行日時 ISO（NOW より十分前）。 */
const ISSUANCE = '2025-12-01T00:00:00Z';
/** 有効期限 ISO（NOW より十分後）。 */
const EXPIRATION = '2027-01-01T00:00:00Z';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const enc = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: enc(pub.subarray(1, 33)), y: enc(pub.subarray(33, 65)) };
}

/** サンプル VC を作る。 */
function sampleVc(overrides: Partial<VerifiableCredential> = {}): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: ISSUANCE,
    expirationDate: EXPIRATION,
    id: 'urn:uuid:1234',
    ...overrides,
  };
}

describe('verifyCredential envelope↔body 自己整合', () => {
  const jwk = toJwk(getP256PublicKey(P256_KEY, false), 'P-256');
  const signer = createPrivateKeySigner(P256_KEY, 'ES256');

  /** UTF-8 文字列を base64url（パディングなし）でエンコードする。 */
  function b64u(text: string): string {
    return base64urlnopad.encode(new TextEncoder().encode(text));
  }

  /**
   * 任意の payload を ES256 で再署名してコンパクト JWS を組み立てる。
   *
   * 署名・時刻検証を通過させた上で envelope↔body 検証（3002）のみを評価するため、改竄した
   * payload を正規の signer で署名し直す（既存 JWS の payload 差し替えでは署名検証で 3010 に倒れる）。
   */
  function signPayload(payload: Record<string, unknown>): string {
    const headerSeg = b64u(JSON.stringify({ alg: 'ES256', typ: 'JWT' }));
    const payloadSeg = b64u(JSON.stringify(payload));
    const signingInput = `${headerSeg}.${payloadSeg}`;
    const signature = signer.sign(new TextEncoder().encode(signingInput));
    return `${signingInput}.${base64urlnopad.encode(signature)}`;
  }

  /**
   * sampleVc を発行時と同じマッピングで JWT-VC payload に変換する。
   *
   * `issue.ts` の payload マッピング（iss/nbf/vc は常時・sub/exp/jti は条件付き）と対称に保つこと。
   * issue 側のマッピングを変更したら本ヘルパも追従させる（乖離すると envelope↔body 検証の前提が崩れる）。
   */
  function basePayload(vc: VerifiableCredential): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      iss: vc.issuer,
      nbf: Math.floor(Date.parse(vc.issuanceDate) / 1000),
      vc,
    };
    const subjectId = vc.credentialSubject.id;
    if (typeof subjectId === 'string') {
      payload.sub = subjectId;
    }
    if (vc.expirationDate !== undefined) {
      payload.exp = Math.floor(Date.parse(vc.expirationDate) / 1000);
    }
    if (vc.id !== undefined) {
      payload.jti = vc.id;
    }
    return payload;
  }

  const verify = (jwt: string) =>
    verifyCredential(jwt, { key: { publicKeyJwk: jwk }, nowSeconds: NOW });

  it('正常系ラウンドトリップは引き続き成功する', () => {
    const jwt = issueCredential(sampleVc(), signer, { nowSeconds: NOW });
    expect(() => verify(jwt)).not.toThrow();
  });

  it('payload.vc 欠落は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc());
    delete payload.vc;
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('vc.issuer 欠落（payload.vc 構造不正）は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc());
    const { issuer: _omit, ...vcWithoutIssuer } = sampleVc();
    payload.vc = vcWithoutIssuer;
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('iss と vc.issuer 不一致は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc());
    payload.iss = 'did:example:attacker';
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('sub と vc.credentialSubject.id 不一致は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc());
    payload.sub = 'did:example:other-subject';
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('subject.id ありで sub 欠落は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc());
    delete payload.sub;
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('subject.id なしで sub 存在は VC_SCHEMA_INVALID（3002）', () => {
    const vc = sampleVc({ credentialSubject: { name: 'Alice' } });
    const payload = basePayload(vc);
    payload.sub = 'did:example:subject';
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('jti と vc.id 不一致は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc());
    payload.jti = 'urn:uuid:tampered';
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('vc.id ありで jti 欠落は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc());
    delete payload.jti;
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('vc.id なしで jti 存在は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc({ id: undefined }));
    payload.jti = 'urn:uuid:1234';
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('nbf と issuanceDate NumericDate 不一致は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc());
    // nbf を 1 秒ずらす（NOW より前なので時刻検証は通過する）。
    payload.nbf = (payload.nbf as number) - 1;
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('payload.nbf 欠落は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc());
    // nbf は assertEnvelopeBinding で必須（payload.nbf === isoToNumericDate(vc.issuanceDate)）。
    // 欠落時は undefined !== <number> で 3002 になる。issuanceDate は NOW より十分過去のため、
    // nbf を削除しても時刻検証（3020）には倒れないことの境界カバレッジ。
    delete payload.nbf;
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('exp と expirationDate NumericDate 不一致は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc());
    // exp を 1 秒ずらす（NOW より後なので時刻検証は通過する）。
    payload.exp = (payload.exp as number) - 1;
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('expirationDate なしで exp 存在は VC_SCHEMA_INVALID（3002）', () => {
    const payload = basePayload(sampleVc({ expirationDate: undefined }));
    payload.exp = Math.floor(Date.parse(EXPIRATION) / 1000);
    expect(() => verify(signPayload(payload))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });
});
