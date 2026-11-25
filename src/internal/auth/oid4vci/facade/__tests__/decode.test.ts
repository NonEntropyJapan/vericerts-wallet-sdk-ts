/**
 * 受領した生 VC → `ReceivedVerifiableCredential` の写像。
 */

import { describe, expect, test } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { issueCredential } from '../../../../credential/vc/issue.js';
import { createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import { ErrorCodes } from '../../../../errors.js';
import { toReceivedCredential } from '../decode.js';
import { buildSdJwtVc, CONFIGURATION_ID, ISSUER } from './facade-fixtures.js';

const SIGNING_KEY = new Uint8Array(32).fill(7);

/** 素の JWT-VC（`~` を含まない）を組み立てる。 */
function buildJwtVc(payload: Readonly<Record<string, unknown>>): string {
  const signer = createPrivateKeySigner(SIGNING_KEY, 'ES256');
  const b64 = (text: string): string => base64urlnopad.encode(new TextEncoder().encode(text));
  const signingInput = `${b64(JSON.stringify({ alg: 'ES256', typ: 'JWT' }))}.${b64(
    JSON.stringify(payload),
  )}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64urlnopad.encode(signature)}`;
}

describe('toReceivedCredential: SD-JWT VC', () => {
  const raw = buildSdJwtVc({ vct: CONFIGURATION_ID, claims: { degree: 'Laurea', year: 2026 } });

  test('ReceivedVerifiableCredential の全メンバを埋める', () => {
    const vc = toReceivedCredential(raw);
    expect(vc.format).toBe('sd-jwt');
    expect(vc.type).toEqual([CONFIGURATION_ID]);
    expect(vc.issuer).toBe(ISSUER);
    expect(vc.issuanceDate).toBe(new Date(1_767_000_000 * 1000).toISOString());
    expect(vc.raw).toBe(raw);
  });

  test('選択的開示のクレームが復元され、構造クレームは claims に混ざらない', () => {
    const vc = toReceivedCredential(raw);
    expect(vc.claims.degree).toBe('Laurea');
    expect(vc.claims.year).toBe(2026);
    for (const structural of ['vct', 'iss', 'iat', '_sd', '_sd_alg']) {
      expect(Object.hasOwn(vc.claims, structural)).toBe(false);
    }
  });

  test('claims は null プロトタイプ（__proto__ クレームでも汚染されない）', () => {
    const vc = toReceivedCredential(raw);
    expect(Object.getPrototypeOf(vc.claims)).toBeNull();
  });

  test('識別子クレームが無ければ id を省く（SD-JWT VC は jti を必須としない）', () => {
    const vc = toReceivedCredential(raw);
    expect(Object.hasOwn(vc, 'id')).toBe(false);
  });
});

describe('toReceivedCredential: JWT-VC', () => {
  test('vc.type を type 列として読み、format は jwt になる', () => {
    const raw = buildJwtVc({
      iss: ISSUER,
      iat: 1_767_000_000,
      exp: 1_800_000_000,
      jti: 'urn:uuid:vc-1',
      vc: { type: ['VerifiableCredential', 'UniversityDegree'] },
    });
    const vc = toReceivedCredential(raw);
    expect(vc.format).toBe('jwt');
    expect(vc.type).toEqual(['VerifiableCredential', 'UniversityDegree']);
    expect(vc.id).toBe('urn:uuid:vc-1');
    expect(vc.expirationDate).toBe(new Date(1_800_000_000 * 1000).toISOString());
  });

  test('jti が無ければ vc.id を id として読む（W3C VC Data Model の標準形）', () => {
    const raw = buildJwtVc({
      iss: ISSUER,
      iat: 1_767_000_000,
      vc: { type: ['VerifiableCredential'], id: 'urn:uuid:vc-from-vc-id' },
    });
    expect(toReceivedCredential(raw).id).toBe('urn:uuid:vc-from-vc-id');
  });

  test('jti と vc.id が両方あれば jti を優先する', () => {
    const raw = buildJwtVc({
      iss: ISSUER,
      iat: 1_767_000_000,
      jti: 'urn:uuid:from-jti',
      vc: { type: ['VerifiableCredential'], id: 'urn:uuid:from-vc-id' },
    });
    expect(toReceivedCredential(raw).id).toBe('urn:uuid:from-jti');
  });

  test('jti も vc.id も無ければ id を省く', () => {
    const raw = buildJwtVc({
      iss: ISSUER,
      iat: 1_767_000_000,
      vc: { type: ['VerifiableCredential'] },
    });
    expect(Object.hasOwn(toReceivedCredential(raw), 'id')).toBe(false);
  });

  test('iat が無ければ nbf を発行日時として使う', () => {
    const raw = buildJwtVc({ iss: ISSUER, nbf: 1_767_000_000, vc: { type: ['Foo'] } });
    expect(toReceivedCredential(raw).issuanceDate).toBe(
      new Date(1_767_000_000 * 1000).toISOString(),
    );
  });
});

/** VC 2.0 系 JWT-VC（`vc` で包まない。walt.id が出す形）。 */
describe('toReceivedCredential: VC 2.0 系 JWT-VC（vc 非包み）', () => {
  const flat = (extra: Readonly<Record<string, unknown>> = {}): string =>
    buildJwtVc({
      iss: ISSUER,
      sub: 'did:key:z6MkHolder',
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:flat-1',
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: ISSUER,
      credentialSubject: { id: 'did:key:z6MkHolder', degree: 'Laurea' },
      validFrom: new Date(1_767_000_000 * 1000).toISOString(),
      validUntil: new Date(1_800_000_000 * 1000).toISOString(),
      jti: 'urn:uuid:flat-1',
      exp: 1_800_000_000,
      iat: 1_767_000_000,
      nbf: 1_767_000_000,
      ...extra,
    });

  test('payload の type / credentialSubject から型・属性を読む（8020 にならない）', () => {
    const vc = toReceivedCredential(flat());
    expect(vc.format).toBe('jwt');
    expect(vc.type).toEqual(['VerifiableCredential', 'OpenBadgeCredential']);
    expect(vc.id).toBe('urn:uuid:flat-1');
    expect(vc.claims.degree).toBe('Laurea');
    expect(vc.expirationDate).toBe(new Date(1_800_000_000 * 1000).toISOString());
  });

  test('claims に VC 本体のメンバ（@context / issuer / validFrom 等）を混ぜない', () => {
    const { claims } = toReceivedCredential(flat());
    expect(Object.keys(claims)).toEqual(['degree']);
  });

  test('@context が無く vc も無い payload は従来どおり型不明で 8020', () => {
    const raw = buildJwtVc({
      iss: ISSUER,
      iat: 1_767_000_000,
      type: ['VerifiableCredential'],
    });
    expect(() => toReceivedCredential(raw)).toThrow(
      expect.objectContaining({ context: { reason: 'credential_type_missing' } }),
    );
  });

  test('vc と @context を併せ持つ payload は vc を本体として読む（verifyCredential の判定と一致）', () => {
    const raw = flat({
      vc: { type: ['VerifiableCredential', 'FromVcClaim'], credentialSubject: { year: 2026 } },
    });
    const vc = toReceivedCredential(raw);
    expect(vc.type).toEqual(['VerifiableCredential', 'FromVcClaim']);
    expect(vc.claims.year).toBe(2026);
    expect(Object.hasOwn(vc.claims, 'degree')).toBe(false);
  });
});

/**
 * W3C JWT-VC の属性は **`vc.credentialSubject` 配下**にある（本 SDK 自身の
 * `credential/vc/issue.ts` が payload を `{ iss, nbf, iat, vc }` として組み、`sub` は
 * `vc.credentialSubject.id` の写しである）。payload 直下から構造クレームを引くだけの写像だと
 * 属性が丸ごと落ちて `claims` が `{}` になるため、**実際の発行経路が出す形**で回帰を固定する。
 */
describe('toReceivedCredential: W3C JWT-VC（vc.credentialSubject が属性の出所）', () => {
  const SUBJECT_DID = 'did:key:z6MkHolder';
  /** `credential/vc/issue.ts` が実際に生成する JWT-VC を組み立てる。 */
  function issueW3cJwtVc(credentialSubject: Readonly<Record<string, unknown>>): string {
    return issueCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'UniversityDegree'],
        issuer: ISSUER,
        issuanceDate: new Date(1_767_000_000 * 1000).toISOString(),
        credentialSubject,
      },
      createPrivateKeySigner(SIGNING_KEY, 'ES256'),
      { nowSeconds: 1_767_000_000 },
    );
  }

  test('vc.credentialSubject の属性が claims に載る', () => {
    const raw = issueW3cJwtVc({ id: SUBJECT_DID, degree: 'Laurea', year: 2026 });
    const vc = toReceivedCredential(raw);
    expect(vc.format).toBe('jwt');
    expect(vc.type).toEqual(['VerifiableCredential', 'UniversityDegree']);
    expect(vc.issuer).toBe(ISSUER);
    expect(vc.claims.degree).toBe('Laurea');
    expect(vc.claims.year).toBe(2026);
  });

  test('credentialSubject.id は Holder 識別子であり属性に含めない', () => {
    const raw = issueW3cJwtVc({ id: SUBJECT_DID, degree: 'Laurea' });
    expect(Object.hasOwn(toReceivedCredential(raw).claims, 'id')).toBe(false);
  });

  test('vc / 登録済みクレームは claims に混ざらない', () => {
    const raw = issueW3cJwtVc({ id: SUBJECT_DID, degree: 'Laurea' });
    const { claims } = toReceivedCredential(raw);
    for (const structural of ['vc', 'iss', 'iat', 'nbf', 'sub', 'jti']) {
      expect(Object.hasOwn(claims, structural)).toBe(false);
    }
  });

  test('claims は null プロトタイプのまま（__proto__ 属性でも汚染されない）', () => {
    const raw = issueW3cJwtVc({ id: SUBJECT_DID, degree: 'Laurea' });
    expect(Object.getPrototypeOf(toReceivedCredential(raw).claims)).toBeNull();
  });

  test('credentialSubject を持たない JWT-VC は空の claims を返す（仕様どおり）', () => {
    const raw = buildJwtVc({
      iss: ISSUER,
      iat: 1_767_000_000,
      vc: { type: ['VerifiableCredential'] },
    });
    expect(Object.keys(toReceivedCredential(raw).claims)).toEqual([]);
  });

  test('credentialSubject が配列（複数 subject）でも添字キーを属性にしない', () => {
    const raw = buildJwtVc({
      iss: ISSUER,
      iat: 1_767_000_000,
      vc: { type: ['VerifiableCredential'], credentialSubject: [{ degree: 'Laurea' }] },
    });
    expect(Object.keys(toReceivedCredential(raw).claims)).toEqual([]);
  });
});

describe('toReceivedCredential の fail-closed', () => {
  test('分解できない入力は 8020（credential_decode_failed）', () => {
    expect(() => toReceivedCredential('not-a-jwt')).toThrow();
    try {
      toReceivedCredential('not-a-jwt');
    } catch (e) {
      expect(e).toMatchObject({
        code: ErrorCodes.CREDENTIAL_REQUEST_FAILED,
        context: { reason: 'credential_decode_failed' },
      });
    }
  });

  test('iss が無い VC は受領の失敗に倒す', () => {
    const raw = buildJwtVc({ iat: 1_767_000_000, vc: { type: ['Foo'] } });
    try {
      toReceivedCredential(raw);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toMatchObject({ context: { reason: 'credential_issuer_missing' } });
    }
  });

  test('型が判別できない VC は受領の失敗に倒す（保存先も検証方法も決められない）', () => {
    const raw = buildJwtVc({ iss: ISSUER, iat: 1_767_000_000 });
    try {
      toReceivedCredential(raw);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toMatchObject({ context: { reason: 'credential_type_missing' } });
    }
  });

  test('発行日時が取れない VC は受領の失敗に倒す', () => {
    const raw = buildJwtVc({ iss: ISSUER, vc: { type: ['Foo'] } });
    try {
      toReceivedCredential(raw);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toMatchObject({ context: { reason: 'credential_issuance_date_missing' } });
    }
  });
});
