/**
 * JSON-LD 色の強い JWT-VC の発行 → 検証ラウンドトリップ（実鍵・モック禁止）。
 *
 * `__tests__/` 直下ではなくサブディレクトリへ切り出すのは 1 ディレクトリ行数上限
 * （.linterly.yml）対応（`gdpr/` 等と同じ理由）。
 *
 * `jwt_vc_json-ld` は `jwt_vc_json` と同じ JWS Enveloping Proof で保護され、SDK の
 * `VerifiableCredential` 型は `@context` を無条件に必須とする。したがって発行（`issue.ts`）・
 * 検証（`verify.ts`）は `@context` / `type` の内容で分岐せず、複数 `@context` / 複数 `type` を
 * 持つ JSON-LD VC も追加の暗号プリミティブなしにラウンドトリップできる。
 * 「発行・検証を実装する」が既存プリミティブ + format 登録（`dcql.ts` / `matcher.ts`）だけで
 * 満たされることを示す確認テストであり、`@context` を増やしても署名・検証が壊れないことの
 * 恒久ガードでもある。
 */

import { describe, expect, it } from 'bun:test';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { issueCredential } from '../../issue.js';
import { createPrivateKeySigner } from '../../signer.js';
import type { VerifiableCredential } from '../../vc.js';
import { verifyCredential } from '../../verify.js';

const PRIVATE_KEY = new Uint8Array(32).fill(7);
/** 固定現在時刻（2026-01-01T00:00:00Z 近傍）。 */
const NOW = 1_767_225_600;
const ISSUANCE = '2025-12-01T00:00:00Z';
const EXPIRATION = '2027-01-01T00:00:00Z';

/** 非圧縮 P-256 公開鍵（0x04 || x || y）から JWK を組み立てる。 */
function publicKeyJwk(): PublicKeyJwk {
  const pub = getP256PublicKey(PRIVATE_KEY, false);
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

/**
 * 複数 `@context` / 複数 `type` を持つ JSON-LD VC。
 *
 * base context に加えて語彙 context を 2 本重ね、`type` も `VerifiableCredential` 以外を 2 つ
 * 持たせる（`@context` が 1 本だけの実質 jwt_vc_json 相当にならないようにする）。
 */
const JSON_LD_VC: VerifiableCredential = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://www.w3.org/ns/credentials/examples/v2',
    'https://schema.org/',
  ],
  type: ['VerifiableCredential', 'UniversityDegreeCredential', 'AlumniCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: {
    id: 'did:example:subject',
    name: 'Alice',
    degree: { type: 'BachelorDegree', name: 'Bachelor of Science' },
  },
  issuanceDate: ISSUANCE,
  expirationDate: EXPIRATION,
  id: 'urn:uuid:json-ld-1',
};

describe('JSON-LD JWT-VC の発行 → 検証', () => {
  it('複数 @context / 複数 type を持つ VC を発行して検証できる', () => {
    // 前提が崩れる（context / type が 1 本に減る）と本テストが自明化するため先に表明する。
    expect(JSON_LD_VC['@context'].length).toBeGreaterThan(1);
    expect(JSON_LD_VC.type.length).toBeGreaterThan(1);

    const jwt = issueCredential(JSON_LD_VC, createPrivateKeySigner(PRIVATE_KEY, 'ES256'), {
      nowSeconds: NOW,
    });
    const result = verifyCredential(jwt, {
      key: { publicKeyJwk: publicKeyJwk() },
      nowSeconds: NOW,
    });

    expect(result.header.alg).toBe('ES256');
    expect(result.payload.iss).toBe('did:example:issuer');
    expect(result.payload.jti).toBe('urn:uuid:json-ld-1');

    // `@context` / `type` は欠落・切り詰めなく payload の `vc` に載る。
    const vc = result.payload.vc as VerifiableCredential;
    expect(vc['@context']).toEqual(JSON_LD_VC['@context']);
    expect(vc.type).toEqual(JSON_LD_VC.type);
    // JSON-LD でネストした credentialSubject も保持される。
    expect((vc.credentialSubject.degree as Record<string, unknown>).name).toBe(
      'Bachelor of Science',
    );
  });
});
