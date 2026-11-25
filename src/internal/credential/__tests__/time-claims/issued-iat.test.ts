/**
 * 発行 API が `iat`（発行時刻）を出力することの回帰テスト（実鍵・モック禁止）。
 *
 * 検証側に `iat` のクロックスキュー評価（`iat > now + skew` → 4014）を入れたが、本 SDK の
 * 発行 API はどれも `iat` を出しておらず、自リポジトリ発行分に対しては実質 no-op だった。
 * 本テストは 3 つの発行 API（`issueCredential` / `issuePresentation` / `createSdJwt`）が既定で
 * `iat` を出力し、`nowSeconds` で注入可能であることを固定する。
 *
 * 併せて、`iat` の追加が既存の不変条件を壊していないことを回帰として押さえる:
 * - JWT-VC の `nbf` ↔ `vc.issuanceDate` の束縛（`assertEnvelopeBinding`）は不変で、`iat` は関与しない。
 *   前倒し発行（`issuanceDate` が未来）の VC は従来どおり `VC_NOT_YET_VALID`（3025）で、
 *   `CLOCK_SKEW_EXCEEDED`（4014）に化けない。
 * - `iat` を持たない既存の VC / VP / SD-JWT VC は従来どおり検証を通る（後方互換）。
 *
 * FC-11（`issuer-key-revocation.ts`）の発行時刻解決がフォーマット別（JWT-VC は `nbf` 優先 /
 * SD-JWT VC は `iat` 優先）のままであることは `issuer-key-revocation.*.test.ts` が押さえる。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { issuePresentation } from '../../presentation/issue.js';
import { verifyPresentation } from '../../presentation/presentation.js';
import { VC_V2_CONTEXT, type VerifiablePresentation } from '../../presentation/vp.js';
import { createSdJwt, createSdJwtAsync, parseSdJwt } from '../../sdjwt/sdjwt.js';
import { verifySdJwt } from '../../sdjwt/verify.js';
import { issueCredential, issueCredentialAsync } from '../../vc/issue.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import { verifyCredential } from '../../vc/verify.js';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_KEY = new Uint8Array(32).fill(53);
const HOLDER_KEY = new Uint8Array(32).fill(59);
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const HOLDER_JWK = toJwk(getSecp256k1PublicKey(HOLDER_KEY, false), 'secp256k1');
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const VCT = 'https://example.com/credentials/identity';
const AUD = 'https://verifier.example';
const NONCE = 'n-407';

/** 固定の現在時刻 N（2026-01-01T00:00:00Z）。 */
const N = 1_767_225_600;
/** JWT-VC / SD-JWT VC の既定スキュー（= 上限キャップ、§2.9.1）。 */
const VC_CAP = 120;

/** エポック秒を ISO 8601 へ変換する。 */
function iso(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

/** コンパクト JWS の payload をデコードする。 */
function payloadOf(jwt: string): Record<string, unknown> {
  const part = jwt.split('.')[1] ?? '';
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** `issuanceDate` を指定したサンプル VC。 */
function sampleVc(issuanceSeconds = N - 10_000): VerifiableCredential {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: iso(issuanceSeconds),
    expirationDate: iso(N + 10_000),
    id: 'urn:uuid:407',
  };
}

/** サンプル VP。 */
function sampleVp(): VerifiablePresentation {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiablePresentation'],
    holder: 'did:example:holder',
    verifiableCredential: [issueCredential(sampleVc(), ISSUER_SIGNER, { nowSeconds: N })],
    id: 'urn:uuid:vp-407',
  };
}

/** 発行済み JWS の payload から `iat` を取り除き、同じ実鍵で再署名する（旧 Issuer 相当）。 */
function stripIat(jwt: string, signer = ISSUER_SIGNER): string {
  const b64u = (text: string): string => Buffer.from(text).toString('base64url');
  const { iat: _iat, ...rest } = payloadOf(jwt);
  const header = JSON.parse(
    Buffer.from(jwt.split('.')[0] ?? '', 'base64url').toString('utf8'),
  ) as Record<string, unknown>;
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(rest))}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

describe('issueCredential（JWT-VC）の iat', () => {
  it('既定で iat を出力し、既定スキューで検証できる', () => {
    const jwt = issueCredential(sampleVc(), ISSUER_SIGNER, { nowSeconds: N });
    expect(payloadOf(jwt).iat).toBe(N);
    expect(
      verifyCredential(jwt, { key: { publicKeyJwk: ISSUER_JWK }, nowSeconds: N }).payload.iat,
    ).toBe(N);
  });

  it('nowSeconds 未指定なら発行時の現在時刻を用いる', () => {
    const before = Math.floor(Date.now() / 1000);
    const iat = payloadOf(issueCredential(sampleVc(), ISSUER_SIGNER)).iat as number;
    const after = Math.floor(Date.now() / 1000);
    expect(iat).toBeGreaterThanOrEqual(before);
    expect(iat).toBeLessThanOrEqual(after);
  });

  it('iat は nbf ↔ vc.issuanceDate の束縛に関与しない（nbf は issuanceDate 由来のまま）', () => {
    // 発行時刻（N）と issuanceDate（N - 10000）が食い違っていても envelope↔body 整合は成立する。
    const jwt = issueCredential(sampleVc(), ISSUER_SIGNER, { nowSeconds: N });
    const payload = payloadOf(jwt);
    expect(payload.nbf).toBe(N - 10_000);
    expect(payload.iat).toBe(N);
    expect(() =>
      verifyCredential(jwt, { key: { publicKeyJwk: ISSUER_JWK }, nowSeconds: N }),
    ).not.toThrow();
  });

  it('前倒し発行（issuanceDate が未来）の VC は従来どおり 3025 で、4014 に化けない', () => {
    // `iat` を発行時刻にしているため、未来の `issuanceDate` は nbf だけを未来にする。
    const jwt = issueCredential(sampleVc(N + VC_CAP + 1), ISSUER_SIGNER, { nowSeconds: N });
    expect(() =>
      verifyCredential(jwt, { key: { publicKeyJwk: ISSUER_JWK }, nowSeconds: N }),
    ).toThrow(new VericertsError(ErrorCodes.VC_NOT_YET_VALID));
  });

  it('発行端末の時計がキャップを超えて進んでいると 4014 で拒否される', () => {
    const jwt = issueCredential(sampleVc(), ISSUER_SIGNER, { nowSeconds: N + VC_CAP + 1 });
    expect(() =>
      verifyCredential(jwt, { key: { publicKeyJwk: ISSUER_JWK }, nowSeconds: N }),
    ).toThrow(new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED));
  });

  it('同一の nowSeconds なら issueCredentialAsync とバイト一致する', async () => {
    const vc = sampleVc();
    expect(await issueCredentialAsync(vc, ISSUER_SIGNER, { nowSeconds: N })).toBe(
      issueCredential(vc, ISSUER_SIGNER, { nowSeconds: N }),
    );
  });
});

describe('issuePresentation（JWT-VP）の iat', () => {
  const EXPECTED = {
    key: { publicKeyJwk: ISSUER_JWK },
    expectedAudience: AUD,
    expectedNonce: NONCE,
    nowSeconds: N,
  } as const;

  it('既定で iat を出力し、既定スキューで検証できる', () => {
    const vp = { ...sampleVp(), holder: 'did:example:issuer' };
    const jwt = issuePresentation(vp, ISSUER_SIGNER, {
      audience: AUD,
      nonce: NONCE,
      nowSeconds: N,
    });
    expect(payloadOf(jwt).iat).toBe(N);
    expect(verifyPresentation(jwt, EXPECTED).payload.iat).toBe(N);
  });

  it('iat と exp は同一の基準時刻から導かれる', () => {
    const vp = { ...sampleVp(), holder: 'did:example:issuer' };
    const jwt = issuePresentation(vp, ISSUER_SIGNER, {
      audience: AUD,
      nonce: NONCE,
      nowSeconds: N,
      expiresInSeconds: 3600,
    });
    const payload = payloadOf(jwt);
    expect(payload.iat).toBe(N);
    expect(payload.exp).toBe(N + 3600);
  });

  it('nowSeconds 未指定なら発行時の現在時刻を用いる', () => {
    const vp = { ...sampleVp(), holder: 'did:example:issuer' };
    const before = Math.floor(Date.now() / 1000);
    const iat = payloadOf(issuePresentation(vp, ISSUER_SIGNER, { audience: AUD, nonce: NONCE }))
      .iat as number;
    expect(iat).toBeGreaterThanOrEqual(before);
    expect(iat).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
  });
});

describe('createSdJwt（SD-JWT VC）の iat', () => {
  /** cnf 付き SD-JWT VC を発行する。 */
  function issueSdJwt(claims: Record<string, unknown> = {}, nowSeconds = N): string {
    return createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      issuer: 'did:example:issuer',
      cnf: { jwk: HOLDER_JWK },
      disclosureClaims: ['name'],
      claims: { name: 'Alice', ...claims },
      salts: { name: 'salt-407' },
      nowSeconds,
    });
  }

  it('既定で iat を出力し、既定スキューで検証できる', () => {
    const sdJwt = issueSdJwt();
    expect(payloadOf(parseSdJwt(sdJwt).issuerJwt).iat).toBe(N);
    // `VerifiedSdJwt` は payload をそのまま返さないため、検証が通ること自体で受理を確認する。
    expect(verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: N }).vct).toBe(VCT);
  });

  it('claims で明示した iat が既定より優先される', () => {
    const sdJwt = issueSdJwt({ iat: N - 500 });
    expect(payloadOf(parseSdJwt(sdJwt).issuerJwt).iat).toBe(N - 500);
  });

  it('claims に iat: undefined を渡すと iat を出力しない（旧 Issuer 互換の発行）', () => {
    const sdJwt = issueSdJwt({ iat: undefined });
    expect(payloadOf(parseSdJwt(sdJwt).issuerJwt).iat).toBeUndefined();
  });

  it('発行端末の時計がキャップを超えて進んでいると 4014 で拒否される', () => {
    const sdJwt = issueSdJwt({}, N + VC_CAP + 1);
    expect(() => verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: N })).toThrow(
      new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
    );
  });

  // 回帰: `iat` を `disclosureClaims` に入れても Disclosure 側へ回さない。回すと issuer-signed
  // payload から平文 `iat` が消え、未来 `iat` の 4014 判定を無言で素通りできてしまう。
  it('iat は disclosureClaims に指定しても平文 payload に残る', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      issuer: 'did:example:issuer',
      disclosureClaims: ['iat', 'name'],
      claims: { name: 'Alice', iat: N + VC_CAP + 1 },
      salts: { name: 'salt-407' },
      nowSeconds: N,
    });
    expect(payloadOf(parseSdJwt(sdJwt).issuerJwt).iat).toBe(N + VC_CAP + 1);
    // `iat` の Disclosure は生成しない（平文と Disclosure の二重出力・`_sd` への混入を防ぐ）。
    expect(parseSdJwt(sdJwt).disclosures.map((d) => d.claimName)).toEqual(['name']);
    // 平文に残るので未来 `iat` のクロックスキュー判定が効く。
    expect(() => verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: N })).toThrow(
      new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
    );
  });

  it('createSdJwtAsync も同一の nowSeconds でバイト一致する（iat を含む）', async () => {
    const opts = {
      vct: VCT,
      issuer: 'did:example:issuer',
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
      salts: { name: 'salt-407' },
      nowSeconds: N,
    };
    expect(await createSdJwtAsync(ISSUER_SIGNER, opts)).toBe(createSdJwt(ISSUER_SIGNER, opts));
    expect(payloadOf(parseSdJwt(await createSdJwtAsync(ISSUER_SIGNER, opts)).issuerJwt).iat).toBe(
      N,
    );
  });
});

describe('後方互換: iat を持たない既存クレデンシャル', () => {
  it('iat の無い JWT-VC は従来どおり検証成功する', () => {
    const jwt = stripIat(issueCredential(sampleVc(), ISSUER_SIGNER, { nowSeconds: N }));
    const result = verifyCredential(jwt, { key: { publicKeyJwk: ISSUER_JWK }, nowSeconds: N });
    expect(result.payload.iat).toBeUndefined();
  });

  it('iat の無い JWT-VP は従来どおり検証成功する', () => {
    const vp = { ...sampleVp(), holder: 'did:example:issuer' };
    const jwt = stripIat(
      issuePresentation(vp, ISSUER_SIGNER, { audience: AUD, nonce: NONCE, nowSeconds: N }),
    );
    const result = verifyPresentation(jwt, {
      key: { publicKeyJwk: ISSUER_JWK },
      expectedAudience: AUD,
      expectedNonce: NONCE,
      nowSeconds: N,
    });
    expect(result.payload.iat).toBeUndefined();
  });

  it('iat の無い SD-JWT VC は従来どおり検証成功する', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      issuer: 'did:example:issuer',
      disclosureClaims: ['name'],
      claims: { name: 'Alice', iat: undefined },
      salts: { name: 'salt-407' },
    });
    expect(payloadOf(parseSdJwt(sdJwt).issuerJwt).iat).toBeUndefined();
    expect(verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: N }).vct).toBe(VCT);
  });
});
