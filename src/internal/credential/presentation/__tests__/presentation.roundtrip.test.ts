/**
 * JWT-VP（JWS）署名 → 検証ラウンドトリップのユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - ES256（P-256）/ ES256K（secp256k1）/ EdDSA（Ed25519）の署名 → 検証成功
 *   （公開鍵 JWK 注入 / 検証関数注入）。
 * - aud / nonce の一致検証（OID4VP）と不一致拒否（HOLDER_BIND_MISMATCH 3012）。
 * - iss ≠ holder の拒否（HOLDER_BIND_MISMATCH 3012）。
 * - 改竄署名 → SIG_INVALID（3010）、alg=none → ALG_NONE（3011）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { CredentialAlg } from '../../vc/jws.js';
import { issuePresentation } from '../issue.js';
import { verifyPresentation } from '../presentation.js';
import type { VerifiablePresentation } from '../vp.js';
import { FIXTURES, sampleVp, signerFor } from './presentation.fixtures.js';

describe.each<CredentialAlg>(['ES256', 'ES256K', 'EdDSA'])('JWT-VP 署名 → 検証（%s）', (alg) => {
  const fx = FIXTURES[alg];

  it('公開鍵 JWK 注入で検証が通り、構造検証済み VP を返す（allowUnbound）', () => {
    // バインドを持たない VP は allowUnbound でオプトアウトして検証する。
    const jwt = issuePresentation(sampleVp(), signerFor(alg));
    const result = verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true });
    expect(result.header.alg).toBe(alg);
    expect(result.payload.iss).toBe('did:example:holder');
    expect(result.payload.jti).toBe('urn:uuid:vp-1');
    expect(result.presentation.holder).toBe('did:example:holder');
    expect(result.presentation.verifiableCredential).toHaveLength(1);
  });

  it('検証関数注入で検証が通る（allowUnbound）', () => {
    const jwt = issuePresentation(sampleVp(), signerFor(alg));
    const result = verifyPresentation(jwt, { key: { verify: fx.verify }, allowUnbound: true });
    expect(result.payload.iss).toBe('did:example:holder');
  });

  it('aud / nonce バインドが一致すれば検証成功', () => {
    const jwt = issuePresentation(sampleVp(), signerFor(alg), {
      audience: 'https://verifier.example',
      nonce: 'n-abc',
    });
    const result = verifyPresentation(jwt, {
      key: { publicKeyJwk: fx.jwk },
      expectedAudience: 'https://verifier.example',
      expectedNonce: 'n-abc',
    });
    expect(result.payload.aud).toBe('https://verifier.example');
    expect(result.payload.nonce).toBe('n-abc');
  });

  it('aud 不一致は HOLDER_BIND_MISMATCH（3012）', () => {
    // nonce は一致させ、aud のみ不一致にする（束縛モードで aud 不一致のみを突く）。
    const jwt = issuePresentation(sampleVp(), signerFor(alg), {
      audience: 'https://a.example',
      nonce: 'n-1',
    });
    expect(() =>
      verifyPresentation(jwt, {
        key: { publicKeyJwk: fx.jwk },
        expectedAudience: 'https://b.example',
        expectedNonce: 'n-1',
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('nonce 不一致は HOLDER_BIND_MISMATCH（3012）', () => {
    // aud は一致させ、nonce のみ不一致にする。
    const jwt = issuePresentation(sampleVp(), signerFor(alg), {
      audience: 'https://a.example',
      nonce: 'n-1',
    });
    expect(() =>
      verifyPresentation(jwt, {
        key: { publicKeyJwk: fx.jwk },
        expectedAudience: 'https://a.example',
        expectedNonce: 'n-2',
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('改竄署名は SIG_INVALID（3010）', () => {
    const jwt = issuePresentation(sampleVp(), signerFor(alg));
    const parts = jwt.split('.');
    const sig = parts[2] ?? '';
    const flipped = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    const tampered = `${parts[0]}.${parts[1]}.${flipped}`;
    expect(() => verifyPresentation(tampered, { key: { publicKeyJwk: fx.jwk } })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });
});

describe('JWT-VP Verifier バインド必須化（リプレイ防止）', () => {
  const fx = FIXTURES.ES256;

  it('既定では expectedAudience/expectedNonce 未指定はバインド未検証として HOLDER_BIND_MISMATCH（3012）', () => {
    // aud/nonce を持つ VP でも、検証側が期待値を渡さなければリプレイ・対象者バインドが
    // 未検証になる。既定（束縛）モードはこれを拒否する（修正前は成功してしまう回帰）。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'), {
      audience: 'https://verifier.example',
      nonce: 'n-abc',
    });
    expect(() => verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk } })).toThrow(
      new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH),
    );
  });

  it('既定で nonce のみ未指定でも拒否（aud 一致でも nonce バインド必須）', () => {
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'), {
      audience: 'https://verifier.example',
      nonce: 'n-abc',
    });
    expect(() =>
      verifyPresentation(jwt, {
        key: { publicKeyJwk: fx.jwk },
        expectedAudience: 'https://verifier.example',
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('allowUnbound: true なら aud/nonce 未指定でも検証成功（明示オプトアウト）', () => {
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const result = verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true });
    expect(result.payload.iss).toBe('did:example:holder');
  });
});

describe('JWT-VP 時刻検証（exp / nbf）', () => {
  const fx = FIXTURES.ES256;
  const BOUND = { audience: 'https://verifier.example', nonce: 'n-1' };
  const EXPECTED = {
    key: { publicKeyJwk: fx.jwk },
    expectedAudience: 'https://verifier.example',
    expectedNonce: 'n-1',
  } as const;

  /** 任意の VP payload を有効署名で組み立てる（時刻型不正・nbf テスト用）。 */
  function signVpPayload(payload: Record<string, unknown>): string {
    const signer = signerFor('ES256');
    const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url');
    const payloadSeg = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signingInput = `${header}.${payloadSeg}`;
    const signature = signer.sign(new TextEncoder().encode(signingInput));
    return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
  }

  it('exp を過ぎた VP は VC_EXPIRED（3024）', () => {
    // 基準時刻 1000s + 有効期間 3600s = exp 4600s。now=5000s で期限切れ。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'), {
      ...BOUND,
      expiresInSeconds: 3600,
      nowSeconds: 1000,
    });
    expect(() => verifyPresentation(jwt, { ...EXPECTED, nowSeconds: 5000 })).toThrow(
      new VericertsError(ErrorCodes.VC_EXPIRED),
    );
  });

  it('exp 内なら検証成功', () => {
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'), {
      ...BOUND,
      expiresInSeconds: 3600,
      nowSeconds: 1000,
    });
    const result = verifyPresentation(jwt, { ...EXPECTED, nowSeconds: 2000 });
    expect(result.payload.exp).toBe(4600);
  });

  it('nbf より前の VP は VC_NOT_YET_VALID（3025）', () => {
    // issuePresentation は nbf を設定しないため、nbf=未来 の payload を手組みして署名する。
    const jwt = signVpPayload({
      iss: 'did:example:holder',
      aud: BOUND.audience,
      nonce: BOUND.nonce,
      nbf: 9_000_000_000,
      vp: sampleVp(),
    });
    expect(() => verifyPresentation(jwt, { ...EXPECTED, nowSeconds: 1000 })).toThrow(
      new VericertsError(ErrorCodes.VC_NOT_YET_VALID),
    );
  });

  it('exp 型不正（非数値）は VC_SCHEMA_INVALID（3002）', () => {
    const jwt = signVpPayload({
      iss: 'did:example:holder',
      aud: BOUND.audience,
      nonce: BOUND.nonce,
      exp: 'not-a-number',
      vp: sampleVp(),
    });
    expect(() => verifyPresentation(jwt, { ...EXPECTED, nowSeconds: 1000 })).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('nbf 型不正（非数値）は VC_SCHEMA_INVALID（3002）', () => {
    const jwt = signVpPayload({
      iss: 'did:example:holder',
      aud: BOUND.audience,
      nonce: BOUND.nonce,
      nbf: 'not-a-number',
      vp: sampleVp(),
    });
    expect(() => verifyPresentation(jwt, { ...EXPECTED, nowSeconds: 1000 })).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });
});

describe('JWT-VP 検証の異常系', () => {
  it('alg=none は ALG_NONE（3011）', () => {
    const fx = FIXTURES.ES256;
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const parts = jwt.split('.');
    const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString(
      'base64url',
    );
    const forged = `${noneHeader}.${parts[1]}.${parts[2]}`;
    expect(() => verifyPresentation(forged, { key: { publicKeyJwk: fx.jwk } })).toThrow(
      new VericertsError(ErrorCodes.ALG_NONE),
    );
  });

  // 回帰: 構造不正の JWT に対し `decodeCompactJws` の INVALID_DID（2001）が
  // そのまま漏れていた。VP 検証 API の失敗面（30xx）に合わせ SIG_INVALID（3010）へ正規化する。
  it.each([
    ['セグメントが少ない', 'bad.jwt'],
    ['セグメントが多い', 'not.a.valid.jwt'],
    ['セグメントが空', '..'],
    ['区切りが無い', 'notajwt'],
    ['base64url として不正', 'a!b.c!d.e!f'],
    ['ヘッダが JSON でない', 'bm90LWpzb24.e30.c2ln'],
  ])('構造不正の JWT（%s）は SIG_INVALID（3010）へ正規化される', (_label, jwt) => {
    const fx = FIXTURES.ES256;
    expect(() => verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk } })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('iss ≠ vp.holder の改竄 payload は HOLDER_BIND_MISMATCH（3012）', () => {
    const fx = FIXTURES.ES256;
    const signer = signerFor('ES256');
    // iss を holder と乖離させた payload を直接組み立てて署名する（攻撃シナリオ）。
    const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({ iss: 'did:example:attacker', vp: sampleVp() }),
    ).toString('base64url');
    const signingInput = `${header}.${payload}`;
    const signature = signer.sign(new TextEncoder().encode(signingInput));
    const jwt = `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
    expect(() => verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk } })).toThrow(
      new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH),
    );
  });

  it('不正 VP は発行時に VC_SCHEMA_INVALID（3002）', () => {
    const bad = { ...sampleVp(), holder: '' } as VerifiablePresentation;
    expect(() => issuePresentation(bad, signerFor('ES256'))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });
});
