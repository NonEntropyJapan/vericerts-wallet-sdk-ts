/**
 * 分離型 Holder Service 向け KB-JWT テンプレートの生成・合成のユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - 秘密鍵なしでテンプレートを生成でき、`sd_hash` / `aud` / `nonce` が正しく確定すること。
 * - 外部署名済み KB-JWT を合成した結果が `verifySdJwt` を通ること（`addKeyBinding` と同一バイト列）。
 * - 別鍵で署名された KB-JWT を `cnf.jwk` 照合で拒否すること。
 *
 * 取り違え・改竄の検出は `key-binding.mismatch.test.ts` を参照。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import {
  attachKeyBinding,
  attachKeyBindingSignature,
  createKeyBindingTemplate,
} from '../key-binding.js';
import { selectDisclosures } from '../sdjwt.js';
import { addKeyBinding, verifySdJwt } from '../verify.js';
import {
  AUD,
  expectCode,
  IAT,
  ISSUER_JWK,
  issue,
  NONCE,
  OTHER_SIGNER,
  SESSION_ALG,
  SESSION_SIGNER,
  signAsSession,
  toCompactKbJwt,
  VCT,
} from './key-binding.fixtures.js';

describe('分離型 Holder Service: KB-JWT テンプレート生成（秘密鍵なし）', () => {
  it('秘密鍵を渡さずにテンプレートを生成でき、nonce / aud / sd_hash が確定する', () => {
    const template = createKeyBindingTemplate(issue(), {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      disclosedClaims: ['name'],
      iatSeconds: IAT,
    });

    expect(template.header).toEqual({ alg: SESSION_ALG, typ: 'kb+jwt' });
    expect(template.payload.nonce).toBe(NONCE);
    expect(template.payload.aud).toBe(AUD);
    expect(template.payload.iat).toBe(IAT);
    // sd_hash は呼び出し側から受け取らず、提示部から SDK が計算する。
    expect(template.payload.sd_hash).toMatch(/^[A-Za-z0-9_-]+$/);
    // 提示部は開示指定どおりに絞り込まれ、KB-JWT はまだ付いていない。
    expect(template.presentation.endsWith('~')).toBe(true);
    expect(template.presentation).toBe(selectDisclosures(issue(), ['name']));
    // signingInput は `header.payload` の 2 セグメント（署名はまだ無い）。
    expect(template.signingInput.split('.')).toHaveLength(2);
  });

  it('開示クレーム未指定なら入力 SD-JWT をそのまま提示部として扱う', () => {
    const sdJwt = issue();
    const template = createKeyBindingTemplate(sdJwt, {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expect(template.presentation).toBe(sdJwt);
  });

  it('既に KB-JWT が付与された SD-JWT にはテンプレートを発行しない（3010）', () => {
    const bound = addKeyBinding(selectDisclosures(issue(), ['name']), SESSION_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expectCode(
      () =>
        createKeyBindingTemplate(bound, {
          alg: SESSION_ALG,
          nonce: NONCE,
          audience: AUD,
          iatSeconds: IAT,
        }),
      ErrorCodes.SIG_INVALID,
    );
  });

  it('disclosedClaims 指定時も KB-JWT 付与済み SD-JWT を拒否する（3010）', () => {
    // `selectDisclosures` は既存 KB-JWT を捨てて末尾 `~` の文字列を返すため、絞り込み後の提示部を
    // 見ていると KB-JWT が黙って剥がされる。判定は絞り込み前の入力に対して行う。
    const bound = addKeyBinding(selectDisclosures(issue(), ['name', 'email']), SESSION_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expectCode(
      () =>
        createKeyBindingTemplate(bound, {
          alg: SESSION_ALG,
          nonce: NONCE,
          audience: AUD,
          disclosedClaims: ['name'],
          iatSeconds: IAT,
        }),
      ErrorCodes.SIG_INVALID,
    );
  });
});

describe('分離型 Holder Service: 外部署名 KB-JWT の合成', () => {
  it('Session 秘密鍵を Holder Service に渡さずに VP を構成でき、検証を通る', () => {
    // --- Holder Service 側（VC バイト列のみ保持。秘密鍵は持たない）---
    const template = createKeyBindingTemplate(issue(), {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      disclosedClaims: ['name'],
      iatSeconds: IAT,
    });

    // --- Agent Session 側（秘密鍵はここだけ。VC バイト列は受け取らない）---
    const signature = signAsSession(template.signingInput);

    // --- Holder Service 側: 外部署名を合成 ---
    const presentation = attachKeyBindingSignature(template, signature);

    const result = verifySdJwt(presentation, {
      issuerKey: ISSUER_JWK,
      expectedVct: VCT,
      audience: AUD,
      nonce: NONCE,
      requireKeyBinding: true,
    });
    expect(result.keyBindingVerified).toBe(true);
    expect(result.claims.name).toBe('Alice');
    // 未開示クレームは漏れない。
    expect(result.claims.email).toBeUndefined();
  });

  it('統合構成の addKeyBinding と同一の KB-JWT バイト列を生成する（整合性）', () => {
    const presented = selectDisclosures(issue(), ['name']);
    const integrated = addKeyBinding(presented, SESSION_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });

    const template = createKeyBindingTemplate(presented, {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    const separated = attachKeyBindingSignature(template, signAsSession(template.signingInput));

    expect(separated).toBe(integrated);
  });

  it('コンパクト KB-JWT 文字列を受け取る形でも合成できる', () => {
    const template = createKeyBindingTemplate(issue(), {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      disclosedClaims: ['name', 'age_over_18'],
      iatSeconds: IAT,
    });
    const kbJwt = toCompactKbJwt(template.signingInput, signAsSession(template.signingInput));

    const presentation = attachKeyBinding(template, kbJwt);
    expect(presentation).toBe(`${template.presentation}${kbJwt}`);
    expect(
      verifySdJwt(presentation, {
        issuerKey: ISSUER_JWK,
        audience: AUD,
        nonce: NONCE,
        requireKeyBinding: true,
      }).keyBindingVerified,
    ).toBe(true);
  });

  it('別鍵で署名された KB-JWT を cnf.jwk 照合で拒否する（3012）', () => {
    const template = createKeyBindingTemplate(issue(), {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      disclosedClaims: ['name'],
      iatSeconds: IAT,
    });
    // Session 鍵ではなく別鍵で署名（なりすまし）。
    const signature = signAsSession(template.signingInput, OTHER_SIGNER);
    expectCode(
      () => attachKeyBindingSignature(template, signature),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });

  it('verifySignature: false なら合成時の署名照合を省略する（addKeyBinding 互換）', () => {
    const template = createKeyBindingTemplate(issue(), {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      disclosedClaims: ['name'],
      iatSeconds: IAT,
    });
    const signature = signAsSession(template.signingInput, OTHER_SIGNER);
    const presentation = attachKeyBindingSignature(template, signature, {
      verifySignature: false,
    });
    // 合成自体は通るが、検証段で Holder Binding 不一致として落ちる。
    expectCode(
      () =>
        verifySdJwt(presentation, {
          issuerKey: ISSUER_JWK,
          audience: AUD,
          nonce: NONCE,
          requireKeyBinding: true,
        }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });
});
