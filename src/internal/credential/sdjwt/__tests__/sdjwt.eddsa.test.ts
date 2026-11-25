/**
 * SD-JWT VC / KB-JWT の EdDSA（alg `EdDSA` / crv `Ed25519` / kty `OKP`）対応テスト
 * （実鍵・実署名、モック禁止。に 1:1 で対応）。
 *
 * 検証内容:
 * 1. Ed25519 の `did:key` で SD-JWT VC を発行・検証できる（`createDidKey` → `resolveDidKey` →
 *    `didDocumentToVerifierKey` で得た OKP 検証鍵での往復。選択的開示も含む）。
 * 2. Ed25519 の `cnf.jwk` で KB-JWT を生成・検証できる（`keyBindingVerified`）。別 Holder 鍵・
 *    sd_hash 改竄・nonce 不一致は 3012。
 * 3. ES256（既存 alg）の SD-JWT VC + KB-JWT が同じ経路で従来どおり通る（`describe.each`）。
 *
 * `alg: none` / alg confusion の拒否（受入条件 3）は兄弟モジュール
 * `sdjwt.eddsa.alg-confusion.test.ts` が担う。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createDidKey, resolveDidKey } from '../../../identity/method-key.js';
import { getEd25519PublicKey } from '../../../keymanager/ed25519.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import { didDocumentToVerifierKey } from '../../vc/verifier-key.js';
import { parseSdJwt, selectDisclosures } from '../sdjwt.js';
import { SD_JWT_VC_TYP } from '../typ.js';
import { addKeyBinding, verifySdJwt } from '../verify.js';
import {
  ALG_FIXTURES,
  AUD,
  b64u,
  decodeIssuerHeader,
  ED_HOLDER_SEED,
  ED_ISSUER_SEED,
  ED_OTHER_HOLDER_SEED,
  IAT,
  issueSdJwt,
  NONCE,
  toOkpJwk,
  VCT,
} from './sdjwt.eddsa.fixtures.js';

const ED = ALG_FIXTURES.EdDSA;

describe.each(['ES256', 'EdDSA'] as const)('SD-JWT VC ラウンドトリップ（%s）', (alg) => {
  const fixture = ALG_FIXTURES[alg];
  /** cnf に Holder 鍵を載せた SD-JWT の提示部（name のみ開示）。 */
  const present = (): string =>
    selectDisclosures(issueSdJwt(fixture.issuerSigner, { jwk: fixture.holderJwk }), ['name']);

  it('Issuer-signed JWT のヘッダが該当 alg / 既定 typ（dc+sd-jwt）を持つ', () => {
    const header = decodeIssuerHeader(issueSdJwt(fixture.issuerSigner));
    expect(header.alg).toBe(alg);
    // 発行既定は `dc+sd-jwt`（旧 `vc+sd-jwt` は明示 opt-in のみ）。
    expect(header.typ).toBe(SD_JWT_VC_TYP);
  });

  it('全開示で全クレームが復元される', () => {
    const result = verifySdJwt(issueSdJwt(fixture.issuerSigner), {
      issuerKey: fixture.issuerJwk,
      expectedVct: VCT,
    });
    expect(result.vct).toBe(VCT);
    expect(result.claims.name).toBe('Alice');
    expect(result.claims.age_over_18).toBe(true);
    expect(result.claims.email).toBe('alice@example.com');
  });

  it('選択的開示では開示クレームのみ復元される', () => {
    const presented = selectDisclosures(issueSdJwt(fixture.issuerSigner), ['name']);
    expect(parseSdJwt(presented).disclosures.length).toBe(1);
    const result = verifySdJwt(presented, { issuerKey: fixture.issuerJwk });
    expect(result.claims.name).toBe('Alice');
    expect(result.claims.age_over_18).toBeUndefined();
    expect(result.claims.email).toBeUndefined();
  });

  it('cnf 鍵で署名した KB-JWT は検証成功する', () => {
    const bound = addKeyBinding(present(), fixture.holderSigner, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    const result = verifySdJwt(bound, {
      issuerKey: fixture.issuerJwk,
      audience: AUD,
      nonce: NONCE,
      requireKeyBinding: true,
    });
    expect(result.keyBindingVerified).toBe(true);
    expect(result.claims.name).toBe('Alice');
  });

  it('cnf と別鍵で署名した KB-JWT は HOLDER_BIND_MISMATCH（3012）', () => {
    const bound = addKeyBinding(present(), fixture.otherHolderSigner, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expect(() =>
      verifySdJwt(bound, { issuerKey: fixture.issuerJwk, audience: AUD, nonce: NONCE }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });
});

describe('受入条件 1: Ed25519 did:key で SD-JWT VC を発行・検証', () => {
  const publicKey = getEd25519PublicKey(ED_ISSUER_SEED);
  const did = createDidKey('Ed25519', publicKey).id;
  const resolved = didDocumentToVerifierKey(resolveDidKey(did));
  // did:key(Ed25519) は JWK 表現の検証鍵を返す（コールバック形ではない）。
  const issuerJwk = resolved.publicKeyJwk ?? {};

  it('did:key(Ed25519) を解決した検証鍵は OKP/Ed25519 で y を持たない', () => {
    expect(issuerJwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: b64u(publicKey) });
    expect(issuerJwk.y).toBeUndefined();
  });

  it('did:key 由来の検証鍵で発行 → 全開示 → 検証が通る', () => {
    const signer = createPrivateKeySigner(ED_ISSUER_SEED, 'EdDSA');
    expect(decodeIssuerHeader(issueSdJwt(signer)).alg).toBe('EdDSA');
    const result = verifySdJwt(issueSdJwt(signer), {
      issuerKey: issuerJwk,
      expectedVct: VCT,
    });
    expect(result.claims.name).toBe('Alice');
    expect(result.claims.email).toBe('alice@example.com');
    expect(result.claims.iss).toBe('did:example:issuer');
  });

  it('did:key 由来の検証鍵で選択的開示（name / age_over_18）を検証できる', () => {
    const signer = createPrivateKeySigner(ED_ISSUER_SEED, 'EdDSA');
    const presented = selectDisclosures(issueSdJwt(signer), ['name', 'age_over_18']);
    const result = verifySdJwt(presented, { issuerKey: issuerJwk });
    expect(result.claims.name).toBe('Alice');
    expect(result.claims.age_over_18).toBe(true);
    expect(result.claims.email).toBeUndefined();
  });
});

describe('受入条件 2: Ed25519 cnf.jwk による KB-JWT', () => {
  /** cnf に Ed25519 Holder 鍵を載せた SD-JWT の提示部（name のみ開示）。 */
  function presentEd(): string {
    return selectDisclosures(issueSdJwt(ED.issuerSigner, { jwk: ED.holderJwk }), ['name']);
  }

  it('Issuer と Holder は別の Ed25519 鍵である', () => {
    expect(ED.holderJwk.x).not.toBe(ED.issuerJwk.x);
    expect(ED.holderJwk).toEqual(toOkpJwk(getEd25519PublicKey(ED_HOLDER_SEED)));
  });

  it('cnf の Ed25519 鍵で署名した KB-JWT は keyBindingVerified=true', () => {
    const bound = addKeyBinding(presentEd(), ED.holderSigner, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    const result = verifySdJwt(bound, {
      issuerKey: ED.issuerJwk,
      audience: AUD,
      nonce: NONCE,
      requireKeyBinding: true,
    });
    expect(result.keyBindingVerified).toBe(true);
    expect(result.cnf?.jwk).toEqual(ED.holderJwk);
  });

  it('別の Ed25519 鍵で署名した KB-JWT は HOLDER_BIND_MISMATCH（3012）', () => {
    const otherSigner = createPrivateKeySigner(ED_OTHER_HOLDER_SEED, 'EdDSA');
    const bound = addKeyBinding(presentEd(), otherSigner, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expect(() =>
      verifySdJwt(bound, { issuerKey: ED.issuerJwk, audience: AUD, nonce: NONCE }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('sd_hash 改竄（Disclosure 後付け）は HOLDER_BIND_MISMATCH（3012）', () => {
    const full = issueSdJwt(ED.issuerSigner, { jwk: ED.holderJwk });
    const bound = addKeyBinding(selectDisclosures(full, ['name']), ED.holderSigner, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    // KB-JWT はそのままに提示部へ別 Disclosure を挿し込み、sd_hash を崩す。
    const email = parseSdJwt(full).disclosures.find((d) => d.claimName === 'email');
    const kbStart = bound.lastIndexOf('~') + 1;
    const injected = `${bound.slice(0, kbStart)}${email?.encoded}~${bound.slice(kbStart)}`;
    expect(() =>
      verifySdJwt(injected, { issuerKey: ED.issuerJwk, audience: AUD, nonce: NONCE }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('nonce 不一致は HOLDER_BIND_MISMATCH（3012）', () => {
    const bound = addKeyBinding(presentEd(), ED.holderSigner, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expect(() =>
      verifySdJwt(bound, { issuerKey: ED.issuerJwk, audience: AUD, nonce: 'wrong-nonce' }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });
});
