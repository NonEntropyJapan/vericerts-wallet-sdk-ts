/**
 * `Wallet.receiveCredential` が受領した VC を既定で署名検証することの統合テスト。
 *
 * OID4VCI フロー配線のテストは `wallet.receive-credential.test.ts`、`opts.verifyReceived` の読み取り
 * 一貫性の回帰テストは `wallet.receive-credential.verify-received-di.test.ts`
 * に分離している（Linterly の 300 行/ファイル上限）。共有フィクスチャは `receive-credential-fixtures.ts`
 * にある。
 *
 * SD-JWT VC・JWT-VC（`format: 'jwt'`）のどちらも、既定検証は正常系（正しく署名された VC を受理）と
 * 異常系 2 種（署名不正 → `received_credential_signature_invalid`、鍵解決失敗 →
 * `issuer_key_unresolved`。いずれも `3010`）を確認する。
 */

import { describe, expect, it } from 'bun:test';
import {
  CONFIGURATION_ID,
  preAuthorizedOfferURI,
} from '../../../internal/auth/oid4vci/facade/__tests__/facade-fixtures.js';
import { ErrorCodes } from '../../../internal/errors.js';
import {
  buildIssuedFlatJwtVc,
  buildIssuedJwtVc,
  buildIssuedJwtVcWithEnvelopeMismatch,
  buildIssuedSdJwt,
  credentialStub,
  ISSUER_DID_KEY,
  ISSUER_DID_PKH,
  setupWallet,
  tamperIssuerSignature,
  UNRESOLVABLE_ISSUER_DID,
} from './receive-credential-fixtures.js';

describe('Wallet.receiveCredential（既定の署名検証）', () => {
  it('did:key Issuer の正しく署名された SD-JWT VC は既定検証を通って受領できる', async () => {
    const stub = credentialStub(buildIssuedSdJwt(ISSUER_DID_KEY));
    const wallet = await setupWallet();

    // `opts.verifyReceived` を渡さない = 既定検証が走る経路。
    const vc = await wallet.receiveCredential(preAuthorizedOfferURI(), {
      fetchImpl: stub.fetchImpl,
    });

    expect(vc.issuer).toBe(ISSUER_DID_KEY);
    expect(vc.format).toBe('sd-jwt');
    expect(vc.claims.degree).toBe('Laurea');
  });

  it('署名を改竄した SD-JWT VC は 3010（received_credential_signature_invalid）で拒否する', async () => {
    // DID は解決できる（鍵は得られる）が署名が一致しないケース。鍵解決失敗とは理由を分ける。
    const stub = credentialStub(tamperIssuerSignature(buildIssuedSdJwt(ISSUER_DID_KEY)));
    const wallet = await setupWallet();

    await expect(
      wallet.receiveCredential(preAuthorizedOfferURI(), { fetchImpl: stub.fetchImpl }),
    ).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
      context: { reason: 'received_credential_signature_invalid' },
    });
  });

  it('JWK を持たない Issuer（did:pkh）は 3010（issuer_key_unresolved）で fail-closed する', async () => {
    const stub = credentialStub(buildIssuedSdJwt(ISSUER_DID_PKH));
    const wallet = await setupWallet();

    await expect(
      wallet.receiveCredential(preAuthorizedOfferURI(), { fetchImpl: stub.fetchImpl }),
    ).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
      context: { reason: 'issuer_key_unresolved' },
    });
  });

  it('DID 解決失敗（未対応メソッド）は 3010（issuer_key_unresolved）へ正規化する', async () => {
    const stub = credentialStub(buildIssuedSdJwt(UNRESOLVABLE_ISSUER_DID));
    const wallet = await setupWallet();

    await expect(
      wallet.receiveCredential(preAuthorizedOfferURI(), { fetchImpl: stub.fetchImpl }),
    ).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
      context: { reason: 'issuer_key_unresolved' },
    });
  });

  it('opts.verifyReceived は既定検証を置換する（併用しないため no-op で受領できる）', async () => {
    // 直前のテストと同じ「Issuer 鍵が解決できない」VC。既定検証が併用されていれば 3010 になる。
    const stub = credentialStub(buildIssuedSdJwt(UNRESOLVABLE_ISSUER_DID));
    const wallet = await setupWallet();

    const vc = await wallet.receiveCredential(preAuthorizedOfferURI(), {
      fetchImpl: stub.fetchImpl,
      verifyReceived: () => {},
    });

    expect(vc.issuer).toBe(UNRESOLVABLE_ISSUER_DID);
  });
});

describe('Wallet.receiveCredential（JWT-VC 経路の既定検証）', () => {
  it('did:key Issuer の正しく署名された JWT-VC は既定検証を通って受領できる', async () => {
    const stub = credentialStub(buildIssuedJwtVc(ISSUER_DID_KEY));
    const wallet = await setupWallet();

    // `opts.verifyReceived` を渡さない = 既定検証（`resolveIssuerVerifierKey` + `verifyCredential`）
    // が走る経路。
    const vc = await wallet.receiveCredential(preAuthorizedOfferURI(), {
      fetchImpl: stub.fetchImpl,
    });

    expect(vc.issuer).toBe(ISSUER_DID_KEY);
    expect(vc.format).toBe('jwt');
    expect(vc.claims.degree).toBe('Laurea');
  });

  it('署名を改竄した JWT-VC は 3010（received_credential_signature_invalid）で拒否する', async () => {
    // DID は解決できる（鍵は得られる）が署名が一致しないケース。鍵解決失敗とは理由を分ける。
    const stub = credentialStub(tamperIssuerSignature(buildIssuedJwtVc(ISSUER_DID_KEY)));
    const wallet = await setupWallet();

    await expect(
      wallet.receiveCredential(preAuthorizedOfferURI(), { fetchImpl: stub.fetchImpl }),
    ).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
      context: { reason: 'received_credential_signature_invalid' },
    });
  });

  it('DID 解決失敗（未対応メソッド）の JWT-VC は 3010（issuer_key_unresolved）へ正規化する', async () => {
    const stub = credentialStub(buildIssuedJwtVc(UNRESOLVABLE_ISSUER_DID));
    const wallet = await setupWallet();

    await expect(
      wallet.receiveCredential(preAuthorizedOfferURI(), { fetchImpl: stub.fetchImpl }),
    ).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
      context: { reason: 'issuer_key_unresolved' },
    });
  });
});

describe('Wallet.receiveCredential（VC 2.0 形の JWT-VC を既定検証で受領）', () => {
  it('vc で包まない JWT-VC（validFrom / validUntil）は既定検証を通って受領できる（8020 / 3010 にならない）', async () => {
    const stub = credentialStub(buildIssuedFlatJwtVc(ISSUER_DID_KEY));
    const wallet = await setupWallet();

    const vc = await wallet.receiveCredential(preAuthorizedOfferURI(), {
      fetchImpl: stub.fetchImpl,
    });

    expect(vc.format).toBe('jwt');
    expect(vc.issuer).toBe(ISSUER_DID_KEY);
    expect(vc.type).toEqual(['VerifiableCredential', CONFIGURATION_ID]);
    expect(vc.id).toBe('urn:uuid:3925-flat');
    expect(vc.claims.degree).toBe('Laurea');
  });

  it('署名を改竄した vc 非包みの JWT-VC は 3010（received_credential_signature_invalid）で拒否する', async () => {
    const stub = credentialStub(tamperIssuerSignature(buildIssuedFlatJwtVc(ISSUER_DID_KEY)));
    const wallet = await setupWallet();

    await expect(
      wallet.receiveCredential(preAuthorizedOfferURI(), { fetchImpl: stub.fetchImpl }),
    ).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
      context: { reason: 'received_credential_signature_invalid' },
    });
  });
});

describe('Wallet.receiveCredential（既定検証の失敗コードを 3010 に潰さない）', () => {
  it('署名は正しいが envelope と body が食い違う JWT-VC は元の 3002 を返す（3010 にしない）', async () => {
    const stub = credentialStub(buildIssuedJwtVcWithEnvelopeMismatch(ISSUER_DID_KEY));
    const wallet = await setupWallet();

    await expect(
      wallet.receiveCredential(preAuthorizedOfferURI(), { fetchImpl: stub.fetchImpl }),
    ).rejects.toMatchObject({ code: ErrorCodes.VC_SCHEMA_INVALID });
  });
});
