/**
 * `receivePID` / `receiveEAA` の既定 Issuer 署名検証の回帰テスト。
 *
 * `wallet.receiveCredential` の既定検証を EUDI 受領経路へも対称化した件の
 * 契約を固定する。
 *
 * - 署名が一致しない PID / (Q)EAA は既定で `3010`（`received_credential_signature_invalid`）。
 * - Issuer 鍵を解決できない（`iss` が DID でない）PID は `3010`（`issuer_key_unresolved`）で
 *   fail-closed。
 * - 検証に失敗した PID / (Q)EAA はセッションに保持されない（後続の提示に回らない）。
 * - `opts.verifyReceived` は既定検証を**置換**する（併用しない）。
 * - `opts.verifyReceived` が throw すれば `3010` へ正規化される。
 * - `Object.prototype.verifyReceived` の汚染は「指定された」とみなさない（既定検証が走り続ける）。
 *
 * ネットワークは `eudiFetchImpl` の注入のみで再現し、グローバル `fetch` は差し替えない。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { createRecordCatalogueSource, PID_VCT } from '../../../internal/eudi/pid/index.js';
import { failureOf } from '../failure.fixtures.js';
import {
  buildSdJwtVc,
  buildSdJwtVcWith,
  CATALOGUE_ENTRY,
  createStub,
  EAA_CLAIMS,
  EAA_VCT,
  FORGED_ISSUER_PRIVATE_KEY,
  ISSUER,
  offerURI,
  requestURI,
  setupWallet,
  VALID_PID_CLAIMS,
} from './eudi-fixtures.js';

/** Catalogue を設定した Wallet（(Q)EAA を受領できる状態）を用意する。 */
function eaaWallet(sdJwt: string): ReturnType<typeof setupWallet> {
  return setupWallet({
    eudiFetchImpl: createStub(sdJwt).fetchImpl,
    eudiCatalogue: createRecordCatalogueSource({ [EAA_VCT]: CATALOGUE_ENTRY }),
  });
}

describe('receivePID / receiveEAA の既定 Issuer 署名検証', () => {
  it('署名が一致しない PID は既定で 3010(received_credential_signature_invalid)', async () => {
    // `iss` は正規 Issuer の DID のまま、署名だけ攻撃者の鍵で作る。
    const forged = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      signingKey: FORGED_ISSUER_PRIVATE_KEY,
    });
    const wallet = await setupWallet({ eudiFetchImpl: createStub(forged).fetchImpl });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'received_credential_signature_invalid',
    });
  });

  it('署名が一致しない (Q)EAA は既定で 3010(received_credential_signature_invalid)', async () => {
    const forged = buildSdJwtVcWith({
      vct: EAA_VCT,
      claims: EAA_CLAIMS,
      signingKey: FORGED_ISSUER_PRIVATE_KEY,
    });
    const wallet = await eaaWallet(forged);

    expect(await failureOf(() => wallet.receiveEAA(offerURI(EAA_VCT)))).toEqual({
      code: '3010',
      reason: 'received_credential_signature_invalid',
    });
  });

  it('Issuer 鍵を解決できない（iss が DID でない）PID は 3010(issuer_key_unresolved)', async () => {
    // ARF の SD-JWT VC は `iss` に HTTPS URL を載せる。現在、SDK は DID 解決に加えて
    // `x5c` 経路と JWT VC Issuer Metadata 経路を持つが、この wallet は `issuerTrustAnchors` も
    // `jwtVcIssuerMetadataResolution` も設定していない（= この VC も `x5c` を持たない）ため、
    // どの経路にも信頼素材が無い。検証できないものを「検証済み」に読み替えず fail-closed に落とす。
    const httpsIssuer = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      iss: ISSUER,
    });
    const wallet = await setupWallet({ eudiFetchImpl: createStub(httpsIssuer).fetchImpl });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('検証に失敗した PID は保持されず、後続の presentPID は 8035', async () => {
    const forged = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      signingKey: FORGED_ISSUER_PRIVATE_KEY,
    });
    const stub = createStub(forged);
    const wallet = await setupWallet({ eudiFetchImpl: stub.fetchImpl });

    await failureOf(() => wallet.receivePID(offerURI()));
    // 保持していれば 8035 ではなく提示が成立してしまう（偽 PID が Verifier へ渡る）。
    expect((await failureOf(() => wallet.presentPID(requestURI(), ['family_name']))).code).toBe(
      '8035',
    );
  });

  it('検証に失敗した (Q)EAA は保持されず、後続の presentEAA は 8035', async () => {
    const forged = buildSdJwtVcWith({
      vct: EAA_VCT,
      claims: EAA_CLAIMS,
      signingKey: FORGED_ISSUER_PRIVATE_KEY,
    });
    const wallet = await eaaWallet(forged);

    await failureOf(() => wallet.receiveEAA(offerURI(EAA_VCT)));
    expect((await failureOf(() => wallet.presentEAA(requestURI(), EAA_VCT))).code).toBe('8035');
  });

  it('opts.verifyReceived は既定検証を置換する（DID 以外の鍵解決へ道を残す）', async () => {
    const httpsIssuer = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      iss: ISSUER,
    });
    const wallet = await setupWallet({ eudiFetchImpl: createStub(httpsIssuer).fetchImpl });

    const seen: string[] = [];
    const pid = await wallet.receivePID(offerURI(), {
      verifyReceived: (raw) => {
        seen.push(raw);
      },
    });

    // 既定検証（DID 解決）は走らないので、HTTPS `iss` でも受領できる。
    expect(pid.vct).toBe(PID_VCT);
    expect(seen).toEqual([httpsIssuer]);
  });

  it('opts.verifyReceived は receiveEAA でも既定検証を置換する', async () => {
    const httpsIssuer = buildSdJwtVcWith({ vct: EAA_VCT, claims: EAA_CLAIMS, iss: ISSUER });
    const wallet = await eaaWallet(httpsIssuer);

    const eaa = await wallet.receiveEAA(offerURI(EAA_VCT), { verifyReceived: () => {} });
    expect(eaa.vct).toBe(EAA_VCT);
  });

  it('opts.verifyReceived の throw は 3010(received_credential_signature_invalid) へ正規化される', async () => {
    const wallet = await setupWallet({
      eudiFetchImpl: createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS)).fetchImpl,
    });

    const failure = await failureOf(() =>
      wallet.receivePID(offerURI(), {
        verifyReceived: () => {
          throw new Error('trust anchor mismatch');
        },
      }),
    );
    expect(failure).toEqual({
      code: '3010',
      reason: 'received_credential_signature_invalid',
    });
  });

  it('opts.verifyReceived が VericertsError（3010 以外）を投げたら、そのコードを潰さず返す', async () => {
    const wallet = await setupWallet({
      eudiFetchImpl: createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS)).fetchImpl,
    });

    const failure = await failureOf(() =>
      wallet.receivePID(offerURI(), {
        verifyReceived: () => {
          throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
        },
      }),
    );
    expect(failure).toEqual({ code: ErrorCodes.VC_SCHEMA_INVALID, reason: undefined });
  });

  it('既定検証で署名は正しいが期限切れの PID は、元の 3024 を返す（3010 にしない）', async () => {
    const expired = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      exp: 1_767_000_100,
    });
    const wallet = await setupWallet({ eudiFetchImpl: createStub(expired).fetchImpl });

    const failure = await failureOf(() => wallet.receivePID(offerURI()));
    expect(failure).toEqual({ code: ErrorCodes.VC_EXPIRED, reason: undefined });
  });
});

describe('verifyReceived のプロトタイプ汚染耐性', () => {
  afterEach(() => {
    delete (Object.prototype as Record<string, unknown>).verifyReceived;
  });

  it('Object.prototype.verifyReceived の汚染では既定検証を置換しない', async () => {
    // 汚染を「指定された検証フック」とみなすと、偽署名の PID が no-op 検証で受理される。
    (Object.prototype as Record<string, unknown>).verifyReceived = (): void => {};
    const forged = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      signingKey: FORGED_ISSUER_PRIVATE_KEY,
    });
    const wallet = await setupWallet({ eudiFetchImpl: createStub(forged).fetchImpl });

    expect(await failureOf(() => wallet.receivePID(offerURI(), {}))).toEqual({
      code: '3010',
      reason: 'received_credential_signature_invalid',
    });
  });
});
