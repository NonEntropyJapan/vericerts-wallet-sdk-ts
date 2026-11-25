/**
 * `x5c` による Issuer 鍵解決の回帰テスト。
 *
 * 以前の既定検証は `iss` を DID として解決する経路しか持たず、ARF / SD-JWT VC の PID
 * Provider（`iss` が HTTPS URL）は常に `3010`（`issuer_key_unresolved`）で拒否されていた。
 * ここで固定する契約は次の 4 点である。
 *
 * - `x5c` が `createWallet({ issuerTrustAnchors })` へ連鎖し SAN が `iss` と一致すれば、
 *   `opts.verifyReceived` 無しで受領できる。
 * - Trust Anchor 未設定・不一致・非 granted はいずれも fail-closed（`3010`）。素通りさせない。
 * - 同じ Trust Anchor 配下でも `iss` と SubjectAltName が食い違う証明書は受理しない
 *   （= 正当な証明書保持者による他 Issuer のなりすましを塞ぐ）。
 * - `x5c` がある以上、その検証失敗を DID 解決へフォールバックさせない。
 *
 * ネットワークは `eudiFetchImpl` の注入のみで再現し、グローバル `fetch` は差し替えない。
 */

import { describe, expect, it, mock } from 'bun:test';
import { buildReceivedIssuerTrust, type DidResolverLike } from '../../../exports/eudi.js';
import { receiveVerifiedPID } from '../../../exports/experimental/eudi.js';
import { receiveDeps } from '../../../internal/auth/eudi/issuance/__tests__/issuance-fixtures.js';
import { createRecordCatalogueSource, PID_VCT } from '../../../internal/eudi/pid/index.js';
import type { QtspServiceCertificate } from '../../../internal/trust/etsi-tsl/index.js';
import { failureOf } from '../failure.fixtures.js';
import {
  buildSdJwtVcWith,
  CATALOGUE_ENTRY,
  createStub,
  EAA_CLAIMS,
  EAA_VCT,
  offerURI,
  setupWallet,
  VALID_PID_CLAIMS,
} from './eudi-fixtures.js';
import { type IssuerChainOverrides, makeIssuerChain, X5C_ISSUER } from './x5c-fixtures.js';

/** `x5c` 付き PID を返す Issuer と、Trust Anchor を設定した Wallet を用意する。 */
async function x5cPidWallet(
  chainOverrides: IssuerChainOverrides = {},
  anchorsOverride?: readonly QtspServiceCertificate[],
): Promise<Awaited<ReturnType<typeof setupWallet>>> {
  const chain = makeIssuerChain(chainOverrides);
  const sdJwt = buildSdJwtVcWith({
    vct: PID_VCT,
    claims: VALID_PID_CLAIMS,
    iss: X5C_ISSUER,
    signingKey: chain.signingKey,
    x5c: chain.x5c,
  });
  return setupWallet({
    eudiFetchImpl: createStub(sdJwt).fetchImpl,
    issuerTrustAnchors: anchorsOverride ?? chain.anchors,
  });
}

describe('受領した SD-JWT VC の Issuer 鍵を x5c から解決する', () => {
  it('HTTPS iss の PID を opts.verifyReceived 無しで受領できる', async () => {
    const wallet = await x5cPidWallet();

    const pid = await wallet.receivePID(offerURI());

    expect(pid.claims.family_name).toBe('Bianchi');
  });

  it('issuerTrustAnchors 未設定は素通りせず 3010(issuer_key_unresolved)', async () => {
    // 「設定漏れ」を「検証済み」に読み替えない（`rpTrustAnchors` 未設定の 8030 と同じ方針）。
    const wallet = await x5cPidWallet({}, []);

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('公開 receiveVerifiedPID は不正な x5c から DID 解決へフォールバックしない', async () => {
    const chain = makeIssuerChain();
    const sdJwt = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      iss: X5C_ISSUER,
      signingKey: chain.signingKey,
      x5c: chain.x5c,
    });
    const resolve = mock(async () => ({ id: X5C_ISSUER }));
    const resolver = { resolve } as unknown as DidResolverLike;
    const trust = buildReceivedIssuerTrust({ issuerTrustAnchors: [] }, resolver, undefined);

    expect(
      await failureOf(() =>
        receiveVerifiedPID(offerURI(), receiveDeps(createStub(sdJwt).fetchImpl), trust),
      ),
    ).toEqual({ code: '3010', reason: 'issuer_key_unresolved' });
    expect(resolve).toHaveBeenCalledTimes(0);
  });

  it('Trust Anchor 不一致（別 CA のアンカー）は 3010(issuer_key_unresolved)', async () => {
    // VC の x5c は自分の CA へ連鎖するが、Wallet に設定されたアンカーは無関係な別 CA である。
    const unrelated = makeIssuerChain();
    const wallet = await x5cPidWallet({}, unrelated.anchors);

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('granted でない Trust Anchor は信頼の起点にしない（3010）', async () => {
    // `extractQtspCertificates` は withdrawn のサービス証明書も返す。granted だけを採る。
    const wallet = await x5cPidWallet({ granted: false });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('SAN が iss と一致しない証明書は受理しない（同一 CA 配下のなりすまし）', async () => {
    // チェーン自体は Trust Anchor へ到達するが、証明書が主張する識別子は別ホストである。
    const wallet = await x5cPidWallet({ san: 'https://other-provider.example.eu' });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('SD-JWT の Issuer 署名に使えない鍵種別（RSA leaf）は 3010', async () => {
    // SPKI → JWK 変換は P-256 のみ。変換できない鍵を「解決できた」に読み替えない。
    const wallet = await x5cPidWallet({ kind: 'rsa' });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('x5c は正しいが署名が別鍵の PID は 3010(received_credential_signature_invalid)', async () => {
    // 鍵解決（x5c）と照合（署名）を分けている契約を固定する。
    const chain = makeIssuerChain();
    const forged = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      iss: X5C_ISSUER,
      signingKey: makeIssuerChain().signingKey,
      x5c: chain.x5c,
    });
    const wallet = await setupWallet({
      eudiFetchImpl: createStub(forged).fetchImpl,
      issuerTrustAnchors: chain.anchors,
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'received_credential_signature_invalid',
    });
  });

  it('(Q)EAA 受領経路にも同じ x5c 解決が効く', async () => {
    const chain = makeIssuerChain();
    const sdJwt = buildSdJwtVcWith({
      vct: EAA_VCT,
      claims: EAA_CLAIMS,
      iss: X5C_ISSUER,
      signingKey: chain.signingKey,
      x5c: chain.x5c,
    });
    const wallet = await setupWallet({
      eudiFetchImpl: createStub(sdJwt).fetchImpl,
      eudiCatalogue: createRecordCatalogueSource({ [EAA_VCT]: CATALOGUE_ENTRY }),
      issuerTrustAnchors: chain.anchors,
    });

    const eaa = await wallet.receiveEAA(offerURI(EAA_VCT));

    expect(eaa.claims.degree).toBe('Laurea Magistrale');
  });
});

describe('wallet.receiveCredential も同じ x5c 解決を使う', () => {
  it('issuerTrustAnchors は PID の受領に加えて receiveCredential の既定検証にも伝播する', async () => {
    // 規則は共通モジュール（`wallet/issuer-trust/`）だが、Trust Anchor の配線は経路ごとに別である。
    // 片方だけ配線が抜けると、同じ VC が受領経路によって通ったり落ちたりする。
    const chain = makeIssuerChain();
    const sdJwt = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      iss: X5C_ISSUER,
      signingKey: chain.signingKey,
      x5c: chain.x5c,
    });
    const stub = createStub(sdJwt);
    const wallet = await setupWallet({ issuerTrustAnchors: chain.anchors });

    const received = await wallet.receiveCredential(offerURI(), { fetchImpl: stub.fetchImpl });

    expect(received.claims.family_name).toBe('Bianchi');
  });
});
