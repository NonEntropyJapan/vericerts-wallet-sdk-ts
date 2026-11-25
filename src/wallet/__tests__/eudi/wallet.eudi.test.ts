/**
 * Wallet ファサードの EUDI PID / (Q)EAA API統合テスト。
 *
 * `createWallet` 経由（実 storage / 実鍵 / アクティブペルソナ）で、`receivePID` / `presentPID` /
 * `receiveEAA` / `presentEAA` が内部プリミティブへ正しく委譲され、セッション内の受領済み
 * Credential を介して受領 → 提示がつながることを検証する。
 * - receivePID が PID を保持し、続く presentPID がその PID を提示する（保持の疎通）。
 * - presentPID は `opts.credential` を保持済み PID より優先する。
 * - 保持済み PID も `opts.credential` も無い presentPID → PRESENTATION_SUBMIT_FAILED(8035)。
 * - 既定（Catalogue 未設定）の receiveEAA → EAA_CATALOGUE_NOT_FOUND(10003)。
 * - Catalogue 設定時の receiveEAA は成功し、presentEAA が vct で見つけて提示する。
 * - `walletAttestation: true` で現行 WUA 未保持 → WUA_FETCH_FAILED(10101)。
 * - アクティブペルソナ未設定の receivePID → PERSONA_NOT_FOUND(2005)。
 *
 * ネットワークは `eudiFetchImpl` の注入のみで再現し、グローバル `fetch` は差し替えない。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../../internal/errors.js';
import type { PIDClaims, PIDCredential } from '../../../internal/eudi/pid/index.js';
import { createRecordCatalogueSource, PID_VCT } from '../../../internal/eudi/pid/index.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import {
  buildSdJwtVc,
  CATALOGUE_ENTRY,
  CREDENTIAL_URL,
  createStub,
  EAA_CLAIMS,
  EAA_VCT,
  ISSUER,
  METADATA_URL,
  NONCE_URL,
  offerURI,
  RESPONSE_URI,
  requestURI,
  setupWallet,
  submittedVpToken,
  TOKEN_URL,
  VALID_PID_CLAIMS,
} from './eudi-fixtures.js';

/** 投げられた VericertsError のコードを取り出す（投げなければ失敗させる）。 */
async function codeOf(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    return (e as VericertsError).code;
  }
  throw new Error('should throw');
}

describe('Wallet EUDI receivePID / presentPID', () => {
  it('receivePID は PID を受領して保持し、presentPID がその PID を提示する', async () => {
    const sdJwt = buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS);
    const stub = createStub(sdJwt);
    const wallet = await setupWallet({ eudiFetchImpl: stub.fetchImpl });

    const pid = await wallet.receivePID(offerURI());
    expect(pid.vct).toBe(PID_VCT);
    expect(pid.raw).toBe(sdJwt);
    expect(pid.claims.family_name).toBe('Bianchi');
    // Issuer Metadata → AS Metadata（Token Endpoint の解決。ここでは 404 で Issuer の token_endpoint へ
    // フォールバック）→ Token → Nonce Endpoint→ Credential の順に通信する。
    expect(stub.calls.map((call) => call.url)).toEqual([
      METADATA_URL,
      `${ISSUER}/.well-known/oauth-authorization-server`,
      TOKEN_URL,
      NONCE_URL,
      CREDENTIAL_URL,
    ]);

    const vp = await wallet.presentPID(requestURI(), ['family_name', 'given_name']);
    // holder は署名鍵の kid（did:key#fragment）から導出した DID。
    expect(vp.holder.startsWith('did:key:')).toBe(true);
    expect(vp.holder.includes('#')).toBe(false);
    // 提示は保持済み PID の SD-JWT を土台にする（Issuer 署名部が一致する）。
    const submitted = stub.calls.find((call) => call.url === RESPONSE_URI);
    const vpToken = submittedVpToken(submitted);
    expect(vpToken.startsWith(sdJwt.split('~')[0] ?? '')).toBe(true);
    // 開示したのは 2 属性 + KB-JWT（`<issuerJwt>~<d1>~<d2>~<kbJwt>`）。
    expect(vpToken.split('~')).toHaveLength(4);
  });

  it('presentPID は opts.credential を保持済み PID より優先する', async () => {
    const stored = buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS);
    const stub = createStub(stored);
    const wallet = await setupWallet({ eudiFetchImpl: stub.fetchImpl });
    await wallet.receivePID(offerURI());

    const otherClaims = { ...VALID_PID_CLAIMS, family_name: 'Rossi' };
    const otherRaw = buildSdJwtVc(PID_VCT, otherClaims);
    const explicit: PIDCredential = {
      vct: PID_VCT,
      claims: otherClaims as PIDClaims,
      raw: otherRaw,
    };
    await wallet.presentPID(requestURI(), ['family_name'], { credential: explicit });

    const submitted = stub.calls.find((call) => call.url === RESPONSE_URI);
    const vpToken = submittedVpToken(submitted);
    expect(vpToken.startsWith(otherRaw.split('~')[0] ?? '')).toBe(true);
    expect(vpToken.startsWith(stored.split('~')[0] ?? '')).toBe(false);
  });

  it('保持済み PID も opts.credential も無い presentPID は PRESENTATION_SUBMIT_FAILED(8035)', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const wallet = await setupWallet({ eudiFetchImpl: stub.fetchImpl });

    expect(await codeOf(() => wallet.presentPID(requestURI(), ['family_name']))).toBe('8035');
    // 提示対象が決まらないので通信は一切発生しない。
    expect(stub.calls).toHaveLength(0);
  });

  it('アクティブペルソナ未設定の receivePID は PERSONA_NOT_FOUND(2005)', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const wallet = await createWallet({
      storage: new MemoryStorage(),
      eudiFetchImpl: stub.fetchImpl,
    });
    await wallet.importMnemonic(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    );

    expect(await codeOf(() => wallet.receivePID(offerURI()))).toBe('2005');
    expect(stub.calls).toHaveLength(0);
  });
});

describe('Wallet EUDI receiveEAA / presentEAA', () => {
  it('Catalogue 未設定（既定の空 Catalogue）の receiveEAA は EAA_CATALOGUE_NOT_FOUND(10003)', async () => {
    const stub = createStub(buildSdJwtVc(EAA_VCT, EAA_CLAIMS));
    const wallet = await setupWallet({ eudiFetchImpl: stub.fetchImpl });

    expect(await codeOf(() => wallet.receiveEAA(offerURI(EAA_VCT)))).toBe('10003');
  });

  it('Catalogue 設定時の receiveEAA は成功し、presentEAA が vct で見つけて提示する', async () => {
    const sdJwt = buildSdJwtVc(EAA_VCT, EAA_CLAIMS);
    const stub = createStub(sdJwt);
    const wallet = await setupWallet({
      eudiFetchImpl: stub.fetchImpl,
      eudiCatalogue: createRecordCatalogueSource({ [EAA_VCT]: CATALOGUE_ENTRY }),
    });

    const eaa = await wallet.receiveEAA(offerURI(EAA_VCT));
    expect(eaa.vct).toBe(EAA_VCT);
    expect(eaa.claims.degree).toBe('Laurea Magistrale');

    const vp = await wallet.presentEAA(requestURI(), EAA_VCT);
    expect(vp.verifiableCredential).toHaveLength(1);
    const submitted = stub.calls.find((call) => call.url === RESPONSE_URI);
    expect(submittedVpToken(submitted).startsWith(sdJwt.split('~')[0] ?? '')).toBe(true);
  });

  it('保持していない vct の presentEAA は PRESENTATION_SUBMIT_FAILED(8035)', async () => {
    const stub = createStub(buildSdJwtVc(EAA_VCT, EAA_CLAIMS));
    const wallet = await setupWallet({
      eudiFetchImpl: stub.fetchImpl,
      eudiCatalogue: createRecordCatalogueSource({ [EAA_VCT]: CATALOGUE_ENTRY }),
    });
    await wallet.receiveEAA(offerURI(EAA_VCT));

    expect(await codeOf(() => wallet.presentEAA(requestURI(), 'urn:eudi:eaa:other:1'))).toBe(
      '8035',
    );
  });
});

describe('Wallet EUDI Wallet Attestation 添付', () => {
  it('現行 WUA を保持しない walletAttestation: true は WUA_FETCH_FAILED(10101)', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const wallet = await setupWallet({ eudiFetchImpl: stub.fetchImpl });

    expect(await codeOf(() => wallet.receivePID(offerURI(), { walletAttestation: true }))).toBe(
      '10101',
    );
    // WUA 不在は通信前に判定する（access_token を取りに行かない）。
    expect(stub.calls).toHaveLength(0);
  });

  it('walletAttestation を省略した受領は client_assertion を送らない', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const wallet = await setupWallet({ eudiFetchImpl: stub.fetchImpl });

    await wallet.receivePID(offerURI());
    const tokenCall = stub.calls.find((call) => call.url === TOKEN_URL);
    const params = new URLSearchParams(tokenCall?.body ?? '');
    expect(params.has('client_assertion')).toBe(false);
  });
});
