/**
 * `receiveVerifiedPID` / `receiveVerifiedEAA`（`wallet/eudi/verified-receive.ts`）の回帰テスト。
 *
 * `Wallet` ファサードを使わず自前の保持ストアを持つ拡張機能は、低レベルの `receivePIDCredential` /
 * `receiveEAACredential`（Issuer 署名を検証しない）を直接呼んでいた。署名検証つきの受領を共有関数として
 * 切り出したので、その fail-closed 契約を `EudiFacade` を介さずに固定する。
 *
 * - `iss` は正規 Issuer（Catalogue の `issuerAllowList` に載る）のまま、署名だけ攻撃者の鍵で作った
 *   PID / (Q)EAA は `3010`（`received_credential_signature_invalid`）で拒否され、**値を返さない**
 *   （= 呼び出し側は保持しようがない）。
 * - 正規 Issuer が署名した VC は受領できる（ポジティブコントロール）。
 */

import { describe, expect, it } from 'bun:test';
import { buildReceivedIssuerTrust, type FetchLike } from '../../../exports/eudi.js';
import {
  type ReceiveDeps,
  receiveVerifiedEAA,
  receiveVerifiedPID,
} from '../../../exports/experimental/eudi.js';
import { createPrivateKeySigner } from '../../../internal/credential/vc/signer.js';
import { createRecordCatalogueSource, PID_VCT } from '../../../internal/eudi/pid/index.js';
import { MethodJwk } from '../../../internal/identity/jwk/method-jwk.js';
import { Resolver } from '../../../internal/identity/resolver.js';
import { failureOf } from '../failure.fixtures.js';
import {
  buildSdJwtVcWith,
  CATALOGUE_ENTRY,
  CREDENTIAL_URL,
  createStub,
  EAA_CLAIMS,
  EAA_VCT,
  FORGED_ISSUER_PRIVATE_KEY,
  ISSUER_DID,
  NONCE_URL,
  offerURI,
  TOKEN_URL,
  VALID_PID_CLAIMS,
} from './eudi-fixtures.js';

const resolver = new Resolver();
resolver.register(new MethodJwk());
const TRUST = buildReceivedIssuerTrust({}, resolver, undefined);

/** 署名器は Token / Credential Request の Proof JWT にしか使わない（検証対象は受領した VC）。 */
const HOLDER_SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(3), 'ES256');

function receiveDeps(sdJwt: string) {
  return {
    signer: HOLDER_SIGNER,
    holderDid: 'did:key:holder',
    keyId: 'holder-key',
    fetchImpl: createStub(sdJwt).fetchImpl,
  };
}

/** `iss` に `issuerAllowList` の許可 Issuer を詐称させる Catalogue（許可リストだけでは偽造を防げないことを示す）。 */
const CATALOGUE = createRecordCatalogueSource({
  [EAA_VCT]: { ...CATALOGUE_ENTRY, issuerAllowList: [ISSUER_DID] },
});

describe('receiveVerifiedPID / receiveVerifiedEAA', () => {
  it('公開 API は private field を持つ class の fetchImpl で Metadata、Token、Credential を取得する', async () => {
    const stub = createStub(buildSdJwtVcWith({ vct: PID_VCT, claims: VALID_PID_CLAIMS }));
    class PinnedReceiveDeps implements ReceiveDeps {
      readonly signer = HOLDER_SIGNER;
      readonly holderDid = 'did:key:holder';
      readonly keyId = 'holder-key';
      #urls: string[] = [];

      fetchImpl(url: string, init: Parameters<FetchLike>[1]): Promise<Response> {
        this.#urls.push(url);
        return stub.fetchImpl(url, init);
      }

      get urls(): readonly string[] {
        return this.#urls;
      }
    }
    const deps = new PinnedReceiveDeps();

    const pid = await receiveVerifiedPID(offerURI(), deps, TRUST);

    expect(pid.vct).toBe(PID_VCT);
    expect(deps.urls).toEqual(stub.calls.map((call) => call.url));
    expect(deps.urls).toContain(TOKEN_URL);
    expect(deps.urls).toContain(CREDENTIAL_URL);
    expect(deps.urls.length).toBeGreaterThanOrEqual(4);
  });

  it('受領中に fetchImpl の getter を読み直さない', async () => {
    const stub = createStub(buildSdJwtVcWith({ vct: PID_VCT, claims: VALID_PID_CLAIMS }));
    let reads = 0;
    const deps = {
      signer: HOLDER_SIGNER,
      holderDid: 'did:key:holder',
      keyId: 'holder-key',
      get fetchImpl(): FetchLike {
        reads += 1;
        return stub.fetchImpl;
      },
    };

    await receiveVerifiedPID(offerURI(), deps, TRUST);

    expect(reads).toBe(1);
    expect(stub.calls.length).toBeGreaterThanOrEqual(4);
  });

  it('Nonce Endpoint が失敗したら access token を Credential Endpoint へ送らない', async () => {
    const stub = createStub(buildSdJwtVcWith({ vct: PID_VCT, claims: VALID_PID_CLAIMS }));
    const fetchImpl: FetchLike = (url, init) =>
      url === NONCE_URL
        ? Promise.resolve(new Response('', { status: 503 }))
        : stub.fetchImpl(url, init);

    await expect(
      receiveVerifiedPID(offerURI(), { ...receiveDeps('unused'), fetchImpl }, TRUST),
    ).rejects.toBeDefined();
    expect(stub.calls.some((call) => call.url === TOKEN_URL)).toBe(true);
    expect(stub.calls.some((call) => call.url === CREDENTIAL_URL)).toBe(false);
  });

  it('Proof signer が失敗したら access token を Credential Endpoint へ送らない', async () => {
    const stub = createStub(buildSdJwtVcWith({ vct: PID_VCT, claims: VALID_PID_CLAIMS }));
    const signer = {
      ...HOLDER_SIGNER,
      sign: () => {
        throw new Error('sign failed');
      },
    };

    await expect(
      receiveVerifiedPID(
        offerURI(),
        { ...receiveDeps('unused'), signer, fetchImpl: stub.fetchImpl },
        TRUST,
      ),
    ).rejects.toBeDefined();
    expect(stub.calls.some((call) => call.url === TOKEN_URL)).toBe(true);
    expect(stub.calls.some((call) => call.url === CREDENTIAL_URL)).toBe(false);
  });

  it('iss が正規 Issuer で署名が攻撃者鍵の PID は 3010(received_credential_signature_invalid) で拒否する', async () => {
    const forged = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      signingKey: FORGED_ISSUER_PRIVATE_KEY,
    });

    expect(
      await failureOf(() => receiveVerifiedPID(offerURI(), receiveDeps(forged), TRUST)),
    ).toEqual({ code: '3010', reason: 'received_credential_signature_invalid' });
  });

  it('許可リスト内の iss を詐称し署名が攻撃者鍵の (Q)EAA は 3010 で拒否する', async () => {
    const forged = buildSdJwtVcWith({
      vct: EAA_VCT,
      claims: EAA_CLAIMS,
      signingKey: FORGED_ISSUER_PRIVATE_KEY,
    });

    expect(
      await failureOf(() =>
        receiveVerifiedEAA(offerURI(EAA_VCT), CATALOGUE, receiveDeps(forged), TRUST),
      ),
    ).toEqual({ code: '3010', reason: 'received_credential_signature_invalid' });
  });

  it('Issuer 鍵を解決できない PID は 3010(issuer_key_unresolved) で拒否する（検証不能を受理に読み替えない）', async () => {
    const unresolvable = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      iss: 'https://issuer.example.eu',
    });

    expect(
      await failureOf(() => receiveVerifiedPID(offerURI(), receiveDeps(unresolvable), TRUST)),
    ).toEqual({ code: '3010', reason: 'issuer_key_unresolved' });
  });

  it('正規 Issuer が署名した PID / (Q)EAA は受領できる', async () => {
    const pid = await receiveVerifiedPID(
      offerURI(),
      receiveDeps(buildSdJwtVcWith({ vct: PID_VCT, claims: VALID_PID_CLAIMS })),
      TRUST,
    );
    const eaa = await receiveVerifiedEAA(
      offerURI(EAA_VCT),
      CATALOGUE,
      receiveDeps(buildSdJwtVcWith({ vct: EAA_VCT, claims: EAA_CLAIMS })),
      TRUST,
    );

    expect(pid.vct).toBe(PID_VCT);
    expect(eaa.vct).toBe(EAA_VCT);
  });
});
