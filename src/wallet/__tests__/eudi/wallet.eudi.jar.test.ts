/**
 * Wallet ファサード（`presentPID` / `presentEAA`）の `request_uri` 参照形式（JAR）対応の
 * 回帰テスト。
 *
 * `createWallet` 経由（実 storage / 実鍵 / アクティブペルソナ）で、HAIP §5.1 が必須とする
 * 参照形式の提示要求が **ファサードから** 処理できることを固定する。内部プリミティブ側の回帰は
 * `internal/auth/eudi/presentation/__tests__/present.jar.test.ts` が担い、ここでは
 * `createWallet({ rpTrustAnchors, eudiFetchImpl })` の 2 つのオプションが提示経路の JAR 取得と
 * 署名検証まで**伝播していること**を確認する。
 *
 * ネットワークは `eudiFetchImpl` の注入のみで再現し、グローバル `fetch` は差し替えない。
 */

import { describe, expect, it } from 'bun:test';
import {
  jarClaims,
  makeJarSigner,
  signJar,
} from '../../../internal/auth/jar/__tests__/jar-fixtures.js';
import { ErrorCodes, type VericertsError } from '../../../internal/errors.js';
import { createRecordCatalogueSource, PID_VCT } from '../../../internal/eudi/pid/index.js';
import {
  buildSdJwtVc,
  CATALOGUE_ENTRY,
  createStub,
  EAA_CLAIMS,
  EAA_VCT,
  offerURI,
  RESPONSE_URI,
  setupWallet,
  submittedVpToken,
  VALID_PID_CLAIMS,
  VERIFIER_CLIENT_ID,
} from './eudi-fixtures.js';

/** JAR を置く `request_uri`（`client_id` と同一オリジン）。 */
const JAR_REQUEST_URI = `${VERIFIER_CLIENT_ID}/request/xyz`;

/** 参照形式の提示要求 URI（`request_uri` 単独形式）。 */
const REFERENCE_REQUEST_URI = `openid4vp://?request_uri=${encodeURIComponent(JAR_REQUEST_URI)}`;

/** 提示フィクスチャの Verifier ドメインで署名できる RP Access Certificate 一式。 */
const VERIFIER = makeJarSigner({ origin: VERIFIER_CLIENT_ID });

/** Trust Anchor へ連鎖する RP 証明書鍵で署名した Request Object。 */
const SIGNED_JAR = signJar(VERIFIER, {
  claims: jarClaims({
    iss: VERIFIER_CLIENT_ID,
    client_id: VERIFIER_CLIENT_ID,
    response_uri: RESPONSE_URI,
  }),
});

/** JAR を返す追加ルート。 */
function jarRoute(jwt: string): Readonly<Record<string, () => Response>> {
  return {
    [JAR_REQUEST_URI]: () =>
      new Response(jwt, {
        status: 200,
        headers: { 'Content-Type': 'application/oauth-authz-req+jwt' },
      }),
  };
}

async function codeAndReasonOf(
  run: () => Promise<unknown>,
): Promise<{ code: string; reason: unknown }> {
  try {
    await run();
    throw new Error('should have thrown');
  } catch (err) {
    const error = err as VericertsError;
    const context = error.context as Record<string, unknown> | undefined;
    return { code: error.code, reason: context?.reason };
  }
}

describe('Wallet EUDI: request_uri 参照形式の提示', () => {
  it('rpTrustAnchors を設定すれば presentPID が参照形式を処理する', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS), jarRoute(SIGNED_JAR));
    const wallet = await setupWallet({
      eudiFetchImpl: stub.fetchImpl,
      rpTrustAnchors: VERIFIER.anchors,
    });
    await wallet.receivePID(offerURI());

    const vp = await wallet.presentPID(REFERENCE_REQUEST_URI, ['family_name', 'given_name']);

    // 注入した fetch で `request_uri` を GET し、Request Object の `response_uri` へ送信している。
    expect(stub.calls.map((call) => call.url)).toContain(JAR_REQUEST_URI);
    const submitted = stub.calls.filter((call) => call.url === RESPONSE_URI);
    expect(submitted).toHaveLength(1);
    expect(vp.verifiableCredential).toEqual([submittedVpToken(submitted[0])]);
  });

  it('rpTrustAnchors 未設定では参照形式を 8030 で拒否し、取得も送信もしない', async () => {
    // 検証の起点が無い状態を「検証済み」に読み替えない（fail-closed）。
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS), jarRoute(SIGNED_JAR));
    const wallet = await setupWallet({ eudiFetchImpl: stub.fetchImpl });
    await wallet.receivePID(offerURI());
    const before = stub.calls.length;

    const failure = await codeAndReasonOf(() =>
      wallet.presentPID(REFERENCE_REQUEST_URI, ['family_name']),
    );

    expect(failure.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(failure.reason).toBe('jar_trust_anchors_unconfigured');
    // JAR の GET も VP Token の POST も発生しない。
    expect(stub.calls.length).toBe(before);
  });

  it('Object.prototype.rpTrustAnchors の汚染値を Trust Anchor に採らない', async () => {
    // 汚染値が起点になると、攻撃者 CA が発行した RP 証明書で署名された任意の提示要求が
    // 「検証済み」として提示 UI へ通る（`factory.ts` の own 限定読みの回帰）。
    const attacker = makeJarSigner({ origin: VERIFIER_CLIENT_ID });
    Object.defineProperty(Object.prototype, 'rpTrustAnchors', {
      configurable: true,
      value: attacker.anchors,
    });
    try {
      const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS), jarRoute(SIGNED_JAR));
      const wallet = await setupWallet({ eudiFetchImpl: stub.fetchImpl });
      await wallet.receivePID(offerURI());

      const failure = await codeAndReasonOf(() =>
        wallet.presentPID(REFERENCE_REQUEST_URI, ['family_name']),
      );

      expect(failure.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
      expect(failure.reason).toBe('jar_trust_anchors_unconfigured');
    } finally {
      delete (Object.prototype as unknown as Record<string, unknown>).rpTrustAnchors;
    }
  });

  it('presentEAA も参照形式を処理する', async () => {
    const stub = createStub(buildSdJwtVc(EAA_VCT, EAA_CLAIMS), jarRoute(SIGNED_JAR));
    const wallet = await setupWallet({
      eudiFetchImpl: stub.fetchImpl,
      eudiCatalogue: createRecordCatalogueSource({ [EAA_VCT]: CATALOGUE_ENTRY }),
      rpTrustAnchors: VERIFIER.anchors,
    });
    const eaa = await wallet.receiveEAA(offerURI(EAA_VCT));

    const vp = await wallet.presentEAA(REFERENCE_REQUEST_URI, eaa.vct);

    expect(stub.calls.map((call) => call.url)).toContain(JAR_REQUEST_URI);
    expect(vp.verifiableCredential).toHaveLength(1);
  });

  it('直接形式は rpTrustAnchors 無しでも従来どおり処理される（非回帰）', async () => {
    const stub = createStub(buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS));
    const wallet = await setupWallet({ eudiFetchImpl: stub.fetchImpl });
    await wallet.receivePID(offerURI());
    const params = new URLSearchParams({
      response_type: 'vp_token',
      client_id: VERIFIER_CLIENT_ID,
      response_mode: 'direct_post',
      response_uri: RESPONSE_URI,
      nonce: 'n-direct-jar-test-0123456789',
      state: 'state-direct-jar-test',
    });

    const vp = await wallet.presentPID(`openid4vp://?${params.toString()}`, ['family_name']);

    expect(stub.calls.map((call) => call.url)).not.toContain(JAR_REQUEST_URI);
    expect(vp.verifiableCredential).toHaveLength(1);
  });
});
