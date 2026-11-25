/**
 * `request_uri`（JAR）取得・検証 API の公開エクスポート面の回帰テスト。
 *
 * 参照形式の提示要求（HAIP §5.1）を公開 API から取得・検証できることを確認する。
 *
 * 現在、参照形式の解決には Trust Anchor（`QtspServiceCertificate`）が必須である。
 * したがって**オプション型と Trust Anchor 型が公開面から名前で書けること**も固定する
 * （書けないと利用者は `fetchJAR` の第 2 引数を型付きで用意できない）。
 *
 * ただしオプション 3 型（`FetchJarOptions` / `JarTrustOptions` / `PresentationRequestOptions`）は
 * 宣言に `@experimental` を持つため、`./experimental` サブパスから公開する。
 * 関数 `fetchJAR` / `parsePresentationRequest` 自体は無タグなのでメインバレルに残る。
 *
 * 内部パス（`internal/auth/jar/*.js`）から import すると公開面の欠落を検知できないため、
 * 必ず公開バレル経由で import する。関数は `parseAuthorizationRequest` / `parseJarRequest` と同じ
 * メインバレルに載ることを確認する。
 */

import { describe, expect, test } from 'bun:test';
import * as sdk from '../../index.js';
import {
  CLIENT_ID,
  jarClaims,
  makeJarSigner,
  REQUEST_URI,
  signJar,
} from '../../internal/auth/jar/__tests__/jar-fixtures.js';
import * as experimental from '../experimental.js';

const VERIFIER = makeJarSigner();
const JAR_JWT = signJar(VERIFIER, {
  claims: jarClaims({ nonce: 'n-surface-0123456789abcdef', state: 's-surface' }),
});

/** 公開型で書いた Trust Anchor 集合（型が公開されていなければ `tsc` が落ちる）。 */
const TRUST_ANCHORS: readonly sdk.QtspServiceCertificate[] = VERIFIER.anchors;

/** JAR を返す fetch スタブ。 */
async function stubFetch(): Promise<Response> {
  return new Response(JAR_JWT, {
    status: 200,
    headers: { 'Content-Type': 'application/oauth-authz-req+jwt' },
  });
}

describe('公開エクスポート: fetchJAR / parsePresentationRequest', () => {
  test('2 つの API がメインバレルから import できる', () => {
    expect(typeof sdk.fetchJAR).toBe('function');
    expect(typeof sdk.parsePresentationRequest).toBe('function');
    // 兄弟 API と同じ扱い（`@experimental` タグは付けていないためサブパスには載らない）。
    expect((experimental as unknown as Record<string, unknown>).fetchJAR).toBeUndefined();
  });

  test('公開 fetchJAR が request_uri から PresentationRequest を返す', async () => {
    const options: experimental.FetchJarOptions = {
      trustAnchors: TRUST_ANCHORS,
      fetchImpl: stubFetch,
    };
    const request: sdk.PresentationRequest = await sdk.fetchJAR(REQUEST_URI, options);
    expect(request.clientId).toBe(CLIENT_ID);
    expect(request.nonce).toBe('n-surface-0123456789abcdef');
  });

  test('公開 parsePresentationRequest が参照形式を取得・検証・解析する', async () => {
    const options: experimental.PresentationRequestOptions = {
      trustAnchors: TRUST_ANCHORS,
      fetchImpl: stubFetch,
    };
    const request = await sdk.parsePresentationRequest(
      `openid4vp://?request_uri=${encodeURIComponent(REQUEST_URI)}`,
      options,
    );
    expect(request.state).toBe('s-surface');
  });

  test('fetchImpl の型 FetchLike をメインバレルから名前で書ける', async () => {
    // SDK は `fetchImpl?: FetchLike` を公開
    // シグネチャとして宣言している。型が公開されていないと利用者が引数の型を名前で書けず、
    // 自前の fetch 実装を型付きで用意できない。
    const injected: sdk.FetchLike = stubFetch;
    const request = await sdk.fetchJAR(REQUEST_URI, {
      trustAnchors: TRUST_ANCHORS,
      fetchImpl: injected,
    });
    expect(request.nonce).toBe('n-surface-0123456789abcdef');
    // 同じ型は `AuthorizationCodeFlowDeps.fetchImpl` / `PARRequest.fetchImpl`（`./experimental`）
    // でも使われる。二重公開はせずメインバレル 1 か所から参照する。`sdk.FetchLike` の値を
    // 両フィールドの型へ代入して型リンクを固定する（別型に分岐したら `tsc` が落ちる）。
    const forFlowDeps: NonNullable<experimental.AuthorizationCodeFlowDeps['fetchImpl']> = injected;
    const forPARRequest: NonNullable<experimental.PARRequest['fetchImpl']> = injected;
    expect(typeof forFlowDeps).toBe('function');
    expect(typeof forPARRequest).toBe('function');
  });

  test('Trust Anchor 型と JarTrustOptions を公開面から名前で書ける', () => {
    // Trust Anchor を利用者が用意できなければ参照形式は使えない。
    const trust: experimental.JarTrustOptions = {
      trustAnchors: TRUST_ANCHORS,
      expectedClientId: CLIENT_ID,
      requestObjectSigningAlgValuesSupported: ['ES256'],
    };
    expect(trust.trustAnchors.length).toBe(1);
    // `loadTrustedList` / `extractQtspCertificates` の戻り値をそのまま渡せる型であること。
    // Trust Anchor 型自体は無タグなのでメインバレル側に残る。
    expect(typeof sdk.extractQtspCertificates).toBe('function');
  });

  test('公開 verifyJarSignature がサブパスから使えて JAR の署名を検証する', async () => {
    // `parseJarRequest`（メインバレル）は署名を検証しないため、取得を自前で行う利用者にとって
    // 公開関数で取得済みの JAR の署名を検証できることを確認する。
    // サブパスからこの公開手段が消えても内部テストでは検出できないため、
    // 公開面をここで固定する。
    expect(typeof experimental.verifyJarSignature).toBe('function');
    // 正当な JAR は通る（戻り値は無い = ゲート）。
    await expect(
      experimental.verifyJarSignature(JAR_JWT, { trustAnchors: TRUST_ANCHORS }),
    ).resolves.toBeUndefined();
    // Trust Anchor 未設定は公開面でも fail-closed。
    await expect(
      experimental.verifyJarSignature(JAR_JWT, {
        trustAnchors: [],
      }),
    ).rejects.toMatchObject({
      code: sdk.ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
      context: { reason: 'jar_trust_anchors_unconfigured' },
    });
    // 無タグの兄弟と違い、メインバレルには載らない。
    expect((sdk as unknown as Record<string, unknown>).verifyJarSignature).toBeUndefined();
  });

  test('オプション 3 型はメインバレルに載らない', () => {
    // 型はランタイムに実体を持たないため、隔離が崩れたことは **型エラー**でしか検知できない。
    // 3 型がメインバレルへ戻ると下の `@ts-expect-error` が「不要」になり `tsc` が落ちる。
    // @ts-expect-error FetchJarOptions は `./experimental` サブパスにのみ載る
    type _MainBarrelFetchJarOptions = sdk.FetchJarOptions;
    // @ts-expect-error JarTrustOptions は `./experimental` サブパスにのみ載る
    type _MainBarrelJarTrustOptions = sdk.JarTrustOptions;
    // @ts-expect-error PresentationRequestOptions は `./experimental` サブパスにのみ載る
    type _MainBarrelPresentationRequestOptions = sdk.PresentationRequestOptions;
    // 関数本体は無タグなのでメインバレルに残る（隔離の対象は宣言にタグを持つ 3 型だけ）。
    expect(typeof sdk.fetchJAR).toBe('function');
    expect(typeof sdk.parsePresentationRequest).toBe('function');
  });

  test('公開面でも HTTPS 強制が維持される（公開エラーコードへ正規化）', async () => {
    await expect(
      sdk.fetchJAR('http://verifier.example.com/req', {
        trustAnchors: TRUST_ANCHORS,
        fetchImpl: stubFetch,
      }),
    ).rejects.toMatchObject({
      code: sdk.ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
    });
  });

  test('公開面でも Trust Anchor 未設定の参照形式は拒否される（fail-closed）', async () => {
    await expect(
      sdk.parsePresentationRequest(`openid4vp://?request_uri=${encodeURIComponent(REQUEST_URI)}`, {
        fetchImpl: stubFetch,
      }),
    ).rejects.toMatchObject({
      code: sdk.ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
      context: { reason: 'jar_trust_anchors_unconfigured' },
    });
  });
});
