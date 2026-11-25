/**
 * `request_uri` 参照形式（JAR）の提示要求で `presentPID` / `presentEAA` を動かすための
 * フィクスチャ。
 *
 * Request Object は **Trust Anchor へ連鎖する RP Access Certificate 鍵**で
 * 署名する。証明書と署名の組み立ては `auth/jar/__tests__/jar-fixtures.ts` を再利用し（DER ビルダと
 * 署名手順を複製すると「テストだけ通る証明書」が生まれる）、ここでは提示経路固有の 2 点だけを足す:
 *
 * 1. 証明書の SubjectAltName / `client_id` / `response_uri` を提示フィクスチャの Verifier
 *    （`VERIFIER_CLIENT_ID` / `RESPONSE_URI`）へ揃える。
 * 2. **1 つの `fetchImpl` が `request_uri` の GET と `direct_post` の POST を両方さばく**スタブ。
 *    提示経路の HTTP シームは 1 つ（`PresentDeps.fetchImpl`）であり、取得と送信で別々の
 *    シームを持たせない設計をテスト側でもそのまま写す。
 */

import {
  type JarSigner,
  jarClaims,
  makeJarSigner,
  signJar,
} from '../../../jar/__tests__/jar-fixtures.js';
import type { JarTrustOptions } from '../../../jar/index.js';
import type { SubmitFetchLike } from '../../../oid4vp/oid4vp-submit.js';
import type { PresentDeps } from '../types.js';
import {
  holderSigner,
  RESPONSE_URI,
  type SubmitCall,
  VERIFIER_CLIENT_ID,
} from './presentation-fixtures.js';

/** JAR を置く `request_uri`（`client_id` と同一オリジン）。 */
export const JAR_REQUEST_URI = `${VERIFIER_CLIENT_ID}/request/abc`;

/** 参照形式の提示要求 URI（`request_uri` 単独形式。HAIP §5.1 の形）。 */
export function buildReferenceRequestURI(): string {
  return `openid4vp://?request_uri=${encodeURIComponent(JAR_REQUEST_URI)}`;
}

/** 参照形式 + `client_id` 併記の提示要求 URI。 */
export function buildReferenceRequestURIWithClientId(clientId = VERIFIER_CLIENT_ID): string {
  const params = new URLSearchParams({ client_id: clientId, request_uri: JAR_REQUEST_URI });
  return `openid4vp://?${params.toString()}`;
}

/** 提示フィクスチャの Verifier ドメインで署名できる RP Access Certificate 一式。 */
export function makePresentationJarSigner(): JarSigner {
  return makeJarSigner({ origin: VERIFIER_CLIENT_ID });
}

/** 提示フィクスチャの Verifier が署名した Request Object を作る。 */
export function signPresentationJar(
  verifier: JarSigner,
  overrides?: Record<string, unknown>,
): string {
  return signJar(verifier, {
    claims: jarClaims({
      iss: VERIFIER_CLIENT_ID,
      client_id: VERIFIER_CLIENT_ID,
      response_uri: RESPONSE_URI,
      ...overrides,
    }),
  });
}

/** `request_uri` GET と `direct_post` POST を 1 つのシームでさばくスタブ。 */
export interface JarSubmitStub {
  /** `PresentDeps.fetchImpl` として注入する実装。 */
  readonly fetchImpl: SubmitFetchLike;
  /** `direct_post` 送信の記録（送信順）。 */
  readonly calls: SubmitCall[];
  /** `request_uri` を GET した URL の記録（取得順）。 */
  readonly fetchedRequestUris: string[];
}

/**
 * JAR の GET と VP Token の POST を両方受けるスタブを作る。
 *
 * `init.method` で振り分ける（`request_uri` は GET、`direct_post` は POST）。GET を
 * `JAR_REQUEST_URI` 以外へ行った場合は 404 を返し、テストが「取りに行った先」を取り違えない
 * ようにする。
 *
 * @param jarJwt GET に対して返す Request Object（コンパクト JWS）。
 */
export function createJarSubmitStub(jarJwt: string): JarSubmitStub {
  const calls: SubmitCall[] = [];
  const fetchedRequestUris: string[] = [];
  const fetchImpl: SubmitFetchLike = (url, init) => {
    if (init.method === 'GET') {
      fetchedRequestUris.push(url);
      if (url !== JAR_REQUEST_URI) {
        return Promise.resolve(new Response('', { status: 404 }));
      }
      return Promise.resolve(
        new Response(jarJwt, {
          status: 200,
          headers: { 'Content-Type': 'application/oauth-authz-req+jwt' },
        }),
      );
    }
    calls.push({ url, body: init.body });
    return Promise.resolve(new Response('', { status: 200 }));
  };
  return { fetchImpl, calls, fetchedRequestUris };
}

/**
 * 参照形式を解決できる提示依存を作る。
 *
 * @param fetchImpl 取得と送信を兼ねるシーム。
 * @param trustAnchors 未指定なら `jarTrust` を載せない（Trust Anchor 未設定の再現）。
 */
export function jarPresentDeps(
  fetchImpl: SubmitFetchLike,
  trustAnchors?: JarTrustOptions['trustAnchors'],
): PresentDeps {
  return {
    signer: holderSigner(),
    fetchImpl,
    jarTrust: trustAnchors === undefined ? undefined : { trustAnchors },
  };
}
