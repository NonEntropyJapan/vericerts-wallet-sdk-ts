/**
 * OID4VP 提示要求の単一入口。
 *
 * Wallet が受け取る提示要求は deep link / QR の 1 本の URI であり、それが直接形式
 * （`response_type=vp_token&…`）なのか `request_uri` 参照形式（JAR）なのかは**受け取った時点では
 * 分からない**。呼び出し側にその判別と分岐（参照形式なら HTTP GET してから署名検証・解析）を
 * 書かせると、各アプリで判定条件と入口検査が再実装され、HAIP §5.1 が必須とする参照形式を
 * 取り落とすか、逆に非 HTTPS の `request_uri` や**署名を検証していない Request Object**を
 * 素通りさせる実装が混ざる。本モジュールはその分岐を SDK 側に 1 か所だけ置き、**どちらの形でも
 * 同じ `PresentationRequest` が返る**ことを保証する。
 *
 * 分岐の判定は `oid4vp-request-query.ts` の `requestUriReferenceOf` に集約されており、同期の
 * `parseAuthorizationRequest`（参照形式を `8030` で拒否する側）と同じ規則を使う。混在
 * （`request_uri` と `response_type` の両方が載る形）でも本 API は **RFC 9101 §6.3 のとおり
 * 署名済み Request Object を優先して取得する**（同期 API 側はそれを取得できないため `8030`）。
 *
 * **参照形式では署名検証を必ず経由する。** したがって参照形式の解決には
 * Trust Anchor が要る。`trustAnchors` を渡さない呼び出しで参照形式が届いた場合は、検証できない
 * ものを通さないため `8030`（`reason: 'jar_trust_anchors_unconfigured'`）で拒否する。直接形式は
 * 署名対象が存在しないため Trust Anchor を要求しない（同期 API と同じ検証のみを行う）。
 * `expectedClientId` は deep link のクエリに載っていた `client_id` を既定で用いる。
 *
 * スコープ外は `fetch-jar.ts` 冒頭と同じ（`request_uri_method=post` は対象外、
 * VP Token 構築・送信は `oid4vp.ts` / `oid4vp-submit.ts`、OpenID Federation / ARF を `x5c`
 * チェーンの起点とする経路は `jar-signature.ts` 冒頭）。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` に Request 本文・
 * `request_uri`・JWT を含めない。
 */

import type { FetchLike } from '../../fetch-di.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { extractQuery, requestUriReferenceOf } from '../oid4vp/oid4vp-request-query.js';
import type { PresentationRequest } from '../request.js';
import { parseAuthorizationRequest } from '../request.js';
import { fetchJAR } from './fetch-jar.js';
import type { JarTrustOptions } from './jar-signature.js';

/**
 * `parsePresentationRequest` のオプション。
 *
 * `JarTrustOptions` を `Partial` で取り込むのは、**直接形式には署名検証の対象が無い**ためである
 * （直接形式しか受け取らない呼び出し側に TSL の取得を強制しない）。参照形式に分岐した時点で
 * `trustAnchors` の有無は実行時に確かめられ、無ければ `8030` で拒否される（fail-closed）。
 * 型で必須にできるのは参照形式だけを扱う `fetchJAR`（`FetchJarOptions`）側である。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export type PresentationRequestOptions = Partial<JarTrustOptions> & {
  /**
   * 参照形式のときに使う HTTP 呼び出しの差し替えシーム（テスト注入用）。
   * 省略時はグローバル `fetch`。直接形式では使われない。
   */
  readonly fetchImpl?: FetchLike;
};

/**
 * 提示要求 URI を形式に応じて解析する（直接形式はそのまま、参照形式は JAR を取得・検証して解析）。
 *
 * 手順:
 * 1. URI からクエリを取り出す（空クエリは `8030`）。
 * 2. `request_uri` 参照形式（`request_uri` が空白のみでない値で載っている。直接パラメータの併記は
 *    問わない。RFC 9101 §6.3 の優先順位）なら `fetchJAR` で Request Object を取得し、
 *    署名検証を通したうえで `parseJarRequest` の正規化結果を返す。
 * 3. それ以外は同期の `parseAuthorizationRequest` の結果を返す。
 *
 * 両形式に共通して必須パラメータ・`response_uri` の HTTPS・`client_id` のオリジン一致を検査し、
 * `transaction_data` があれば、生の文字列配列として取り込む。要素が空文字列の場合や空の配列は拒否する。
 *
 * 両形式とも `Promise<PresentationRequest>` を返し、呼び出し側は URI 形式に応じて待機方法を切り替える必要がない。
 *
 * @param requestURI Wallet が受け取った提示要求 URI（`openid4vp://?…`）。
 * @param options Trust Anchor・突き合わせ材料・HTTP 差し替えシーム。参照形式では
 *                `trustAnchors` が必須（無ければ `8030`）。直接形式では省略できる。
 * @returns 正規化された `PresentationRequest`。
 * @throws 空クエリ / 必須パラメータ欠落 / DCQL 構文エラー / ドメイン不一致、および参照形式での
 *         非 HTTPS `request_uri` / 通信失敗 / 非 2xx / JWS 形式不正 / 署名検証失敗 /
 *         Trust Anchor 未設定の場合（VericertsError、code `8030`）。
 */
export async function parsePresentationRequest(
  requestURI: string,
  options?: PresentationRequestOptions,
): Promise<PresentationRequest> {
  const query = extractQuery(requestURI);
  const reference = requestUriReferenceOf(query);
  if (reference === undefined) {
    return parseAuthorizationRequest(requestURI);
  }
  return fetchJAR(reference, buildFetchJarOptions(query, options ?? {}));
}

/**
 * `fetchJAR` へ渡すオプションを組み立てる。
 *
 * すべてのメンバを**値が `undefined` でも own プロパティとして**載せる（横断 `fetch-di.ts` /
 * `own-property.ts` の規則）。載せずに省略すると、下流の own 限定読みが素通りする代わりに、
 * このリテラルが `Object.prototype` を継承した状態で DI 解決に渡り、指定していない
 * `fetchImpl` / `trustAnchors` が汚染値に化ける。
 *
 * `expectedClientId` は明示指定が無ければ deep link のクエリの `client_id` を使う
 * （例: `openid4vp://?client_id=<cid>&request_uri=…`）。deep link 側の `client_id` と Request Object 内の
 * `client_id` が食い違う要求を検出するための突き合わせ相手で、クエリに載っていない場合
 * （`request_uri` 単独形式）は `undefined` のまま = この突き合わせは行わない。
 */
function buildFetchJarOptions(
  query: URLSearchParams,
  options: PresentationRequestOptions,
): Parameters<typeof fetchJAR>[1] {
  const explicitClientId = ownProperty<unknown>(options, 'expectedClientId');
  const queryClientId = query.get('client_id');
  const expectedClientId = isNonBlankString(explicitClientId)
    ? explicitClientId
    : isNonBlankString(queryClientId)
      ? queryClientId
      : undefined;
  return {
    // `trustAnchors` は型上は必須だが、`Partial` 由来で欠落し得る。空のまま渡し、
    // `fetchJAR` → `verifyJarSignature` の fail-closed 判定（8030）に落とす。
    trustAnchors: ownProperty<JarTrustOptions['trustAnchors']>(
      options,
      'trustAnchors',
    ) as JarTrustOptions['trustAnchors'],
    expectedClientId,
    // `federationTrustAnchor` / `arfTrustAnchor` も他のメンバと
    // 同じ規約で own 限定で読み、`fetchJAR` へそのまま転送する。ここで転送し忘れると、呼び出し側が
    // OIDF / ARF 層を設定したつもりでも `verifyJarSignature` に届かず黙って TSL 単独へ縮退する。
    federationTrustAnchor: ownProperty<JarTrustOptions['federationTrustAnchor']>(
      options,
      'federationTrustAnchor',
    ),
    arfTrustAnchor: ownProperty<JarTrustOptions['arfTrustAnchor']>(options, 'arfTrustAnchor'),
    requestObjectSigningAlgValuesSupported: ownProperty<readonly string[]>(
      options,
      'requestObjectSigningAlgValuesSupported',
    ),
    revokedSerials: ownProperty<ReadonlySet<string>>(options, 'revokedSerials'),
    now: ownProperty<number>(options, 'now'),
    fetchImpl: ownProperty<FetchLike>(options, 'fetchImpl'),
  };
}
