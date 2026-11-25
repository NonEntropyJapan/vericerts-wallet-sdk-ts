/**
 * 受領した SD-JWT VC の Issuer 鍵解決 — JWT VC Issuer Metadata（`/.well-known/jwt-vc-issuer`）経路。
 *
 * プロトコル: draft-ietf-oauth-sd-jwt-vc §5（JWT VC Issuer Metadata）。
 *
 * **なぜ opt-in なのか。** この経路は **Issuer 自身のホスト（WebPKI / TLS）だけを信頼の起点とする**。
 * ETSI TSL Trust Anchor を起点とする `x5c` 経路（`x5c.ts`）とは信頼の強さが違う。既定検証へ無条件に
 * 加えると、**HTTPS の `iss` を名乗るあらゆるホストが自分の鍵を自分で証明できる**ことになり、
 * 現在 `3010`（`issuer_key_unresolved`）で fail-closed に閉じている面がすべて開く。既存の呼び出し側に
 * とってはサイレントな検証緩和になるため、`createWallet({ jwtVcIssuerMetadataResolution: true })` で
 * **明示的に有効化したときだけ**取得に行く。未設定なら HTTP リクエストは 1 度も発生しない。
 *
 * **`x5c` 経路との優先順位。** `x5c` が常に優先である（`resolveReceivedIssuerKey` の分岐 1.）。
 * 本経路は `x5c` を持たない VC の、かつ `iss` が HTTPS URL の場合にだけ入る。`x5c` の失敗を本経路で
 * 埋め合わせることはしない — 埋め合わせると、攻撃者は TSL 配下で通らない `x5c` を付けたまま、自分の
 * ホストが公開する鍵へ検証を落とし込める。`iss` が DID なら従来どおり DID 解決へ進む（分岐の重なりは
 * 無い。DID は HTTPS URL ではない）。
 *
 * **キャッシュは持たない（決定）。** 取得は検証のたびに行う。SDK が取得タイミングを握らない既存方針
 * （`loadTrustedList` の DI シーム、`rpTrustAnchors` / `issuerTrustAnchors` を呼び出し側が与える形）と
 * 揃える。Wallet 側に TTL キャッシュを置くと、失効・ローテーション後の鍵を無効化する信号が無いまま
 * 「いつ取得した鍵か判らない」状態で署名検証を行うことになる。取得回数を抑えたい運用は
 * `eudiFetchImpl` に自前のキャッシュ付き `fetch` を注入する — シームはすでにそこにあり、
 * SDK 内に二重のキャッシュ方針を持たせる必要は無い。
 *
 * Metadata 取得と鍵選択の制約
 * - `iss` は受領した VC 由来 = **攻撃者が影響し得る URL** である（draft §10.1 の SSRF 注意）。
 *   HTTPS 以外・query / fragment 付きは**取得せずに**拒否する。
 * - metadata 文書の取得も `jwks_uri` の取得も、**リダイレクト後の最終 URL の origin**が `iss` の
 *   origin と一致することまで確かめる。片方だけを縛ると、縛っていない側が任意 HTTPS ホストへの
 *   リクエスト踏み台として残る。
 * - metadata の `issuer` が `iss` と**完全一致**しない場合は中身を一切使わない（draft §5.3）。
 * - `jwks_uri` は `iss` と**同一 origin** に限る（下の {@link fetchJwkSet} 参照）。
 * - 失敗は真偽値ではなく throw で表し、理由は呼び出し側（`received-signature.ts`）が `3010` の
 *   `issuer_key_unresolved` へ畳む。戻り値・例外に取得 URL / 応答本文を含めない。
 */

import type { FetchLike } from '../../internal/auth/oid4vci/oid4vci.js';
import {
  fetchJsonDocument,
  fetchWellKnownJson,
} from '../../internal/auth/well-known-json/index.js';
import { isPublicHttpsUrl } from '../../internal/http/public-https-url.js';
import type { PublicKeyJwk } from '../../internal/identity/did.js';
import { trimTrailingSlashes } from '../../internal/primitives/trim-trailing-slashes.js';
import { isNonBlankString } from '../../internal/prototype-safety/non-empty-string.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import { unresolvable } from './unresolvable.js';

/** JWT VC Issuer Metadata の well-known 接頭辞（draft-ietf-oauth-sd-jwt-vc §5）。 */
const WELL_KNOWN_PREFIX = '/.well-known/jwt-vc-issuer';

/** JWT VC Issuer Metadata の取得元（`fetchWellKnownJson` へ渡す 2 分割の形）。 */
interface MetadataLocation {
  /** `iss` の origin（`scheme://host[:port]`）。 */
  readonly origin: string;
  /** `/.well-known/jwt-vc-issuer` に `iss` の path を続けたパス。 */
  readonly wellKnownPath: string;
}

/**
 * `iss` から JWT VC Issuer Metadata の取得元を組み立てる（draft §5）。
 *
 * well-known は **host と path のあいだ**へ差し込む（RFC 8414 と同じ形）。OpenID Connect Discovery
 * のような単純な末尾連結ではない — `iss: https://ex.example/tenant/1` の取得先は
 * `https://ex.example/.well-known/jwt-vc-issuer/tenant/1` であり、末尾連結で作った
 * `https://ex.example/tenant/1/.well-known/jwt-vc-issuer` ではない。差し込みの前に `iss` の末尾
 * スラッシュを落とすことも draft が明記している。
 *
 * draft は `iss` を「scheme / host（と任意の port / path）から成る HTTPS URL で、query と fragment を
 * 持たない」と定めるので、その形を満たさない値は**取得に行かずに**拒否する（`undefined` を返す）。
 * query / fragment を黙って捨てて取得すると、`iss` として提示された識別子と実際に問い合わせた先が
 * 食い違い、`issuer` 完全一致検査が意味を失う。
 */
function metadataLocation(iss: string): MetadataLocation | undefined {
  if (!isPublicHttpsUrl(iss)) {
    return undefined;
  }
  const url = new URL(iss);
  if (url.search !== '' || url.hash !== '') {
    return undefined;
  }
  return {
    origin: url.origin,
    wellKnownPath: `${WELL_KNOWN_PREFIX}${trimTrailingSlashes(url.pathname)}`,
  };
}

/**
 * JWK Set 文書から、Issuer-signed JWT の `kid` に対応する鍵を 1 つ選ぶ。
 *
 * - ヘッダに `kid` があれば `kid` 一致の鍵**だけ**を候補にする。一致が 1 件でなければ拒否する。
 *   「一致が無ければ全鍵を試す」形のフォールバックは置かない — Issuer が指した鍵と違う鍵で検証を
 *   通してしまえば、`kid` を付ける意味（鍵の取り違えを検知すること）が無くなる。
 * - ヘッダに `kid` が無い場合は、JWK Set がちょうど 1 鍵のときだけそれを採る。複数鍵から「どれか
 *   通るもの」を選ぶのは、鍵の指定が無い VC に Issuer の**別用途の鍵**での検証成立を許すことになる。
 * - `kid` が**在るが JWS の規定する文字列でない**（`kid: 123` / `kid: ''` / オブジェクト等）場合は
 *   拒否する。「文字列でなければ `kid` 無しとみなす」形にすると、攻撃者が非文字列の `kid` を置く
 *   だけで上の 2 規則のうち**緩いほう**（1 鍵なら無条件に採る）へ格下げでき、鍵の指定を無効化
 *   できてしまう。`kid` を付けた以上は `kid` で絞れることを要求する。
 *
 * 鍵そのものの妥当性（`kty` / `crv` と `alg` の整合）は `verifySdJwt` の署名検証が判定する。ここでは
 * 「オブジェクトであること」までを確かめ、鍵種別の判定を二重に持たない。
 *
 * **オブジェクトでない要素を含む JWK Set は、その時点で不正として拒否する。** 黙って落とすと
 * `{"keys": [null, <jwk>]}` が「ちょうど 1 鍵」として通り、上の `kid` 無しの条件（JWK Set が
 * ちょうど 1 鍵）が攻撃者の影響下で崩れる。JWK Set は Issuer が出す文書なので、不正な要素が
 * 混ざること自体が「解釈してはいけない文書」の合図である。
 */
function selectKey(keys: readonly unknown[], kid: unknown): PublicKeyJwk {
  const isJwkObject = (key: unknown): key is PublicKeyJwk =>
    typeof key === 'object' && key !== null && !Array.isArray(key);
  if (!keys.every(isJwkObject)) {
    throw unresolvable();
  }
  const objects: readonly PublicKeyJwk[] = keys;
  if (kid !== undefined && !isNonBlankString(kid)) {
    // `kid` は在るが文字列でない / 空。`kid` 無し扱いへ格下げしない（上の規則を参照）。
    throw unresolvable();
  }
  const candidates = isNonBlankString(kid)
    ? objects.filter((key) => ownProperty<unknown>(key, 'kid') === kid)
    : objects;
  if (candidates.length !== 1) {
    throw unresolvable();
  }
  // `length === 1` を確かめた直後の添字アクセス。`noUncheckedIndexedAccess` 下でも実体は非 undefined。
  const [key] = candidates;
  if (key === undefined) {
    throw unresolvable();
  }
  return key;
}

/**
 * metadata の `jwks`（インライン）または `jwks_uri`（参照）から JWK Set の `keys` 配列を得る。
 *
 * draft §5 は「`jwks_uri` か `jwks` のいずれか**一方**を含まなければならない」と定めるので、両方ある
 * 文書・どちらも無い文書は拒否する（どちらを採るかを SDK が勝手に決めない）。
 *
 * **`jwks_uri` は `iss` と同一 origin に限る。** ここまでで信頼したのは「`iss` の origin の TLS 証明書を
 * 持つホスト」だけである。別 origin の `jwks_uri` を辿ると、その別ホストが `iss` の鍵を決められる
 * ことになり、認証した相手と鍵を出す相手が食い違う。加えて `jwks_uri` は受領した VC 由来の
 * metadata が指す任意の URL であり、origin を縛らなければ内部ネットワークへの SSRF 踏み台になる
 * （draft §10.1）。
 *
 * **束縛は取得後の最終 URL まで及ぶ。** 取得前の URL だけを検査すると、同一 origin の `jwks_uri` が
 * 別 origin（内部ホストを含む）へ 302 した先に追随して鍵を採ってしまう。`fetchJsonDocument` へ
 * `origin` を渡し、`response.url` の origin が一致しない応答を拒否させる。
 */
async function fetchKeys(
  metadata: object,
  origin: string,
  fetchImpl: FetchLike | undefined,
): Promise<readonly unknown[]> {
  const jwks = ownProperty<unknown>(metadata, 'jwks');
  const jwksUri = ownProperty<unknown>(metadata, 'jwks_uri');
  if ((jwks === undefined) === (jwksUri === undefined)) {
    // 両方ある / どちらも無い。
    throw unresolvable();
  }
  if (jwks !== undefined) {
    return keysOf(jwks);
  }
  if (
    !isNonBlankString(jwksUri) ||
    !isPublicHttpsUrl(jwksUri) ||
    new URL(jwksUri).origin !== origin
  ) {
    throw unresolvable();
  }
  // `origin` を第 4 引数に渡すのが肝心。取得前の URL だけを縛っても、同一 origin の `jwks_uri` が
  // 別 origin へ 302 すれば追随してしまい、下の不変条件が実効を持たない。
  return keysOf(await fetchJsonDocument(jwksUri, fetchImpl, unresolvable, origin));
}

/** JWK Set 文書から `keys` 配列を取り出す（配列でなければ拒否）。 */
function keysOf(document: unknown): readonly unknown[] {
  if (typeof document !== 'object' || document === null || Array.isArray(document)) {
    throw unresolvable();
  }
  const keys = ownProperty<unknown>(document, 'keys');
  if (!Array.isArray(keys)) {
    throw unresolvable();
  }
  return keys;
}

/**
 * JWT VC Issuer Metadata から Issuer の検証鍵を解決する（本モジュール冒頭の規則に従う）。
 *
 * 手順:
 * 1. `iss` が draft §5 の形（query / fragment を持たない HTTPS URL）でなければ**取得せずに**拒否。
 * 2. `GET {origin}/.well-known/jwt-vc-issuer{path}` を取得する（HTTPS 維持・**`iss` の origin への
 *    束縛**・10 秒上限・本文 1 MiB 上限・JSON Content-Type 必須・プロトタイプ外しは
 *    `fetchWellKnownJson` が担う）。
 * 3. metadata の `issuer` が `iss` と完全一致しなければ、中身を一切使わずに拒否する（draft §5.3）。
 * 4. `jwks` / `jwks_uri` のいずれか一方から JWK Set を得る。
 * 5. Issuer-signed JWT ヘッダの `kid` で鍵を 1 つに絞る。
 *
 * @param iss Issuer-signed JWT payload の `iss`（型は未検査の外部入力）。
 * @param kid Issuer-signed JWT ヘッダの `kid`（型は未検査の外部入力）。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム（`createWallet({ eudiFetchImpl })`）。
 * @returns Issuer の公開鍵 JWK。
 * @throws 上記のいずれかを満たさない場合（呼び出し側が `3010` / `issuer_key_unresolved` へ畳む）。
 */
export async function resolveJwtVcIssuerKey(
  iss: unknown,
  kid: unknown,
  fetchImpl: FetchLike | undefined,
): Promise<PublicKeyJwk> {
  if (!isNonBlankString(iss)) {
    throw unresolvable();
  }
  const location = metadataLocation(iss);
  if (location === undefined) {
    throw unresolvable();
  }
  // 第 5 引数の `origin` が肝心。metadata 文書自体の取得にも同じ origin 束縛を掛けないと、
  // `/.well-known/jwt-vc-issuer` が別 origin（内部ホストを含む）へ 302 したときに追随してしまい、
  // 「認証したのは `iss` の origin の TLS 証明書を持つホストだけ」という不変条件が metadata 側で
  // 迂回される（`jwks_uri` 側だけ縛っても非対称に穴が残る）。
  const metadata = await fetchWellKnownJson(
    location.origin,
    location.wellKnownPath,
    fetchImpl,
    unresolvable,
    location.origin,
  );
  if (ownProperty<unknown>(metadata, 'issuer') !== iss) {
    throw unresolvable();
  }
  return selectKey(await fetchKeys(metadata, location.origin, fetchImpl), kid);
}

/**
 * `iss` が JWT VC Issuer Metadata 経路の対象か（= HTTPS URL か）。
 *
 * DID の `iss` は従来どおり DID 解決へ進む。判定を分岐側（`x5c.ts`）に書き写さず本モジュールに
 * 置くのは、対象の定義（draft §3.5「`iss` が HTTPS URI のとき」）を 1 か所に保つためである。
 */
export function isMetadataResolvableIssuer(iss: unknown): boolean {
  return isNonBlankString(iss) && isPublicHttpsUrl(iss);
}
