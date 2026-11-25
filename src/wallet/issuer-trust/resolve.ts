/**
 * 受領した SD-JWT VC の Issuer 鍵解決 — **経路の分岐**。
 *
 * `resolveReceivedIssuerKey` は Issuer-signed JWT ヘッダと `iss` に応じて検証鍵の取得方法を選ぶ。
 *
 * **なぜ複数経路いるか。** ARF / SD-JWT VC（draft-ietf-oauth-sd-jwt-vc）の PID Provider は `iss` に
 * HTTPS URL を載せ、検証鍵を Issuer-signed JWT ヘッダの `x5c`（証明書チェーン）で示す。一方で
 * 本 SDK の既存の受領経路は `iss` を DID として解決する。DID 解決しか持たないと
 * HTTPS `iss` の Issuer は常に `3010`（`issuer_key_unresolved`）になり、呼び出し側は
 * `opts.verifyReceived` で検証を**自前で書く**しかない — 署名検証という最も間違えやすい部分を
 * 各アプリへ押し出すことになる。
 *
 * **鍵解決の優先順位**
 *
 * 1. Issuer-signed JWT ヘッダが `x5c` を持つ → 証明書チェーン経路（`x5c.ts`）。以降は他経路へ
 *    **フォールバックしない**（`x5c` は「このチェーンで検証せよ」という主張であり、失敗を
 *    別経路で埋め合わせると、攻撃者が用意した `x5c` を付けるだけで経路を選ばせられる）。
 * 2. `x5c` が無く、`createWallet({ jwtVcIssuerMetadataResolution: true })` が指定されていて、かつ
 *    `iss` が HTTPS URL → JWT VC Issuer Metadata 経路（`jwt-vc-issuer.ts`）。**既定は off** で、
 *    未指定なら取得に行かない（従来の挙動をそのまま保つ）。
 * 3. それ以外（`x5c` が無く、metadata 経路の対象でない）→ 従来どおり `iss` を DID として
 *    解決する（`resolveSdJwtIssuerKey`）。
 * 4. いずれでも鍵が得られなければ `3010`（`issuer_key_unresolved`）で fail-closed。
 *
 * 鍵を解決できない場合の扱い
 * - 失敗は真偽値ではなく throw で表し、理由は呼び出し側（`received-signature.ts`）が `3010` の
 *   `issuer_key_unresolved` へ畳む。戻り値・例外に証明書本文 / DN / VC 本文を含めない。
 */

import type { FetchLike } from '../../internal/auth/oid4vci/oid4vci.js';
import { parseSdJwt } from '../../internal/credential/index.js';
import { decodeCompactJws } from '../../internal/credential/vc/jws.js';
import { bindInjectedFetch } from '../../internal/http/bind-fetch.js';
import type { DidResolverLike } from '../../internal/identity/bounded-resolver.js';
import type { PublicKeyJwk } from '../../internal/identity/did.js';
import {
  nonObjectPrototypeProperty,
  ownProperty,
} from '../../internal/prototype-safety/own-property.js';
import type { QtspServiceCertificate } from '../../internal/trust/etsi-tsl/index.js';
import { resolveSdJwtIssuerKey } from '../issuer-key.js';
import { isMetadataResolvableIssuer, resolveJwtVcIssuerKey } from './jwt-vc-issuer.js';
import { unresolvable } from './unresolvable.js';
import { resolveX5cIssuerKey } from './x5c.js';

/**
 * 受領した VC の Issuer 鍵解決に使う信頼材料（`createWallet` が組み立てて受領経路へ渡す）。
 *
 * ## メンバの読み取り規律（`resolveReceivedIssuerKey` が守る不変条件）
 *
 * 本オブジェクトは {@link buildReceivedIssuerTrust}（`wallet/factory.ts` から呼ぶ）が組み立てるが、
 * 読み取りは**プロトタイプ鎖を辿らない**。
 * どのメンバも「省略された」と「汚染値を拾った」を取り違えると fail-open になるためである。
 * 使うヘルパーはメンバの種別で決まる（`internal/prototype-safety/own-property.ts` の規約）。
 *
 * - **純データ**（`issuerTrustAnchors` / `jwtVcIssuerMetadataResolution`）→ `ownProperty`。
 *   加えて {@link buildReceivedIssuerTrust} は**値が `undefined` でも own プロパティとして載せる**
 *   （`wallet/eudi/rp-trust.ts` と同じ規律）。省略すると `Object.prototype.issuerTrustAnchors` の
 *   汚染値が「設定された Trust Anchor」に化け、攻撃者 CA が Issuer 鍵の信頼の起点になる。
 *   `jwtVcIssuerMetadataResolution` も同じで、汚染値が「有効化した」に化けると **opt-in して
 *   いない呼び出しで Issuer 自身のホストからの鍵取得が始まる**（既定の fail-closed 面が開く）。
 * - **DI 依存**（`resolver` / `jwtVcIssuerMetadataFetchImpl`）→ `nonObjectPrototypeProperty`。
 *   これらはプロトタイプメソッド / アクセサで実装されるのが正当な形なので own 限定では読めない
 *   （own 限定で読むと注入した `fetch` が黙ってグローバル `fetch` に差し替わる）。一方で鎖を
 *   そのまま辿ると `Object.prototype.jwtVcIssuerMetadataFetchImpl` の汚染値が注入シームに化け、
 *   metadata 取得が攻撃者の `fetch` を通る。`Object.prototype` 由来だけを弾くこのヘルパーが
 *   両方を満たす。`jwtVcIssuerMetadataFetchImpl` は読みと同時に**レシーバを束ねる**ので
 *   {@link bindInjectedFetch}（同じ弾き方に `bind` を足したもの）を使う。
 */
export interface ReceivedIssuerTrust {
  /** `iss` を DID として解決する Resolver（`x5c` を持たない VC の経路）。 */
  readonly resolver: DidResolverLike;
  /** `x5c` チェーンの到達先とする Issuer 側 Trust Anchor（未設定なら `x5c` 経路は fail-closed）。 */
  readonly issuerTrustAnchors: readonly QtspServiceCertificate[] | undefined;
  /**
   * JWT VC Issuer Metadata 経路を有効にするか
   * （`createWallet({ jwtVcIssuerMetadataResolution })`）。
   *
   * `true` **ちょうど**のときだけ有効になる。truthy な非真偽値で開かないのは、
   * この経路が Issuer 自身のホストを信頼の起点にする = 既定の fail-closed 面を開くものであり、
   * 「意図して有効化した」以外の形で入ってはならないためである。
   */
  readonly jwtVcIssuerMetadataResolution: boolean | undefined;
  /**
   * JWT VC Issuer Metadata 取得に使う `fetch` の差し替えシーム
   * （`createWallet({ eudiFetchImpl })`。未注入ならグローバル `fetch`）。
   *
   * EUDI の発行者通信と取得先の信頼の前提が同じ（どちらも Issuer 自身のホスト）なので、
   * `didConfigurationFetchImpl` のように別シームへは分けない。
   *
   * 名前に `jwtVc` を冠するのは、姉妹メンバ `jwtVcIssuerMetadataResolution` と同じ理由である。
   * 「Issuer Metadata」だけだと OID4VCI の Credential Issuer Metadata
   * （`/.well-known/openid-credential-issuer`）と紛れるが、本シームが取りに行くのは
   * draft-ietf-oauth-sd-jwt-vc の JWT VC Issuer Metadata（`/.well-known/jwt-vc-issuer`）だけで、
   * 両者は取得先も用途も別物である。
   */
  readonly jwtVcIssuerMetadataFetchImpl: FetchLike | undefined;
}

/**
 * 受領した SD-JWT VC の Issuer 検証鍵を解決する（本モジュール冒頭の分岐順序に従う）。
 *
 * @param trust Issuer 鍵解決の信頼材料。
 * @param sdJwt 受領した SD-JWT VC のコンパクト表現。
 * @returns Issuer の公開鍵 JWK。
 * @throws いずれの経路でも鍵を得られない場合（呼び出し側が `3010` へ畳む）。
 */
export async function resolveReceivedIssuerKey(
  trust: ReceivedIssuerTrust,
  sdJwt: string,
): Promise<PublicKeyJwk> {
  const { header, payload } = decodeCompactJws(parseSdJwt(sdJwt).issuerJwt);
  const iss = ownProperty<unknown>(payload, 'iss');
  // `x5c` は own 限定で読む。鎖読みだと `x5c` を**持たない**（= 他経路の）VC が汚染された
  // `Object.prototype.x5c` を掴み、攻撃者の証明書チェーンで経路ごと差し替えられる。
  if (ownProperty<unknown>(header, 'x5c') !== undefined) {
    return resolveX5cIssuerKey(
      header,
      iss,
      ownProperty<readonly QtspServiceCertificate[]>(trust, 'issuerTrustAnchors'),
    );
  }
  // opt-in フラグは純データなので own 限定で読み、`true` ちょうどだけを有効とする（`jwt-vc-issuer.ts`
  // 冒頭）。`iss` が DID の VC は対象外なので、この分岐は従来の DID 解決経路を狭めない。
  if (
    ownProperty<unknown>(trust, 'jwtVcIssuerMetadataResolution') === true &&
    isMetadataResolvableIssuer(iss)
  ) {
    return resolveJwtVcIssuerKey(
      iss,
      ownProperty<unknown>(header, 'kid'),
      // 注入シームは関数値なので own 限定では読まない（本インターフェースの読み取り規律を参照）。
      // 同時に**レシーバを束ねて**渡す（`internal/fetch-di.ts` 規則 2）。下流の
      // `fetchJsonWithinLimits` が束ね直せるのは合成リテラルだけなので、ここで束ねないと
      // `this` 参照つきの prototype メソッド DI が壊れ、失敗は `3010`
      // `issuer_key_unresolved` の幻の障害になる。`factory.ts` が束ねた関数を再度束ねても
      // レシーバは変わらない（`Function.prototype.bind` の性質）ので、両側で守って良い。
      bindInjectedFetch(trust, 'jwtVcIssuerMetadataFetchImpl'),
    );
  }
  const resolver = nonObjectPrototypeProperty<DidResolverLike>(trust, 'resolver');
  if (resolver === undefined) {
    // 必須メンバだが、汚染値を掴むくらいなら鍵無しで倒す（fail-closed）。
    throw unresolvable();
  }
  return resolveSdJwtIssuerKey(resolver, sdJwt);
}

/**
 * `createWallet` のオプションから {@link ReceivedIssuerTrust} を組み立てる。
 *
 * 組み立てを `factory.ts` に直書きせず本モジュールへ置くのは、**書き込みの規律が読み取りの規律と
 * 対になっている**ためである（上の「メンバの読み取り規律」）。離すと、片方だけを直すリファクタが
 * 成立してしまう。
 *
 * 要点は純データ 2 メンバ（`issuerTrustAnchors` / `jwtVcIssuerMetadataResolution`）を
 * **値が `undefined` でも own プロパティとして載せる**ことである（`wallet/eudi/rp-trust.ts` と
 * 同じ規律）。省略すると、下流が鎖読みへ退化したとたんに
 *
 * - `Object.prototype.issuerTrustAnchors` の汚染値が「設定された Trust Anchor」に化け、攻撃者 CA が
 *   発行した証明書チェーンを持つ偽の PID / (Q)EAA が「検証済み」として保持される
 * - `Object.prototype.jwtVcIssuerMetadataResolution` の汚染値が「有効化した」に化け、opt-in して
 *   いない呼び出しで Issuer 自身のホストからの鍵取得が始まる（既定の fail-closed 面が開く）
 *
 * という 2 つの fail-open が同時に開く。own プロパティを常に載せておけば、読み取り側の規律が
 * 崩れても汚染値は届かない（多層防御）。この不変条件は
 * `__tests__/issuer-trust/received-issuer-trust.test.ts` が固定する。
 *
 * @param opts `createWallet` のオプション（未検査の外部入力）。
 * @param resolver 組み立て済みの DID Resolver。
 * @param fetchImpl JWT VC Issuer Metadata 取得に使う `fetch`（`eudiFetchImpl` を共有する。
 *        EUDI の発行者通信と取得先の信頼の前提が同じため）。呼び出し側（`factory.ts`）が
 *        {@link bindInjectedFetch} で**レシーバを束ねた**関数値を渡すこと。
 */
export function buildReceivedIssuerTrust(
  opts: object,
  resolver: DidResolverLike,
  fetchImpl: FetchLike | undefined,
): ReceivedIssuerTrust {
  return {
    resolver,
    issuerTrustAnchors: ownProperty<readonly QtspServiceCertificate[]>(opts, 'issuerTrustAnchors'),
    jwtVcIssuerMetadataResolution: ownProperty<boolean>(opts, 'jwtVcIssuerMetadataResolution'),
    jwtVcIssuerMetadataFetchImpl: fetchImpl,
  };
}
