/**
 * 受領した SD-JWT VC の Issuer 鍵解決 — `x5c`（証明書チェーン）→ ETSI TSL Trust Anchor 経路。
 *
 * `resolveReceivedIssuerKey` は `x5c` があれば証明書チェーンの検証を優先する。
 * この検証に失敗した場合は、JWT VC Issuer Metadata や DID の鍵に切り替えない。
 *
 * **なぜこの経路がいるか。** ARF / SD-JWT VC（draft-ietf-oauth-sd-jwt-vc）の PID Provider は `iss` に
 * HTTPS URL を載せ、検証鍵を Issuer-signed JWT ヘッダの `x5c`（証明書チェーン）で示す。DID 解決
 * しか持たないと HTTPS `iss` の Issuer は常に `3010`（`issuer_key_unresolved`）になり、呼び出し側は
 * `opts.verifyReceived` で検証を**自前で書く**しかない — 署名検証という最も間違えやすい部分を
 * 各アプリへ押し出すことになる。
 *
 * **`iss` と証明書の結び付けは必須である。** Trust Anchor へ連鎖しただけの証明書を受理すると、
 * 同じ Trust Anchor 配下の**任意の**証明書保持者が任意の `iss` を騙れる（自分の正当な証明書で
 * 他人の PID を偽造できる）。したがって `iss` が leaf 証明書の SubjectAltName（URI）と一致
 * することを必ず確かめる。JAR 署名検証が `client_id` と SAN を突き合わせる
 * （`auth/jar/jar-identity-binding.ts`）のと同じ規律である。
 *
 * 証明書を検証できない場合の扱い
 * - 失敗は真偽値ではなく throw で表し、理由は呼び出し側（`received-signature.ts`）が `3010` の
 *   `issuer_key_unresolved` へ畳む。戻り値・例外に証明書本文 / DN / VC 本文を含めない。
 */

import { extractX5cChain } from '../../internal/auth/jar/jar-x5c.js';
import type { PublicKeyJwk } from '../../internal/identity/did.js';
import { isNonBlankString } from '../../internal/prototype-safety/non-empty-string.js';
import {
  grantedTrustAnchors,
  parseCertificate,
  type QtspServiceCertificate,
  verifyCertificateChain,
} from '../../internal/trust/etsi-tsl/index.js';
import {
  spkiToPublicKeyJwk,
  subjectAltNameUrisOfCertificate,
} from '../../internal/trust/x509/index.js';
import { unresolvable } from './unresolvable.js';

/**
 * URI を比較用に正規化する（scheme / host は小文字・既定ポートは省略・末尾スラッシュは 1 つ落とす）。
 *
 * 揺れを吸収するのは表記だけで、**パス・query・fragment・userinfo は落とさない**。パスまで捨てて
 * origin で比べると、`https://ex.com/tenant-a` の証明書保持者が `https://ex.com/tenant-b` を
 * 名乗れてしまう（{@link issuerMatchesSan} 参照）。userinfo も同じ理由で残す — `URL.host` には
 * 含まれないため、明示的に組み戻さないと異なる `iss` が同じ SAN に束縛され得る。
 *
 * `new URL` がパースできない値だけ `undefined` を返し、呼び出し側の完全一致だけに委ねる。
 * **これは「HTTPS URL 以外」とは違う。** `new URL('did:web:ex.eu')` は成功する（scheme `did:`、
 * host 無し、pathname `web:ex.eu`）ので、DID の `iss` も正規化経路を通り `did://web:ex.eu` の
 * ような文字列になる。同じ規則を SAN URI 側にも掛けるため突き合わせは対称で、`iss` が DID の
 * 場合に照合が緩むことはない（そもそも DID の `iss` は `resolve.ts` の分岐で DID 解決経路へ
 * 進むため、本経路へ来るのは `x5c` を持つ VC だけである）。
 */
function normalizedUri(value: string): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  // `new URL` は scheme / host の小文字化と既定ポートの省略までを行う。末尾スラッシュだけは
  // 残るので、ルート以外のパスから 1 つだけ落として `/tenant-a/` と `/tenant-a` を揃える。
  const path = url.pathname.endsWith('/') ? url.pathname.slice(0, -1) : url.pathname;
  // userinfo（`https://a@ex.com/t` の `a`）は `URL.host` に含まれないので明示的に戻す。落とすと
  // `https://a@ex.com/t` / `https://b@ex.com/t` / `https://ex.com/t` が同じ文字列に畳まれ、
  // パスを落とさないと決めたのと同じ理由（異なる `iss` を同じ SAN へ束ねない）に反する。
  const userinfo =
    url.username === '' && url.password === '' ? '' : `${url.username}:${url.password}@`;
  return `${url.protocol}//${userinfo}${url.host}${path}${url.search}${url.hash}`;
}

/**
 * `iss` が leaf 証明書の SubjectAltName（URI）と一致するか。
 *
 * draft-ietf-oauth-sd-jwt-vc は `iss` と SAN URI の**完全一致**を要求する。origin 一致まで認めると、
 * 同じ origin の証明書保持者がパスの異なる別 `iss` を騙れる（SAN `https://ex.com/tenant-a` の証明書で
 * `iss: https://ex.com/tenant-b` を主張できる）。これは本モジュール冒頭で塞ぐと宣言した「同一 Trust
 * Anchor 配下のなりすまし」の、同一 origin 内への縮小版にほかならない。
 *
 * 末尾スラッシュ・既定ポート表記といった**表記の揺れ**は {@link normalizedUri} の正規化で吸収する。
 * 揺れを吸収するのにパスを捨てる必要は無い。
 */
function issuerMatchesSan(iss: string, leafDer: Uint8Array): boolean {
  const uris = subjectAltNameUrisOfCertificate(leafDer);
  if (uris.some((uri) => uri === iss)) {
    return true;
  }
  const normalizedIss = normalizedUri(iss);
  return normalizedIss !== undefined && uris.some((uri) => normalizedUri(uri) === normalizedIss);
}

/**
 * Issuer-signed JWT ヘッダの `x5c` を Issuer 側 Trust Anchor まで検証し、leaf の公開鍵を返す。
 *
 * @param header デコード済み JOSE Header。
 * @param iss Issuer-signed JWT payload の `iss`（型は未検査の外部入力）。
 * @param anchors `createWallet({ issuerTrustAnchors })` の値（未設定なら `undefined`）。
 * @returns leaf 証明書の EC P-256 公開鍵 JWK。
 * @throws Trust Anchor 未設定 / `x5c` 不正 / チェーン不成立 / SAN 不一致 / 鍵が P-256 でない場合。
 */
export async function resolveX5cIssuerKey(
  header: object,
  iss: unknown,
  anchors: readonly QtspServiceCertificate[] | undefined,
): Promise<PublicKeyJwk> {
  // granted でないサービス証明書は Trust Anchor に採らない（`extractQtspCertificates` の規約）。
  const trustAnchorsDer = Array.isArray(anchors) ? grantedTrustAnchors(anchors) : [];
  if (trustAnchorsDer.length === 0) {
    // 未設定は「検証を省く」ではない（`rpTrustAnchors` 未設定の `8030` と同じ方針）。
    throw unresolvable();
  }
  const chain = extractX5cChain(header);
  if (chain === undefined || !isNonBlankString(iss)) {
    throw unresolvable();
  }
  const result = await verifyCertificateChain(chain.leafDer, chain.intermediatesDer, {
    trustAnchorsDer,
  });
  if (!result.trusted || !issuerMatchesSan(iss, chain.leafDer)) {
    throw unresolvable();
  }
  let key: PublicKeyJwk | undefined;
  try {
    key = spkiToPublicKeyJwk(parseCertificate(chain.leafDer).spki);
  } catch {
    // チェーン検証を通った証明書はパースできるはずだが、例外を「解決できた」に読み替えない。
    throw unresolvable();
  }
  if (key === undefined) {
    throw unresolvable();
  }
  return key;
}
