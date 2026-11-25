/**
 * refreshService エンドポイント呼び出し（`refreshCredential` の手順 4）。
 *
 * VC 本文と応答本文を例外へ載せない。応答のプロパティはオブジェクト自身が持つものだけを読む。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FetchLike } from '../../fetch-di.js';
import { declaresOversizedBody, discardBody, readBodyWithinLimit } from '../../http/body-limit.js';
import { isPublicHttpsUrl, isRedirectedResponse } from '../../http/public-https-url.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../vc/vc.js';

/** refreshService 呼び出しの HTTP タイムアウト（ミリ秒）。発行者通信と揃えて 10 秒。 */
const REFRESH_REQUEST_TIMEOUT_MS = 10_000;

/**
 * refreshService エンドポイントを呼び出し、更新後の生 VC 文字列を受領する。
 *
 * `service.url` へ `POST`（body に対象 VC の ID を同梱）し、応答 JSON の `credential`
 * （または `verifiableCredential`）から生 VC 文字列を取り出す。秘匿情報の平文送信を防ぐため
 * HTTPS 以外は拒否する。
 *
 * @param service 呼び出す refreshService（`url` / `id` を own 読みする）。
 * @param vc 更新対象の VC（`id` を own 読みして要求本文に載せる）。
 * @param fetchImpl 注入された `fetch` 実装。関数でない場合（省略・`null` 等）はグローバル `fetch`。
 * @param fetchReceiver `fetchImpl` を取り出した元のオブジェクト（`RefreshDependencies`）。
 *        `fetchImpl` が関数として注入された場合だけこれを `this` に束ねて呼ぶ。
 * @throws HTTPS 以外 / 必須欄欠落 / HTTP エラー / 応答不正で `REFRESH_FAILED`（3030）、
 *         通信失敗で `ISSUER_COMMUNICATION_FAILED`（3004）。
 */
export async function callRefreshEndpoint(
  service: RefreshServiceConfig,
  vc: VerifiableCredential,
  fetchImpl?: FetchLike,
  fetchReceiver?: object,
): Promise<string> {
  // 送信先・識別子は純データ。鎖読みだと `url` を**宣言していない** refreshService でも汚染値
  // （攻撃者の URL）が採用され、そこへ更新要求が飛ぶ。必須欄が欠けたら fail-closed に倒す。
  const url = ownProperty<string>(service, 'url');
  const refreshServiceId = ownProperty<string>(service, 'id');
  if (typeof url !== 'string' || typeof refreshServiceId !== 'string' || !isPublicHttpsUrl(url)) {
    throw new VericertsError(ErrorCodes.REFRESH_FAILED);
  }
  // `vc.id` は任意欄。省略時は継承値を混ぜず undefined のままにする（JSON 化で落ちる）。
  const credentialId = ownProperty<string>(vc, 'id');

  const body = JSON.stringify({ credentialId, refreshServiceId });
  // 注入された `fetchImpl` は `class Deps { async fetchImpl(url, init) {…} }` のように prototype
  // メソッドで実装され得る。取り出した関数を裸で呼ぶと、従来
  // `deps.fetchImpl(url, init)` で成立していた `this` 参照つき実装（証明書ピンニング設定や
  // 接続プールをインスタンスに持つ fetch など）が壊れるため、呼び出し元をレシーバに束ね直す。
  // 一方フォールバック先のグローバル `fetch` は `this` を差し替えると `Illegal invocation` に
  // なるため、注入されたときだけレシーバを渡す。
  //
  // 「注入されたか」の判定は**一箇所**（`injected`）で行い、呼び出す関数とレシーバの双方を
  // そこから導く。`fetchImpl ?? fetch`（null もグローバルへ倒れる）と `fetchImpl === undefined`
  // のように条件がずれていると、`deps.fetchImpl = null`（型のない JS 呼び出しでは有り得る）で
  // 「グローバル `fetch` に `deps` をレシーバとして束ねる」組み合わせが成立し、ブラウザでは
  // `Illegal invocation` の TypeError → 3004 へ潰れて既定 `fallback=keep-old` が無言で
  // リフレッシュを取り下げる。非関数はすべて「未注入」として扱う。
  const injected: FetchLike | undefined = typeof fetchImpl === 'function' ? fetchImpl : undefined;
  const doFetch: FetchLike = injected ?? (fetch as FetchLike);
  const fetchThis = injected === undefined ? undefined : fetchReceiver;
  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。`refreshService.url`
  // は受領済み VC 由来で攻撃者の影響下にあり、この経路はウォレットのバックグラウンドで無人実行
  // されるため、ヘッダだけ返して本文を引き延ばすサーバに無限に待ってはならない。
  const timer = setTimeout(() => controller.abort(), REFRESH_REQUEST_TIMEOUT_MS);
  let parsed: unknown;
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      response = await doFetch.call(fetchThis, url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body,
        // 3xx に追従して更新要求（credentialId を含む POST）を別ホスト・内部宛へ再送しない。
        // 3xx / opaqueredirect は `response.ok` が偽になり、下で REFRESH_FAILED に倒れる。
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch {
      // ネットワークエラー / タイムアウト（abort）。詳細は秘密を含み得るため正規化する。
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }

    // `redirect: 'manual'` を指定しても、注入された `fetchImpl` が 3xx を追従して返す場合がある。
    // 最終 URL が非公開 / 非 HTTPS（内部アドレス宛を含む）の応答、3xx / opaqueredirect は成功として
    // 受理しない（manifest 応募経路 `submitCredentialApplication` と同じ防御）。
    if (isRedirectedResponse(response) || !response.ok) {
      throw new VericertsError(ErrorCodes.REFRESH_FAILED);
    }
    // 自己申告の `content-length` で早期に落とし、実バイト数でも上限（1 MiB）で打ち切る。
    if (declaresOversizedBody(response)) {
      throw new VericertsError(ErrorCodes.REFRESH_FAILED);
    }

    try {
      const text = await readBodyWithinLimit(response);
      if (text === undefined) {
        // 上限超過。
        throw new VericertsError(ErrorCodes.REFRESH_FAILED);
      }
      parsed = parseJsonWithoutPrototype(text);
    } catch {
      // 本文読み出し中のネットワークエラー / abort / 上限超過 / パース失敗。
      // 応答本文（VC を含み得る）は message に載せない。
      throw new VericertsError(ErrorCodes.REFRESH_FAILED);
    }
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new VericertsError(ErrorCodes.REFRESH_FAILED);
  }
  // 応答は `parseJsonWithoutPrototype` 由来で `Object.prototype` を継承しないが、own 限定読みは
  // **多層防御として残す**。鎖読みだと応答が `{}` でも汚染値が
  // 「新しい生 VC」として採用され、攻撃者の VC に入れ替わる。
  const raw =
    ownProperty<unknown>(parsed, 'credential') ??
    ownProperty<unknown>(parsed, 'verifiableCredential');
  // 空白のみの値は VC として使えない。判定の実体は SDK 内の単一の共有ヘルパに置く。
  if (!isNonBlankString(raw)) {
    throw new VericertsError(ErrorCodes.REFRESH_FAILED);
  }
  return raw;
}
