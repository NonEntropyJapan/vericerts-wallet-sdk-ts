/**
 * WUA の取得で使う HTTP リクエストと応答パーサー。
 *
 * ## なぜ `obtain.ts` から分けるか
 *
 * 分割の境界は行数ではなく**責務**で引いている。本モジュールが持つのは「攻撃者が影響し得る
 * URL への HTTP POST」という 1 つの攻撃面と、その入口検査（HTTPS 限定・リダイレクト追跡・
 * タイムアウト・応答本文の own 限定パース）だけである。2 段フローになったことで同じ検査を
 * `/wua/challenge` と `/wua/issue` の**両方**に適用する必要が生じたため、検査を 1 か所へ
 * 閉じ込めて監査可能にする（`eudi/issuance/metadata.ts` と同じ方針）。オーケストレーション
 * （鍵・時刻の検査、デバイスバインド Proof の生成、取得後の WUA 検証）は `obtain.ts` に残す。
 *
 * ## 要求・応答形式は本 SDK が 1 形に固定する
 * Wallet Provider の challenge 応答から `challenge` / `nonce`、発行応答から `wallet_attestation` を読む。
 *
 * セキュリティ上の注意:
 * - HTTPS 検査は呼び出し元（`obtain.ts`）が `providerEndpoint` に対して済ませ、本モジュールは
 *   リダイレクト後も HTTPS にとどまることを最終 URL で確認する（SSRF / 平文降格の防止）。
 * - `clearTimeout` は**本文を読み切った後**に行う。ヘッダだけ先に返して本文を引き延ばす応答で
 *   無限に待たないためである（`credential/json-schema/fetch-document.ts` と同じ形）。
 * - 例外の `message` / `context` / `cause` に URL・応答本文・JWT・鍵素材を一切載せない。
 *   `context` は固定文字列の `reason` だけを持つ。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { resolveInjectedFetch } from '../../fetch-di.js';
import { declaresOversizedBody, discardBody, readBodyWithinLimit } from '../../http/body-limit.js';
import { isRedirectedResponse } from '../../http/public-https-url.js';
import { trimTrailingSlashes } from '../../primitives/trim-trailing-slashes.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';

/** WUA 取得のタイムアウト（ミリ秒）。応答ヘッダだけ返して本文を引き延ばす経路も含めて覆う。 */
const WUA_OBTAIN_TIMEOUT_MS = 10_000;

/** challenge 要求のパス。 */
const WUA_CHALLENGE_PATH = '/wua/challenge';

/** WUA 発行要求のパス。 */
const WUA_ISSUE_PATH = '/wua/issue';

/**
 * `/wua/issue` の応答 JSON が WUA JWT を載せるフィールド名。
 *
 * 本 SDK は「JSON object の `wallet_attestation` にコンパクト JWS を載せる」1 形だけを受理する。
 */
const WUA_RESPONSE_JWT_FIELD = 'wallet_attestation';

/** `/wua/challenge` の応答から読み取る値（`wp_policy` は本 SDK では使わない）。 */
export interface WuaChallenge {
  /** デバイスバインド Proof が署名対象に含める challenge。 */
  readonly challenge: string;
  /** 同じく Proof に含める nonce（リプレイ防止）。 */
  readonly nonce: string;
}

/** 取得失敗（10101、再試行可）を固定理由で組み立てる。URL・本文・JWT・`cause` は載せない。 */
export function fetchFailed(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.WUA_FETCH_FAILED, { context: { reason } });
}

/**
 * `providerEndpoint` と固定パスから要求 URL を組み立てる。
 *
 * 末尾スラッシュを除去してから連結する（`https://wp.example/` をそのまま連結すると
 * `//wua/challenge` になり、Wallet Provider によっては 404 になる。`issuance/metadata.ts` の
 * `buildMetadataUrl` と同じ扱い）。
 *
 * @param providerEndpoint Wallet Provider Backend のベース URL（HTTPS。呼び出し元が検査済み）。
 * @param path `/wua/challenge` または `/wua/issue`。
 * @returns 連結後の要求 URL。
 */
function buildWuaUrl(providerEndpoint: string, path: string): string {
  return `${trimTrailingSlashes(providerEndpoint)}${path}`;
}

/**
 * JSON 本文を POST し、応答本文のテキストを返す。
 *
 * `fetchImpl` は関数値 DI なので `resolveInjectedFetch`（横断 `internal/fetch-di.ts`）で
 * 解決し、取り出し元（`options`）をレシーバに束ねて呼ぶ（own 限定で読むと prototype メソッドで
 * 注入した正当な DI が無言でグローバル `fetch` へ差し替わり、鎖読みだと `Object.prototype` 汚染下で
 * **指定していない**呼び出しが攻撃者の fetch に委譲される）。
 *
 * @param url 要求 URL（HTTPS）。
 * @param body JSON 直列化して送る要求本文。
 * @param options `fetchImpl` の読み取り元。
 * @returns 応答本文のテキスト。
 * 本文は `MAX_DOCUMENT_BYTES`（1 MiB）の内側で読む（`http/body-limit.ts`）。上限超過の理由は
 * `fetch-json.ts` の {@link import('../../http/fetch-json.js').JsonFetchReason} と同じ
 * `oversized_body` を使う（同じ共有検査の失敗に経路ごとの別名を与えない）。
 *
 * @throws ネットワーク失敗・タイムアウト・非 2xx・平文へのリダイレクト・本文の上限超過の場合
 *   （code `10101`）。
 */
async function postJson(url: string, body: object, options: object): Promise<string> {
  const { doFetch, receiver } = resolveInjectedFetch(options);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WUA_OBTAIN_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      response = await doFetch.call(receiver, url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(body),
        // 3xx に追従して本文を別ホストへ再送しない。
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch {
      // ネットワークエラー / タイムアウト（abort）。URL を漏らさないため cause は握りつぶす。
      throw fetchFailed('network_error');
    }
    // リダイレクト先が HTTPS にとどまっていることを最終 URL のスキームで検証する
    // （判定は共有ヘルパー `https-url.ts` に寄せる）。
    if (isRedirectedResponse(response)) {
      throw fetchFailed('insecure_redirect');
    }
    if (!response.ok) {
      throw fetchFailed('unexpected_status');
    }
    // 自己申告の `content-length` で早期に落とし、実バイト数でも打ち切る。
    if (declaresOversizedBody(response)) {
      throw fetchFailed('oversized_body');
    }
    let text: string | undefined;
    try {
      text = await readBodyWithinLimit(response);
    } catch {
      // 本文読み出し中のネットワークエラー / abort。本文は載せない。
      throw fetchFailed('network_error');
    }
    if (text === undefined) {
      throw fetchFailed('oversized_body');
    }
    return text;
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}

/**
 * 応答本文を JSON object へパースする。
 *
 * `parseJsonWithoutPrototype` でプロトタイプを持たないオブジェクトに変換する。呼び出し側では自身のプロパティだけを読み取る。
 *
 * @param body 応答本文のテキスト。
 * @returns パース済みの JSON object。
 * @throws JSON でない・object でない場合（code `10101`）。
 */
function parseJsonObject(body: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(body);
  } catch {
    // 応答本文は message に載せない。
    throw fetchFailed('invalid_json');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw fetchFailed('not_a_json_object');
  }
  return parsed as Record<string, unknown>;
}

/**
 * `POST <providerEndpoint>/wua/challenge` で challenge / nonce を取得する。
 *
 * 要求本文は `{ "devicePubKey": <公開鍵 JWK> }`。応答の `challenge` / `nonce` は `ownProperty` で
 * own 限定に読む（鎖読みだと当該フィールドを持たない応答でも `Object.prototype` の汚染値が
 * **署名対象の challenge として供給される**）。`wp_policy` は本 SDK では使わないため読まない。
 *
 * @param providerEndpoint Wallet Provider Backend のベース URL（HTTPS）。
 * @param devicePublicKeyJwk デバイスバインド Proof の署名鍵に対応する公開鍵 JWK。
 * @param options `fetchImpl` の読み取り元。
 * @returns challenge と nonce。
 * @throws 通信失敗・非 2xx・平文へのリダイレクト・非 JSON・`challenge` / `nonce` の欠落や
 *         空白のみの場合（code `10101`）。
 */
export async function requestWuaChallenge(
  providerEndpoint: string,
  devicePublicKeyJwk: object,
  options: object,
): Promise<WuaChallenge> {
  const parsed = parseJsonObject(
    await postJson(
      buildWuaUrl(providerEndpoint, WUA_CHALLENGE_PATH),
      { devicePubKey: devicePublicKeyJwk },
      options,
    ),
  );
  const challenge = ownProperty<unknown>(parsed, 'challenge');
  const nonce = ownProperty<unknown>(parsed, 'nonce');
  if (!isNonBlankString(challenge) || !isNonBlankString(nonce)) {
    throw fetchFailed('invalid_challenge_response');
  }
  return { challenge, nonce };
}

/** `POST <providerEndpoint>/wua/issue` で WUA JWT を取得する。
 *
 * 要求本文は `{ "assertion": <デバイスバインド Proof の JWS> }` で、`devicePosture` が
 * `undefined` のときは `device_posture` **キー自体を載せない**（`undefined` を載せると
 * 「送っていない」ことと「空を送った」ことが Wallet Provider 側で区別できなくなる）。
 *
 * @param providerEndpoint Wallet Provider Backend のベース URL（HTTPS）。
 * @param assertion デバイスバインド Proof（コンパクト JWS）。
 * @param devicePosture 呼び出し側が組み立てた不透明な device posture。`undefined` なら送らない。
 * @param options `fetchImpl` の読み取り元。
 * @returns WUA JWT（コンパクト JWS）。
 * @throws 通信失敗・非 2xx・平文へのリダイレクト・非 JSON・`wallet_attestation` の欠落や
 *         空白のみの場合（code `10101`）。
 */
export async function requestWuaIssuance(
  providerEndpoint: string,
  assertion: string,
  devicePosture: unknown,
  options: object,
): Promise<string> {
  const parsed = parseJsonObject(
    await postJson(
      buildWuaUrl(providerEndpoint, WUA_ISSUE_PATH),
      {
        assertion,
        ...(devicePosture === undefined ? {} : { device_posture: devicePosture }),
      },
      options,
    ),
  );
  const jwt = ownProperty<unknown>(parsed, WUA_RESPONSE_JWT_FIELD);
  if (!isNonBlankString(jwt)) {
    throw fetchFailed('missing_attestation_jwt');
  }
  return jwt;
}
