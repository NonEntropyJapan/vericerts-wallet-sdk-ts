/**
 * 設定値の HTTPS エンドポイントから JSON を取得する did:ebsi / did:ion / did:cheqd 共通の取得層。
 *
 * 3 メソッドは取得先（EBSI ノード / Sidetree ノード / cheqd リゾルバー）を**呼び出し側の設定値**で指定し、
 * DID 文字列からは導出しない。取得は `http/public-redirect-fetch.ts` を使い、リダイレクトをホップごとに
 * 公開 HTTPS 宛へ検査する。本文は `MAX_DOCUMENT_BYTES`（1 MiB）の内側で読み、パースの前に解決スコープへ
 * 計上する（`did-web-fetch.ts` と同じ規則）。
 *
 * エラーコード粒度（did-web-fetch.ts と同じ）:
 * - 取得失敗（ネットワークエラー / タイムアウト / HTTP 非 2xx / 非公開・非 HTTPS 宛 / 上限超過）→ `2003`
 * - Content-Type 不一致 / JSON 不正 → `2010`
 *
 * セキュリティ上の注意: 例外メッセージや `context` に DID・URL・レスポンス本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  declaresOversizedBody,
  discardBody,
  isAllowedContentType,
  OVERSIZED_BODY_REASON,
  readBodyWithinLimit,
} from '../../http/body-limit.js';
import { fetchFollowingPublicRedirects } from '../../http/public-redirect-fetch.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import {
  assertResolutionWorkRemaining,
  consumeResolutionBody,
  type ResolutionWorkBudget,
} from '../resolution-budget.js';

/** 解決 1 回のタイムアウト（ミリ秒。本文の読み出しまでを覆う）。 */
const RESOLVE_TIMEOUT_MS = 10_000;

/** {@link fetchResolverJson} の取得条件。 */
export interface ResolverJsonRequest {
  /** 取得先 URL（{@link buildEndpointUrl} の結果）。 */
  readonly url: string;
  /** `Accept` ヘッダ値。 */
  readonly accept: string;
  /** 受理する Content-Type（パラメータ部は除いて判定）。 */
  readonly contentTypes: readonly string[];
  /** 使用する fetch 実装（未指定ならグローバル `fetch`）。 */
  readonly fetchFn?: typeof fetch;
  /** 解決スコープの予算（未指定なら計上しない）。 */
  readonly scope?: ResolutionWorkBudget;
  /**
   * 2xx に加えて本文を読む HTTP ステータス（例: DID Resolution の `410 Gone`）。省略時は 2xx のみで、
   * それ以外は `2003`。読んだ本文の扱い（拒否するか）は呼び出し側が `status` を見て決める。
   */
  readonly extraStatuses?: readonly number[];
}

/** 取得して JSON パースした結果と、スコープへ計上した本文の文字数。 */
export interface ResolverJsonResult {
  readonly value: unknown;
  /** HTTP ステータス。 */
  readonly status: number;
  /** 本文の文字数（キャッシュの重みに使う）。 */
  readonly bodyLength: number;
}

/**
 * 設定値のベース URL と DID から取得先 URL を組み立てる。
 *
 * ベース URL は `https:` のみ受理し、資格情報（userinfo）・クエリ・フラグメントを持つものは拒否する。
 * 設定ミスは取得を始めず `2003`（`context.reason: 'insecure_endpoint_url'`）にする（did:ipid の
 * `insecure_api_url` と同じく、宛先を安全に決められないので到達不能として扱う）。
 *
 * @param baseUrl 設定値のベース URL（末尾の `/` は無視する）。
 * @param path ベースの下のパス（先頭 `/` 付き。DID を含めてよい。呼び出し側が文字種を検査済みであること）。
 * @param query 付加するクエリ（値は URL エンコードする）。
 * @throws ベース URL が HTTPS でない / パースできない / 余分な要素を持つ場合（code `2003`）。
 */
export function buildEndpointUrl(
  baseUrl: string,
  path: string,
  query: Readonly<Record<string, string>> = {},
): string {
  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    throw insecureEndpoint();
  }
  if (
    base.protocol !== 'https:' ||
    base.username !== '' ||
    base.password !== '' ||
    base.search !== '' ||
    base.hash !== ''
  ) {
    throw insecureEndpoint();
  }
  const prefix = base.pathname.endsWith('/') ? base.pathname.slice(0, -1) : base.pathname;
  const pairs = Object.entries(query).map(
    ([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`,
  );
  const search = pairs.length === 0 ? '' : `?${pairs.join('&')}`;
  return `${base.origin}${prefix}${path}${search}`;
}

function insecureEndpoint(): VericertsError {
  return new VericertsError(ErrorCodes.DID_NOT_FOUND, {
    context: { reason: 'insecure_endpoint_url' },
  });
}

/**
 * HTTPS GET で JSON を取得してパースする。
 *
 * 本文量が尽きたスコープでは取得自体を始めない。`clearTimeout` は本文読了後に行い、本文を読まずに
 * throw した経路でも接続を解放する。
 *
 * @throws 取得失敗（code `2003`）・Content-Type / JSON 不正（code `2010`）・
 *   スコープの本文量超過（code `2001`、`resolution_work_limit`）。
 */
export async function fetchResolverJson(request: ResolverJsonRequest): Promise<ResolverJsonResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RESOLVE_TIMEOUT_MS);
  let response: Response | undefined;
  try {
    assertResolutionWorkRemaining(request.scope, 0);
    try {
      response = await fetchFollowingPublicRedirects(request.fetchFn ?? fetch, request.url, {
        method: 'GET',
        signal: controller.signal,
        headers: { Accept: request.accept },
      });
    } catch {
      // ネットワークエラー / タイムアウト / 非公開・非 HTTPS 宛のリダイレクト。詳細は秘密を含み得る。
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    const extraStatuses = ownProperty<readonly number[]>(request, 'extraStatuses');
    if (!response.ok && !(extraStatuses?.includes(response.status) ?? false)) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    if (!isAllowedContentType(response.headers.get('content-type'), request.contentTypes)) {
      throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
    }
    if (declaresOversizedBody(response)) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND, {
        context: { reason: OVERSIZED_BODY_REASON },
      });
    }
    let text: string | undefined;
    try {
      text = await readBodyWithinLimit(response);
    } catch {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    if (text === undefined) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND, {
        context: { reason: OVERSIZED_BODY_REASON },
      });
    }
    // JSON.parse のヒープ増幅より前に、スコープ全体の本文量で拒否する。
    consumeResolutionBody(request.scope, text.length);
    let value: unknown;
    try {
      value = parseJsonWithoutPrototype(text);
    } catch {
      throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
    }
    return { value, status: response.status, bodyLength: text.length };
  } finally {
    clearTimeout(timer);
    discardBody(response);
  }
}

/** 値が配列でないプレーンオブジェクトなら返し、そうでなければ `2010`。 */
export function asJsonObject(value: unknown): Readonly<Record<string, unknown>> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  return value as Readonly<Record<string, unknown>>;
}
