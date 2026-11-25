/**
 * did:web の `did.json` 取得と DID Document 検証。
 *
 * `method-web.ts` から「ネットワーク取得とレスポンス検証」だけを切り出したモジュール。
 * キャッシュ層（`did-web-cache.ts`）はここで得た `Cache-Control` を使って TTL を決めるため、
 * 取得結果は DID Document とヘッダ値の組で返す。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・URL・レスポンス本文を含めない。
 * - TLS 1.2+ はランタイム（Bun/Node のグローバル `fetch`）の既定に依拠する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  declaresOversizedBody,
  discardBody,
  isAllowedContentType,
  readBodyWithinLimit,
} from '../../http/body-limit.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import { fetchFollowingPublicRedirects } from '../../http/public-redirect-fetch.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type { DIDDocument } from '../did.js';
import { assertNetworkDidDocumentShape } from '../did-document-read.js';
import { consumeResolutionBody, type ResolutionWorkBudget } from '../resolution-budget.js';
import type { DidWebFetchResult } from './did-web-cache.js';

/** 受理する Content-Type（パラメータ部 `; charset=...` は除いて判定）。 */
const ALLOWED_CONTENT_TYPES: ReadonlyArray<string> = ['application/did+json', 'application/json'];

/** 解決のタイムアウト（ミリ秒）。 */
const RESOLVE_TIMEOUT_MS = 10_000;

/**
 * `fetch` のレスポンス本文を DIDDocument にパースする。
 *
 * JSON.parse の結果が DID Core の最小構造（`id` 文字列を持つオブジェクト）であることを
 * 検証する。JSON parse 失敗・`id` を欠く・型不一致・非オブジェクトは「DID ドキュメント
 * スキーマ不正」として `DID_DOC_INVALID`（code `2010`）に正規化する（取得は成功している
 * ため取得失敗 `2003` とは区別する）。
 *
 * さらに `doc.id` が解決対象 DID（`expectedDid`）と一致することを検証する。これがないと
 * `did:web:trusted.example` を解決して別 DID のドキュメントが返っても成功扱いになり、
 * DID の取り違え／なりすましを許してしまう（W3C did:web 仕様: 取得した DID Document の
 * `id` は解決対象の DID と一致しなければならない）。
 *
 * 照合は**バイト単位の完全一致**（fail-closed）で行う。なりすましの見逃しは起こらないが、
 * ポート表記の揺れ（`did:web:host%3A8443` と `did:web:host:8443` は同一 URL に解決される）
 * では `id` 不一致として拒否されうる。`didWebToUrl` は URL 化時に `%3A` をデコードするが、
 * `id` 照合はデコードしない。したがって発行者の `did.json` の `id` と解決入力 DID は同一表記で
 * 統一する必要がある。安全側に倒すための意図的な設計判断であり、
 * 正規化による緩和は安全性を下げるため行わない。
 *
 * @param text レスポンス本文（JSON 文字列）。
 * @param expectedDid 解決対象の did:web 文字列（`doc.id` の照合先）。
 * @returns DIDDocument。
 * @throws JSON 不正・構造不正・`id` 不一致の場合（VericertsError、code `2010`）。
 */
function parseDidDocument(text: string, expectedDid: string): DIDDocument {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(text);
  } catch {
    // 本文に秘密が含まれ得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  const doc = parsed as Record<string, unknown>;
  if (typeof doc.id !== 'string' || doc.id.length === 0) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  // 解決対象 DID と取得ドキュメントの id が不一致なら取り違え／なりすましとして拒否する。
  if (doc.id !== expectedDid) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  const document = parsed as DIDDocument;
  // 欠落は許容し、配列でない verificationMethod / relationship / service は 2010。
  assertNetworkDidDocumentShape(document);
  return document;
}

/**
 * HTTPS GET で `did.json` を取得し、DID Document として検証する。
 *
 * キャッシュ層から呼ばれる「ネットワーク取得そのもの」であり、TTL 決定に必要な
 * `Cache-Control` ヘッダを DID Document と一緒に返す。
 *
 * @param url 取得先 HTTPS URL（`didWebToUrl` の結果）。
 * @param did 解決対象 DID（`doc.id` の照合先）。
 * @param fetchFn 使用する fetch 実装（未指定ならグローバル `fetch`）。
 * @param scope 解決スコープの予算。本文を読み終えた直後（パースの前）に本文長を計上する。
 * 本文は `MAX_DOCUMENT_BYTES`（1 MiB）の内側で読み、`clearTimeout` は本文読了後に行う
 * （`http/body-limit.ts`）。取得先ドメインは解決対象 DID 由来で攻撃者が選べるため、
 * 上限も abort 窓も本文読み出しまで及ばせる。
 *
 * @returns DID Document と `Cache-Control` ヘッダ値。
 * @throws 取得失敗（タイムアウト / 非 HTTPS リダイレクト / 上限超過を含む、code `2003`）・
 *   Content-Type / JSON / スキーマ不正（code `2010`）。
 */
export async function fetchDidWebDocument(
  url: string,
  did: string,
  fetchFn: typeof fetch = fetch,
  scope?: ResolutionWorkBudget,
): Promise<DidWebFetchResult> {
  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。
  const timer = setTimeout(() => controller.abort(), RESOLVE_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      response = await fetchFollowingPublicRedirects(fetchFn, url, {
        method: 'GET',
        signal: controller.signal,
        headers: { Accept: ALLOWED_CONTENT_TYPES.join(', ') },
      });
    } catch {
      // ネットワークエラー / タイムアウト（abort）。詳細は秘密を含み得るため正規化する。
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    // リダイレクト先が HTTPS にとどまっていることを最終 URL のスキームで検証する
    // （判定は共有ヘルパー `https-url.ts` に寄せる）。
    if (response.url.length > 0 && !isPublicHttpsUrl(response.url)) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    if (!response.ok) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    // Content-Type 不一致は取得は成功しているため「ドキュメント不正」に分類する。判定は共有
    // ヘルパー（`http/body-limit.ts`）に寄せる。ヘッダ欠落は既定どおり拒否する（fail-closed）。
    if (!isAllowedContentType(response.headers.get('content-type'), ALLOWED_CONTENT_TYPES)) {
      throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
    }
    // 自己申告の `content-length` で早期に落とし、実バイト数でも打ち切る。
    if (declaresOversizedBody(response)) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    let text: string | undefined;
    try {
      text = await readBodyWithinLimit(response);
    } catch {
      // 本文読み出し中のネットワークエラー / abort。本文・URL は載せない。
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    if (text === undefined) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    // JSON.parse のヒープ増幅（本文の 20〜30 倍）より前に、スコープ全体の本文量で拒否する。
    consumeResolutionBody(scope, text.length);
    return {
      document: parseDidDocument(text, did),
      cacheControl: response.headers.get('cache-control'),
      bodyLength: text.length,
    };
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}
