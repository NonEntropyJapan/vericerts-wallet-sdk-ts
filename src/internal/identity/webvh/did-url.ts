/**
 * did:webvh の DID 構文パースと DID Log（did.jsonl）URL マッピング。
 *
 * `codec.ts` から再エクスポートされ、検証
 * （`verify.ts`）・メソッドプラグイン（`method-webvh.ts`）から共有される
 * （1 ファイル 300 行以下のため分割）。例外メッセージ・`context` に DID 文字列・URL を
 * 含めない。
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
import { consumeResolutionBody, type ResolutionWorkBudget } from '../resolution-budget.js';
import { encodeWebVhPathSegment, resolveWebVhHost } from './did-https.js';
import { MULTIHASH_BASE58_LENGTH } from './multihash.js';

/** `did:webvh:` メソッドプレフィックス。 */
export const DID_WEBVH_PREFIX = 'did:webvh:';

/** DID Log のファイル名。 */
const DID_JSONL_FILE = 'did.jsonl';

/** witness proof ファイル名（DID Log の隣、spec: The Witness Proofs File）。 */
const DID_WITNESS_FILE = 'did-witness.json';

/** path なし did:webvh の well-known ディレクトリ。 */
const WELL_KNOWN_DIR = '.well-known';

/** DID Log 取得のタイムアウト（ミリ秒、did:web と同じ値）。 */
const FETCH_TIMEOUT_MS = 10_000;

/**
 * DID Log として受理する media type（パラメータ部 `; charset=...` は除いて判定）。
 *
 * `Accept` ヘッダと応答の検査の**両方**をこの 1 つの集合から導く。片方だけを広げると
 * 「要求していない media type を受理する」状態になるためである。did.jsonl は JSON Lines で
 * あって JSON ではないので、`application/json` は受理しない。仕様（The DID to HTTPS Transformation 6.）は
 * `text/jsonl` を推奨（SHOULD）しており、従来の `application/jsonl` / `text/plain` と併せて受理する。
 *
 * `Content-Type` 無しの応答も受理しない（fail-closed）。did:web / did:ipid の取得経路と同じ判断で、
 * 「何を返したか宣言しない取得先」を信用しないほうが安全側である。
 */
const DID_LOG_MEDIA_TYPES: readonly string[] = ['text/jsonl', 'application/jsonl', 'text/plain'];

/** `did-witness.json` として受理する media type（仕様 The Witness Proofs File は `application/json` を推奨）。 */
export const DID_WITNESS_MEDIA_TYPES: readonly string[] = ['application/json'];

/**
 * DID Log を HTTPS 経由で取得する。
 *
 * リダイレクト追従後の最終 URL が HTTPS であることを検証し、HTTP エラー・タイムアウト・
 * 非 HTTPS リダイレクト・本文の上限超過はいずれも「解決（取得）失敗」として `DID_NOT_FOUND`
 * （code `2003`）にマップする（DID 文字列形式不正 `2001` とは区別する）。例外メッセージ・
 * `context` に URL・Log 本文を含めない。
 *
 * **本文は `MAX_DOCUMENT_BYTES`（1 MiB）の内側で読む。** 取得先の `domain` は受領した VC の
 * `iss` 由来であり攻撃者が選べるため、上限なしに読むと提示された VC 一つで無制限の JSONL を
 * メモリへ流し込める（`http/body-limit.ts`）。同じ理由で `clearTimeout` は**本文を読み終えてから**
 * 行う。ヘッダだけ先に返して本文を引き延ばす応答を 10 秒の予算の外に出さないためである。
 *
 * **Content-Type も同じ理由で検査する。** 取得先を攻撃者が選べる以上、返ってくるのは DID Log とは
 * 限らない。`text/html` のエラーページをそのまま JSONL の行パーサへ渡さないよう、
 * `mediaTypes`（既定は DID Log 用の {@link DID_LOG_MEDIA_TYPES}）の外の media type は本文を読む前に拒否する（did:web / did:ipid の
 * 取得経路と揃える）。
 *
 * @param url DID Log の URL。
 * @param fetchFn 使用する fetch 実装（未指定ならグローバル `fetch`）。ホストアプリが証明書
 *   ピン留め済みの `fetch` を注入できるようにするための seam であり、グローバル `fetch` を
 *   直に呼ぶとこの経路だけがピン留めを失う（`fetchDidWebDocument` と同じ形）。
 * @param scope 解決スコープ全体の予算。本文を読み終えた直後（パース・検証の前）に本文長を計上する。
 * @param mediaTypes 受理する media type（`did-witness.json` の取得は {@link DID_WITNESS_MEDIA_TYPES} を渡す。拘束（公開 HTTPS・リダイレクト・本文上限・タイムアウト・取得失敗は `2003`）は DID Log と同じ。`fetch` の参照が別の関数へ流れると外部取得の許可リストの拘束判定が崩れるため、`did-witness.json` の取得も専用の薄いラッパを作らず本関数を直接呼ぶ）。
 * @returns 本文テキスト。
 * @throws 本文量の予算超過（code `2001`、`resolution_work_limit`）、取得失敗（HTTP エラー / タイムアウト / 非 HTTPS リダイレクト / Content-Type 不一致 /
 *   上限超過）の場合（code `2003`）。
 */
export async function fetchDidLog(
  url: string,
  fetchFn: typeof fetch = fetch,
  scope?: ResolutionWorkBudget,
  mediaTypes: readonly string[] = DID_LOG_MEDIA_TYPES,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      response = await fetchFollowingPublicRedirects(fetchFn, url, {
        method: 'GET',
        signal: controller.signal,
        headers: { Accept: mediaTypes.join(', ') },
      });
    } catch {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    // HTTPS 判定は共有ヘルパーに寄せる（`https-url.ts`）。`startsWith('https://')` はホスト無しの
    // `https://` を通すため、経路ごとに条件がずれる。
    if (response.url.length > 0 && !isPublicHttpsUrl(response.url)) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    if (!response.ok) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    // 要求していない media type（`text/html` のエラーページ等）は行パーサへ渡さない。
    if (!isAllowedContentType(response.headers.get('content-type'), mediaTypes)) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
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
    // パース・検証より前に、スコープ全体の本文量で拒否する。
    consumeResolutionBody(scope, text.length);
    return text;
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}

/** did:webvh DID の構造化表現（scid / domain / path セグメント。いずれも DID 文字列上の表記＝パーセントエンコード済み）。 */
export interface ParsedWebVh {
  readonly scid: string;
  readonly domain: string;
  readonly pathSegments: readonly string[];
}

/** SCID の ABNF（base58btc 文字 46 個）。 */
const SCID_PATTERN = /^[1-9A-HJ-NP-Za-km-z]+$/;

/**
 * did:webvh 文字列を構造化する。`did:webvh:` 除去後 `:` で分割し scid / domain / path に
 * 割り当てる。scid は base58btc 文字 46 個、domain と path セグメントは仕様の ABNF と検証規則に従う
 * （`./did-https.ts`。`? # @ \` や `.` / `..`、パーセントエンコードされた区切り、IP ホストで取得先が DID の示す場所から
 * ずれるのを防ぐ）。DID URL（`/` `?` `#`）は DID ではないので拒否する。
 *
 * @param did did:webvh 文字列。
 * @returns scid / domain / path セグメント。
 * @throws プレフィックス不正・セグメント不足・空セグメント・scid / domain / path の検証失敗の場合（VericertsError、code `2001`）。
 */
export function parseWebVh(did: string): ParsedWebVh {
  if (!did.startsWith(DID_WEBVH_PREFIX)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const segments = did.slice(DID_WEBVH_PREFIX.length).split(':');
  const [scid, domain, ...pathSegments] = segments;
  if (
    scid === undefined ||
    domain === undefined ||
    scid.length !== MULTIHASH_BASE58_LENGTH ||
    !SCID_PATTERN.test(scid)
  ) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // domain と path の検証（空セグメントを含む）。変換が成功することで ABNF とデコード後の規則を確かめる。
  webVhBaseUrl({ scid, domain, pathSegments });
  return { scid, domain, pathSegments };
}

/**
 * 構造化済み did:webvh から、DID Log と witness proof ファイルを置くディレクトリ URL（末尾 `/` なし）を構築する。
 * path なしは `https://host[:port]/.well-known`、path ありは `https://host[:port]/{path}`。
 *
 * @param parsed 構造化済み did:webvh（手組みも許すため、`parseWebVh` を通っていなくても同じ検証を課す）。
 * @throws domain / path の検証失敗の場合（VericertsError、code `2001`）。
 */
function webVhBaseUrl(parsed: ParsedWebVh): string {
  const { host, port } = resolveWebVhHost(parsed.domain);
  const authority = port === undefined ? host : `${host}:${port}`;
  const pathPart =
    parsed.pathSegments.length === 0
      ? WELL_KNOWN_DIR
      : parsed.pathSegments.map(encodeWebVhPathSegment).join('/');
  let url: URL;
  try {
    url = new URL(`https://${authority}/${pathPart}`);
  } catch {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (url.protocol !== 'https:' || url.search !== '' || url.hash !== '') {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return url.toString();
}

/**
 * DID Log（did.jsonl）の取得 URL を構築する（spec: The DID to HTTPS Transformation）。
 *
 * @throws domain / path の検証失敗の場合（VericertsError、code `2001`）。
 */
export function webVhLogUrl(parsed: ParsedWebVh): string {
  return `${webVhBaseUrl(parsed)}/${DID_JSONL_FILE}`;
}

/**
 * witness proof ファイル（did-witness.json）の取得 URL を構築する。DID Log の URL の末尾 `did.jsonl` だけを
 * 置き換えたもの（spec: The Witness Proofs File）。
 *
 * @throws domain / path の検証失敗の場合（VericertsError、code `2001`）。
 */
export function webVhWitnessUrl(parsed: ParsedWebVh): string {
  return `${webVhBaseUrl(parsed)}/${DID_WITNESS_FILE}`;
}
