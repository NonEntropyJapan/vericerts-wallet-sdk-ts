/**
 * did:ipid の IPFS Gateway クライアント（解決用）。
 *
 * 解決（resolve）: IPFS Gateway 経由で DID Document を取得する。
 * - CID:  `GET <gateway>/ipfs/<CID>`
 * - IPNS: `GET <gateway>/ipns/<name>`（署名付きレコード。検証済みの解決先 CID を `/ipfs/<CID>` で取得し直す）
 *
 * 公開（create / update）の IPFS HTTP API 呼び出しは `ipfs-api.ts` にある（1 ファイル 300 行以下）。
 * 双方が使う設定（{@link IpidGatewayConfig}）・タイムアウト・URL 正規化は本モジュールが持つ。
 *
 * エラーコードの分類:
 * - 取得失敗（network / 4xx / 5xx / timeout / 平文への降格 / 本文の上限超過）→ `DID_NOT_FOUND`
 *   （2003、再試行可）。
 * - Content-Type 不正 / JSON parse 失敗 / スキーマ不正 / CID とのハッシュ不一致
 *   （`context.reason: 'cid_mismatch'` / 照合不能な CID は `'cid_unverifiable'`）→ `DID_DOC_INVALID`（2010）。
 *
 * タイムアウトの既定値は 30 秒（IPNS 解決は遅延し得るため）。AbortController で実装し、
 * **本文の読み出しまでを 1 つの予算で覆う**（`clearTimeout` は本文読了後）。ヘッダだけ先に返して
 * 本文を引き延ばす応答を予算の外に出さないためである。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に Gateway URL・DID・本文・鍵バイトを含めない。`context.reason` に載せるのは固定の識別子だけである。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  declaresOversizedBody,
  discardBody,
  isAllowedContentType,
  readBytesWithinLimit,
} from '../../http/body-limit.js';
import { isPublicHttpsUrl, isRedirectResponse } from '../../http/public-https-url.js';
import { fetchFollowingPublicRedirects } from '../../http/public-redirect-fetch.js';
import { isHttpsUrl } from '../../https-url.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type { DIDDocument } from '../did.js';
import { assertNetworkDidDocumentShape } from '../did-document-read.js';
import {
  assertResolutionWorkRemaining,
  consumeResolutionBody,
  type ResolutionWorkBudget,
} from '../resolution-budget.js';
import { verifyRawCidContent } from './cid.js';
import {
  ed25519KeyFromIpnsName,
  IPNS_RECORD_CONTENT_TYPE,
  MAX_IPNS_RECORD_BYTES,
  verifyIpnsRecord,
} from './ipns-record.js';

/** 受理する Content-Type（パラメータ部 `; charset=...` は除いて判定）。 */
const ALLOWED_CONTENT_TYPES: ReadonlyArray<string> = ['application/did+json', 'application/json'];

/**
 * Gateway 取得・API 呼び出しのタイムアウト（ミリ秒、既定値は 30 秒）。
 *
 * 公開経路（`ipfs-api.ts`）も同じ予算を使う。IPFS ノードへの POST は解決と同じネットワーク条件に
 * 置かれるため、経路ごとに別の数字を持つと片方だけが無期限に待つ状態が生まれる。
 */
export const IPID_HTTP_TIMEOUT_MS = 30_000;

/** IPFS Gateway / API のエンドポイント設定。 */
export interface IpidGatewayConfig {
  /** DID Document 取得用の Gateway URL（既定 `https://ipfs.io`）。末尾スラッシュは任意。 */
  readonly gatewayUrl: string;
  /** 公開用 IPFS HTTP API URL（既定 `http://localhost:5001`）。 */
  readonly apiUrl: string;
}

/** Gateway と API の既定設定。 */
export const DEFAULT_IPID_GATEWAY: IpidGatewayConfig = {
  gatewayUrl: 'https://ipfs.io',
  apiUrl: 'http://localhost:5001',
};

/**
 * 末尾スラッシュを取り除いた base URL を返す。
 *
 * 解決（本モジュール）と公開（`ipfs-api.ts`）の双方が同じ正規化を要するため export する。
 */
export function trimTrailingSlash(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

/**
 * レスポンス本文を DIDDocument にパースする。
 *
 * IPFS 上の正規形に自身の CID を含めると CID の計算が自己参照になる。
 * 取得した JSON の `id` が空または未設定なら、解決に使った DID（`expectedDid`）で補完する。
 * `id` が存在し、かつ `expectedDid` と一致しない場合は別 DID への参照で不整合のため拒否する。
 *
 * JSON parse 失敗・型不一致・非オブジェクト・id 不整合は `DID_DOC_INVALID`（2010）に正規化する。
 *
 * @param text レスポンス本文（JSON 文字列）。
 * @param expectedDid 解決に使った DID 文字列（id 補完・整合性検証に使う）。
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
  // id が無い/空（canonical form）なら要求 DID で補完。存在するなら要求 DID と一致必須。
  if (doc.id === undefined || (typeof doc.id === 'string' && doc.id.length === 0)) {
    const filled = { ...(parsed as DIDDocument), id: expectedDid };
    assertNetworkDidDocumentShape(filled);
    return filled;
  }
  if (typeof doc.id !== 'string' || doc.id !== expectedDid) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  const document = parsed as DIDDocument;
  assertNetworkDidDocumentShape(document);
  return document;
}

/**
 * リダイレクト追従で平文へ降格していないか判定する。
 *
 * **降格だけを禁じ、平文そのものは禁じない。** `gatewayUrl` はローカルノードの
 * `http://127.0.0.1:8080` でも正当に設定でき、そこへ無条件の HTTPS 要求を課すと既存の設定が
 * 取得ごと失敗する。一方 HTTPS で始めた取得が平文で終わるのは、取得元が選んだ降格であって
 * 利用者の選択ではないため拒否する。判定は共有ヘルパー（`https-url.ts`）に寄せる。
 *
 * @param requestUrl 取得に使ったリクエスト URL。
 * @param response 応答（`response.url` が空なら追跡できないため判定しない）。
 * @returns 平文へ降格していれば `true`。
 */
function downgradedToPlaintext(requestUrl: string, response: Response): boolean {
  return isHttpsUrl(requestUrl) && response.url.length > 0 && !isHttpsUrl(response.url);
}

/**
 * Gateway へ GET する。
 *
 * 公開 HTTPS の Gateway はリダイレクトを**ホップごとに**公開 HTTPS 宛へ縛って追従する
 * （`http/public-redirect-fetch.ts`）。`redirect: 'follow'` のままだと、Gateway が 3xx で内部ホスト・
 * 平文へ誘導しても GET が送出され、最終 URL の事後検査では遅い。ローカルノード
 * （`http://127.0.0.1:8080` 等）は設定者が明示した開発構成なので初回の取得だけ許し、
 * リダイレクトは追従せず呼び出し側で拒否する。
 */
async function getFromGateway(url: string, init: Omit<RequestInit, 'redirect'>): Promise<Response> {
  if (isPublicHttpsUrl(url)) {
    return fetchFollowingPublicRedirects(fetch, url, init);
  }
  return fetch(url, { ...init, redirect: 'manual' });
}

/** {@link fetchGatewayBody} の取得条件（要求する表現と、受理する Content-Type・本文上限）。 */
export interface GatewayBodySpec {
  /** `Accept` ヘッダ値。 */
  readonly accept: string;
  /** 受理する Content-Type（パラメータ部は除いて判定）。 */
  readonly contentTypes: readonly string[];
  /** 本文の上限バイト数（省略時は `MAX_DOCUMENT_BYTES`）。 */
  readonly maxBytes?: number;
}

/**
 * IPFS Gateway から本文をバイト列のまま取得する（DID Document と IPNS レコードで共通）。
 *
 * 本文は `MAX_DOCUMENT_BYTES`（1 MiB）以下の上限の内側で読む（`http/body-limit.ts`）。CID / IPNS 名は解決
 * 対象 DID 由来で攻撃者が選べるため、上限なしに読むと DID 一つで無制限の応答をメモリへ流し込める。
 * 尽きたスコープでは取得を始めない。本文量の計上は呼び出し側が（復号・検証の前に）行う。
 *
 * @throws 取得失敗（タイムアウト / 平文への降格 / 上限超過を含む、code `2003`）・
 *   Content-Type 不正（code `2010`）・スコープの予算超過（code `2001`）。
 */
export async function fetchGatewayBody(
  config: IpidGatewayConfig,
  path: string,
  spec: GatewayBodySpec,
  scope: ResolutionWorkBudget | undefined,
): Promise<Uint8Array> {
  assertResolutionWorkRemaining(scope, 0);
  const url = `${trimTrailingSlash(config.gatewayUrl)}/${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), IPID_HTTP_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      response = await getFromGateway(url, {
        method: 'GET',
        signal: controller.signal,
        headers: { Accept: spec.accept },
      });
    } catch {
      // ネットワークエラー / タイムアウト（abort）。詳細は秘密を含み得るため正規化する。
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    // 追従しない構成（ローカル / 平文 Gateway）で返った 3xx は、取得元が選んだ転送として拒否する。
    if (isRedirectResponse(response)) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND, {
        context: { reason: 'insecure_redirect' },
      });
    }
    if (downgradedToPlaintext(url, response)) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND, {
        context: { reason: 'insecure_redirect' },
      });
    }
    if (!response.ok) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    // Content-Type 不一致は取得成功後の分類のため「ドキュメント不正」（2010）とする。
    // 判定は共有ヘルパー（`http/body-limit.ts`）に寄せる。ヘッダ欠落は既定どおり拒否する。
    if (!isAllowedContentType(response.headers.get('content-type'), spec.contentTypes)) {
      throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
    }
    const maxBytes = ownProperty<number>(spec, 'maxBytes');
    const limits = maxBytes === undefined ? undefined : { maxBytes };
    // 自己申告の `content-length` で早期に落とし、実バイト数でも打ち切る。
    if (declaresOversizedBody(response, limits)) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND, { context: { reason: 'oversized_body' } });
    }
    let bytes: Uint8Array | undefined;
    try {
      bytes = await readBytesWithinLimit(response, limits);
    } catch {
      // 本文読み出し中のネットワークエラー / abort。本文・URL は載せない。
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    if (bytes === undefined) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND, { context: { reason: 'oversized_body' } });
    }
    return bytes;
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}

/**
 * IPNS 名を、署名検証済みレコードが指す CID に解決する。
 *
 * `GET <gateway>/ipns/<name>` の本文（DID Document と称するもの）は採用しない。Gateway から署名付き
 * レコードそのもの（`application/vnd.ipfs.ipns-record`）を取得し、IPNS 名の公開鍵で検証する
 * （`ipns-record.ts`）。取得した本文量は検証の前にスコープへ計上する。
 *
 * @param name IPNS 名（did:ipid の method-specific id）。
 * @returns 署名済みレコードの `Value` が指す CID。
 * @throws 取得失敗（code `2003`）・Content-Type 不正 / レコード検証失敗（code `2010`）・予算超過（code `2001`）。
 */
export async function resolveIpnsRecordCid(
  config: IpidGatewayConfig,
  name: string,
  scope?: ResolutionWorkBudget,
): Promise<string> {
  // 検証できない名前（Ed25519 が埋め込まれていない形式）は、取得を始める前に拒否する。
  if (ed25519KeyFromIpnsName(name) === undefined) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
      context: { reason: 'ipns_key_unsupported' },
    });
  }
  const record = await fetchGatewayBody(
    config,
    `ipns/${name}`,
    {
      accept: IPNS_RECORD_CONTENT_TYPE,
      contentTypes: [IPNS_RECORD_CONTENT_TYPE],
      maxBytes: MAX_IPNS_RECORD_BYTES,
    },
    scope,
  );
  consumeResolutionBody(scope, record.length);
  return verifyIpnsRecord(name, record, scope);
}

/**
 * IPFS Gateway 経由で DID Document を取得する。
 *
 * @param config Gateway / API 設定。
 * @param path Gateway パス（`ipfs/<cid>`）。
 * @param expectedDid 解決に使った DID 文字列（取得本文の id 補完・整合性検証に使う）。
 * @param contentCid 取得本文を照合する CID。`did:ipid:<CID>` はその CID、`did:ipid:<ipns-name>` は検証済み
 *   IPNS レコードが指す CID。取得本文のハッシュを CID と照合し、不一致・照合不能は拒否する
 *   （Gateway は信頼境界の外。`cid.ts`）。
 * @param scope 解決スコープ全体の予算。尽きたスコープでは取得を始めず、本文を読み終えた直後（CID 照合・
 *   パースの前）に本文長を計上する（did:web と同形）。省略時は計上しない。
 * @returns DID Document。
 * @throws 取得失敗（タイムアウト / 平文への降格 / 上限超過を含む、code `2003`）・
 *   Content-Type / JSON / スキーマ不正 / CID 不一致（code `2010`）・
 *   スコープの本文量予算超過（code `2001`、`context.reason: 'resolution_work_limit'`）。
 */
export async function fetchFromGateway(
  config: IpidGatewayConfig,
  path: string,
  expectedDid: string,
  contentCid: string,
  scope?: ResolutionWorkBudget,
): Promise<DIDDocument> {
  const bytes = await fetchGatewayBody(
    config,
    path,
    { accept: ALLOWED_CONTENT_TYPES.join(', '), contentTypes: ALLOWED_CONTENT_TYPES },
    scope,
  );
  const text = new TextDecoder().decode(bytes);
  // 取得した本文は CID 照合・パースより前にスコープへ計上する（相異なる DID を並べた増幅の上限）。
  consumeResolutionBody(scope, text.length);
  // 本文を UTF-8 に戻したバイト列でハッシュする。パースに渡す `text` 自体がその CID と一致した
  // 内容であることを保証する（BOM / 不正バイト列を含む応答は一致せず拒否される）。
  const verdict = verifyRawCidContent(contentCid, new TextEncoder().encode(text));
  if (verdict !== 'match') {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
      context: { reason: verdict === 'mismatch' ? 'cid_mismatch' : 'cid_unverifiable' },
    });
  }
  return parseDidDocument(text, expectedDid);
}
