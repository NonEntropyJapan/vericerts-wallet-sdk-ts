/**
 * did:ipid の IPFS HTTP API クライアント（公開用）。
 *
 * 公開（create / update）は IPFS HTTP API を呼び出す:
 * - `POST <api>/api/v0/add`                                  → CIDv1
 * - `POST <api>/api/v0/key/import?arg=<keyname>`             → IPNS キー名（更新可能 DID 用）
 * - `POST <api>/api/v0/name/publish?arg=<cid>&key=<keyname>` → IPNS 名
 *
 * 解決経路（Gateway 取得）と設定・タイムアウト・URL 正規化は `gateway.ts` と共有する。
 *
 * エラーコードの分類:
 * - API 呼び出しの失敗（network / 4xx / 5xx / timeout / 平文宛先の拒否）→ `DID_NOT_FOUND`（2003）。
 * - JSON parse 失敗 / レスポンス形状不正 → `DID_DOC_INVALID`（2010）。
 *
 * セキュリティ上の注意:
 * - **`key/import` は IPNS の Ed25519 秘密鍵そのものを送る。** 宛先 `config.apiUrl` は呼び出し側が
 *   渡した任意の文字列なので、平文 HTTP の遠隔ノードを許すと秘密鍵が素のまま外へ出る。よって
 *   宛先は HTTPS かループバックに限る（{@link isAllowedApiEndpoint}）。既定の
 *   `http://localhost:5001` はループバックなのでそのまま動く。
 * - 呼び出しは {@link import('./gateway.js').IPID_HTTP_TIMEOUT_MS} の AbortController で覆い、
 *   本文読了までを 1 つの予算に収める。タイムアウトが無いと、応答を返さない宛先に対して公開処理が
 *   無期限に留まる。
 * - 例外メッセージや `context` に API URL・本文・鍵バイトを含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { declaresOversizedBody, discardBody, readBodyWithinLimit } from '../../http/body-limit.js';
import { isRedirectedPostResponse } from '../../http/public-https-url.js';
import { isHttpsUrl } from '../../https-url.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { IPID_HTTP_TIMEOUT_MS, type IpidGatewayConfig, trimTrailingSlash } from './gateway.js';

/**
 * 平文 `http:` を許すループバックのホスト名（`localhost` / `127.0.0.1` / `[::1]` の 3 つだけ）。
 * `127.0.0.2` など `127.0.0.0/8` のほかのアドレスは許さない。
 * `new URL()` が `127.1` を `127.0.0.1` に、`[0:0:0:0:0:0:0:1]` を `[::1]` に、`LOCALHOST` を `localhost` に
 * 正規化するので、それらは同じホストとして通る。
 */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * IPFS HTTP API の宛先として許容する URL か判定する。
 *
 * HTTPS なら無条件に許す。平文 `http:` はループバック（`localhost` / `127.0.0.1` / `[::1]` の 3 つだけ）に
 * 限って許す — 既定値 `http://localhost:5001` は同一ホストの IPFS ノードを指し、TLS を要求すると
 * 既定構成が動かなくなるためである。ループバックを出る平文だけを拒むので、秘密鍵や DID Document が
 * TLS 無しでネットワークへ出ることはない。
 *
 * @param value 検査する API URL。
 * @returns 宛先として許容できれば `true`。
 */
function isAllowedApiEndpoint(value: string): boolean {
  if (isHttpsUrl(value)) {
    return true;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:') {
    return false;
  }
  return LOOPBACK_HOSTS.has(url.hostname);
}

/**
 * IPFS HTTP API へ POST し JSON レスポンスを返す共通処理。
 *
 * 宛先が HTTPS でもループバックでもなければ**送信せずに**拒否する（`context.reason` は
 * `insecure_api_url`）。API 呼び出しの失敗（network / 4xx / 5xx / timeout）は取得・公開失敗として
 * `DID_NOT_FOUND`（2003）に正規化する（再試行可）。
 *
 * リダイレクトは追従しない（`redirect: 'manual'`）。3xx 応答・非公開な最終 URL は本文を読まずに
 * `insecure_api_url` で拒否する（307 / 308 で秘密鍵本文が再送されるのを防ぐ）。
 *
 * 戻り値は非 null オブジェクト（配列を除く）であることを保証する。呼び出し側（`ipfsAdd` /
 * `ipfsKeyImport` / `ipfsNamePublish`）はフィールドアクセス前の null チェックなしにキャストする
 * ため、ここで保証しないと構文的に有効な JSON（例: 本文 `null`）が素の `TypeError` として
 * 呼び出し元まで漏れる。
 */
async function postApi(url: string, body?: BodyInit): Promise<unknown> {
  if (!isAllowedApiEndpoint(url)) {
    // 秘密鍵を平文で送出しないため、fetch を 1 度も発生させずに落とす。URL は context に載せない。
    throw new VericertsError(ErrorCodes.DID_NOT_FOUND, {
      context: { reason: 'insecure_api_url' },
    });
  }
  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。
  const timer = setTimeout(() => controller.abort(), IPID_HTTP_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      // 3xx に追従して `key/import` の IPNS 秘密鍵を別ホストへ再送しない。
      response = await fetch(url, {
        method: 'POST',
        body,
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    if (isRedirectedPostResponse(url, response)) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND, {
        context: { reason: 'insecure_api_url' },
      });
    }
    if (!response.ok) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    // 自己申告の `content-length` で早期に落とし、実バイト数でも打ち切る。
    if (declaresOversizedBody(response)) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND, { context: { reason: 'oversized_body' } });
    }
    let text: string | undefined;
    try {
      text = await readBodyWithinLimit(response);
    } catch {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
    }
    if (text === undefined) {
      throw new VericertsError(ErrorCodes.DID_NOT_FOUND, { context: { reason: 'oversized_body' } });
    }
    let parsed: unknown;
    try {
      // `response.json()` は `Object.prototype` を継承する結果を返すため、パース境界で断つ。
      parsed = parseJsonWithoutPrototype(text);
    } catch {
      throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
    }
    return parsed;
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}

/** `POST <api>/api/v0/add` のレスポンス（Kubo 形式）。`Hash` が CID。 */
interface IpfsAddResult {
  readonly Hash: string;
}

/**
 * DID Document JSON を IPFS にアップロードして CIDv1 を得る。
 *
 * `POST <api>/api/v0/add?cid-version=1` に multipart/form-data で JSON を添付する。
 *
 * @param config Gateway / API 設定。
 * @param documentJson アップロードする DID Document の JSON 文字列。
 * @returns CIDv1（`Hash`）。
 * @throws API 呼び出し失敗（平文宛先の拒否を含む、code `2003`）・レスポンス不正（code `2010`）。
 */
export async function ipfsAdd(config: IpidGatewayConfig, documentJson: string): Promise<string> {
  const url = `${trimTrailingSlash(config.apiUrl)}/api/v0/add?cid-version=1`;
  const form = new FormData();
  form.append('file', new Blob([documentJson], { type: 'application/json' }), 'did.json');
  const result = (await postApi(url, form)) as IpfsAddResult;
  if (typeof result.Hash !== 'string' || result.Hash.length === 0) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  return result.Hash;
}

/** `POST <api>/api/v0/key/import` のレスポンス（Kubo 形式）。`Name` がキー名。 */
interface IpfsKeyImportResult {
  readonly Name: string;
}

/**
 * IPNS 用 Ed25519 秘密鍵バイト列の許容長（libp2p key 形式）。
 *
 * libp2p の Ed25519 秘密鍵は raw 64B（seed 32B + 公開鍵 32B）、protobuf でラップした import 形式
 * （`key/import` が受理する形式）は数バイトのヘッダを含むため概ね 36〜68B に収まる。下限 32B・
 * 上限 68B を外れる長さは明らかに不正としてローカルで弾く（API へ送らない）。
 */
const IPNS_KEY_MIN_BYTES = 32;
const IPNS_KEY_MAX_BYTES = 68;

/**
 * IPNS 鍵バイト列の長さ・形式を検証する。
 *
 * @param keyBytes 検証する IPNS 秘密鍵バイト列。
 * @throws 長さが許容範囲外の場合（VericertsError、code `1003`）。秘密素材は例外に出さない。
 */
function validateIpnsKeyBytes(keyBytes: Uint8Array): void {
  if (keyBytes.length < IPNS_KEY_MIN_BYTES || keyBytes.length > IPNS_KEY_MAX_BYTES) {
    // 鍵バイトそのものは秘密のため message / cause に含めない。
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
}

/**
 * IPNS 鍵を IPFS ノードに import する。
 *
 * `POST <api>/api/v0/key/import?arg=<keyName>` に PEM/protobuf 鍵を multipart で添付する。
 * 秘密鍵そのものを送るため、宛先が HTTPS でもループバックでもなければ送信せずに拒否する
 * （{@link isAllowedApiEndpoint}）。
 *
 * @param config Gateway / API 設定。
 * @param keyName 登録するキー名。
 * @param keyBytes import する Ed25519 IPNS 鍵バイト列（libp2p key 形式）。
 * @returns 登録されたキー名。
 * @throws 鍵バイト長不正（code `1003`）・API 呼び出し失敗（平文宛先の拒否を含む、code `2003`）・
 *   レスポンス不正（code `2010`）。
 */
export async function ipfsKeyImport(
  config: IpidGatewayConfig,
  keyName: string,
  keyBytes: Uint8Array,
): Promise<string> {
  validateIpnsKeyBytes(keyBytes);
  const url = `${trimTrailingSlash(config.apiUrl)}/api/v0/key/import?arg=${encodeURIComponent(keyName)}`;
  const form = new FormData();
  // SharedArrayBuffer 由来を排除した ArrayBuffer 上のコピーにして BlobPart 型へ適合させる。
  const keyBlobPart = keyBytes.slice().buffer as ArrayBuffer;
  form.append('key', new Blob([keyBlobPart], { type: 'application/octet-stream' }), keyName);
  const result = (await postApi(url, form)) as IpfsKeyImportResult;
  if (typeof result.Name !== 'string' || result.Name.length === 0) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  return result.Name;
}

/** `POST <api>/api/v0/name/publish` のレスポンス（Kubo 形式）。`Name` が IPNS 名。 */
interface IpfsNamePublishResult {
  readonly Name: string;
}

/**
 * CID を IPNS 名に publish する。
 *
 * `POST <api>/api/v0/name/publish?arg=<cid>&key=<keyName>` → IPNS 名（base36 libp2p-key）。
 *
 * @param config Gateway / API 設定。
 * @param cid publish 対象の CIDv1。
 * @param keyName publish に使う IPNS キー名。
 * @returns IPNS 名（base36 libp2p-key）。
 * @throws API 呼び出し失敗（平文宛先の拒否を含む、code `2003`）・レスポンス不正（code `2010`）。
 */
export async function ipfsNamePublish(
  config: IpidGatewayConfig,
  cid: string,
  keyName: string,
): Promise<string> {
  const url = `${trimTrailingSlash(config.apiUrl)}/api/v0/name/publish?arg=${encodeURIComponent(cid)}&key=${encodeURIComponent(keyName)}`;
  const result = (await postApi(url)) as IpfsNamePublishResult;
  if (typeof result.Name !== 'string' || result.Name.length === 0) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  return result.Name;
}
