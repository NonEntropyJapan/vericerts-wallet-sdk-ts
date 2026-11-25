/**
 * Entity Statement（Entity Configuration / Subordinate Statement）の compact JWT 取得。
 *
 * `entity-configuration.ts` と `subordinate.ts` が共有する唯一の取得経路。取得ハードニング
 * （公開ホスト検査・リダイレクトのホップごと再検査、タイムアウト、本文上限、Content-Type 検査）
 * を 1 か所に集約し、片方だけ修正が漏れる事態を避ける。
 *
 * 本関数が投げるのは常に `FEDERATION_FETCH_FAILED`（5011）であり、内容の検証失敗
 * （`TRUST_CHAIN_INVALID`）は含まない。この境界がそのまま negative cache の対象境界になる
 * （`statement-cache.ts`: 取得の内側で起きた失敗だけを 30 秒記憶する）。
 * 例外メッセージや context に entity_id・URL・JWT・鍵を含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  declaresOversizedBody,
  discardBody,
  OVERSIZED_BODY_REASON,
  readBodyWithinLimit,
} from '../../../http/body-limit.js';
import { isPublicHttpsUrl } from '../../../http/public-https-url.js';
import { fetchFollowingPublicRedirects } from '../../../http/public-redirect-fetch.js';
import { FEDERATION_CONTENT_TYPES, isAllowedEntityStatementContentType } from './content-type.js';

/** 取得のタイムアウト（ミリ秒）。did:web 解決（method-web.ts）と揃える。 */
const FETCH_TIMEOUT_MS = 10_000;

/**
 * 本文サイズ上限（1 MiB）超過を表す取得失敗。
 *
 * コードは他の取得失敗と同じ `FEDERATION_FETCH_FAILED`（5011）のまま保つ（negative cache の
 * 対象境界を動かさない）。代わりに `context.reason` を立て、`fail-open/fetch-failure.ts` が
 * これを**コンテンツ失敗**として FO-6 の入力から除外する。区別が無いと、攻撃者が制御する
 * エンティティは「一度正当に応答してキャッシュを作らせ、以後 1 MiB 超を返す」だけで FO-6 を
 * 作り出し、陳腐化した Statement を復活させられる。Subordinate Statement は常に
 * fail-closed だが、1 MiB 超とゼロバイト応答をログ上区別するため同じ理由名を使う。
 */
function oversizedBody(): VericertsError {
  return new VericertsError(ErrorCodes.FEDERATION_FETCH_FAILED, {
    context: { reason: OVERSIZED_BODY_REASON },
  });
}

/**
 * 取得 URL から Entity Statement の compact JWT を取得する（検証は行わない）。
 *
 * 本文は `MAX_DOCUMENT_BYTES`（1 MiB）の内側で読み、`clearTimeout` は本文読了後に行う
 * （`http/body-limit.ts`）。取得先は外部由来の URL なので、上限も abort 窓も本文読み出しまで及ばせる。
 *
 * @param url 取得 URL（呼び出し側で公開 HTTPS を確認済みであること）。
 * @param fetchFn 注入された HTTP 取得関数。省略時はランタイムのグローバル `fetch`。どちらでも
 *   `fetchFollowingPublicRedirects` 経由で呼ぶため、リダイレクトはホップごとに公開 HTTPS 宛へ縛られる。
 * @returns compact JWS 文字列。
 * @throws 取得失敗の場合（VericertsError、FEDERATION_FETCH_FAILED）。
 */
export async function fetchStatementJwt(url: string, fetchFn?: typeof fetch): Promise<string> {
  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      // リダイレクトはホップごとに公開 HTTPS 宛へ縛って追従する。
      response = await fetchFollowingPublicRedirects(fetchFn ?? fetch, url, {
        method: 'GET',
        signal: controller.signal,
        headers: { Accept: FEDERATION_CONTENT_TYPES.join(', ') },
      });
    } catch {
      // ネットワークエラー / タイムアウト（abort）。詳細は秘密を含み得るため正規化する。
      throw new VericertsError(ErrorCodes.FEDERATION_FETCH_FAILED);
    }

    // リダイレクト先が公開 HTTPS にとどまっていることを最終 URL で検証する
    // （判定は共有ヘルパー `public-https-url.ts` に寄せる。`startsWith('https://')` はホスト無しを通す）。
    if (response.url.length > 0 && !isPublicHttpsUrl(response.url)) {
      throw new VericertsError(ErrorCodes.FEDERATION_FETCH_FAILED);
    }
    if (!response.ok) {
      throw new VericertsError(ErrorCodes.FEDERATION_FETCH_FAILED);
    }
    // `Accept` で宣言した型と同じ集合で応答も検査する。
    if (!isAllowedEntityStatementContentType(response.headers.get('content-type'))) {
      throw new VericertsError(ErrorCodes.FEDERATION_FETCH_FAILED);
    }
    // 自己申告の `content-length` で早期に落とし、実バイト数でも打ち切る。
    if (declaresOversizedBody(response)) {
      throw oversizedBody();
    }

    let text: string | undefined;
    try {
      text = await readBodyWithinLimit(response);
    } catch {
      // 本文読み出し中のネットワークエラー / abort。本文・URL は載せない。
      throw new VericertsError(ErrorCodes.FEDERATION_FETCH_FAILED);
    }
    // 上限超過（`undefined`）とゼロバイト応答を潰さない。前者は理由を立てて fail-open から外す。
    if (text === undefined) {
      throw oversizedBody();
    }
    const jwt = text.trim();
    if (jwt.length === 0) {
      throw new VericertsError(ErrorCodes.FEDERATION_FETCH_FAILED);
    }
    return jwt;
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}
