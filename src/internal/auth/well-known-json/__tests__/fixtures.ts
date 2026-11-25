/**
 * well-known Metadata 取得テストの共有フィクスチャ。
 *
 * `fetchWellKnownJson` / `fetchJsonDocument` を叩くテストは 2 ファイルに分かれている
 * （入口検査そのものは `internal/auth/__tests__/well-known-json.test.ts`、本文取得規律は
 * `./fetch-json-document.test.ts`）。同じ関数を同じ入口から叩くので、識別子・失敗ファクトリ・
 * fetch スタブまで各ファイルへ写すと、片方だけが更新されて「どちらが現行か」を決められなくなる。
 * 組み立て部品はここに 1 つだけ置く。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { fetchWellKnownJson } from '../index.js';

/** テストで使う発行者識別子。 */
export const ISSUER = 'https://issuer.example.eu';

/** Issuer Metadata の well-known パス。 */
export const WELL_KNOWN_PATH = '/.well-known/openid-credential-issuer';

/** `ISSUER` から組み立てられる取得 URL。 */
export const METADATA_URL = `${ISSUER}${WELL_KNOWN_PATH}`;

/** 呼び出し側が渡す失敗ファクトリ（コードの選択は呼び出し側の責務）。 */
export function failure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED, { context: { reason } });
}

/** 要求 URL を記録しつつ固定の `Response` を返す `fetchImpl`。 */
export function stubFetch(response: () => Response): { fetchImpl: FetchLike; urls: string[] } {
  const urls: string[] = [];
  return {
    urls,
    fetchImpl: (url) => {
      urls.push(url);
      return Promise.resolve(response());
    },
  };
}

/** JSON 本文の 200 応答。 */
export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** 取得する。既定の well-known パスと失敗ファクトリを埋めるだけの薄いラッパ。 */
export function fetchJson(issuer: string, fetchImpl: FetchLike | undefined): Promise<object> {
  return fetchWellKnownJson(issuer, WELL_KNOWN_PATH, fetchImpl, failure);
}
