/**
 * Credential Endpoint レスポンス JSON の検証・正規化。
 *
 * `oid4vci.ts` から切り出した応答パース層。切り出しの理由は `oid4vci/par/response.ts` と同じで
 * 2 つある。
 * (1) 送信側（`requestCredential`）と応答の型検証で責務が異なり、後者だけを単体で読めるように
 *     するため。
 * (2) 分離前の `oid4vci.ts` が 324 行と 1 ファイル 300 行の上限を超えており（分離後は 295 行）、
 *     同ファイルへ積み増すと悪化するため。
 *
 * 応答本文は `parseJsonWithoutPrototype` でパースするため `Object.prototype` を継承しない。
 * パース境界を通らない値も同じように扱えるよう、応答メンバは**自身のプロパティに限って読む**。
 * 鎖読みだと Issuer が `{}` を返しただけでも
 * `Object.prototype.credential` の汚染値が「Issuer が発行した VC」として採用され、
 * `requestCredential` が `{ status: 'issued', credential: <汚染値> }` を返す。呼び出し側は
 * これを受領 VC として保管・提示しうる。同型で `transaction_id` の汚染は即時発行の応答を
 * 遅延発行に化けさせ、`c_nonce` の汚染は後続の JWT Proof を攻撃者の選んだ nonce にバインドする。
 * `typeof … === 'string'` のガードは汚染値が文字列であれば素通りするため防げない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { readBodyWithinLimit } from '../../http/body-limit.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { readCredentialsArray } from './credential-wire/response-credentials.js';

/**
 * Credential Endpoint のレスポンス。即時発行は旧 Draft の `credential` と
 * OID4VCI 1.0 §8.3 の `credentials: [{ credential }]`（ちょうど 1 要素）を `credential` へ正規化して返す。
 */
export interface CredentialResponse {
  /** 即時発行された VC（JWT / SD-JWT 文字列）。 */
  readonly credential?: string;
  /** 遅延発行時の取引 ID（Deferred Endpoint ポーリング用）。 */
  readonly transaction_id?: string;
  /** 次回 Proof 用に更新された c_nonce。 */
  readonly c_nonce?: string;
}

/**
 * 文字列のみを返す。それ以外（欠落・非文字列）は `undefined`。
 *
 * own 限定で読んでも型は保証されないため、従来どおり `typeof … === 'string'` で絞る。
 * 値は呼び出し側で 1 回だけ読んだものを受け取る（同じキーを 2 度読むと、アクセサ汚染では
 * 判定に使った値と採用する値が食い違いうる）。
 */
function toStringOrUndefined(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/**
 * レスポンス本文を `CredentialResponse` として安全にパースする。
 *
 * `credential` / `transaction_id` / `c_nonce` はいずれもパース結果の**純データ**なので
 * own 限定（`ownProperty`）で読む（多層防御。上のモジュール冒頭を参照）。`credential` も `transaction_id` も取得できない応答は
 * 呼び出し側で `CREDENTIAL_REQUEST_FAILED`（8020）へ倒れる（fail-closed）。
 *
 * 戻り値のオブジェクトリテラルは 3 キーすべてを（値が `undefined` でも）**自身のプロパティ
 * として**定義するため、呼び出し側の `parsed.credential` 等は汚染された `Object.prototype` へ
 * 到達しない。
 *
 * @param text レスポンス本文（JSON 文字列）。
 * @returns own 限定で読み出した `CredentialResponse`。
 * @throws JSON でない / object でない場合（VericertsError、code `8020`）。
 */
export function parseCredentialResponse(text: string): CredentialResponse {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(text);
  } catch {
    // 本文（VC を含み得る）は message に載せない。
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  }
  const legacyCredential = toStringOrUndefined(ownProperty<unknown>(parsed, 'credential'));
  const transactionId = toStringOrUndefined(ownProperty<unknown>(parsed, 'transaction_id'));
  const credentials = ownProperty<unknown>(parsed, 'credentials');
  return {
    credential:
      credentials === undefined
        ? legacyCredential
        : readCredentialsArray(credentials, legacyCredential, transactionId),
    transaction_id: transactionId,
    c_nonce: toStringOrUndefined(ownProperty<unknown>(parsed, 'c_nonce')),
  };
}

/**
 * Credential Endpoint の応答**本文**を上限内で読み出し、{@link parseCredentialResponse} に渡す。
 *
 * 読み出しは呼び出し側のタイムアウト（`AbortController`）の**内側**で行われる前提である。
 * `clearTimeout` を本文読了より前に置くと、ヘッダだけ即座に返して本文をだらだら送る Issuer に
 * 対して無限に待つ（`internal/http/fetch-json.ts` が明記する不変条件）。
 *
 * 本文は `MAX_DOCUMENT_BYTES`（1 MiB）で打ち切る。取得元は Issuer 由来の URL であり、巨大な
 * 応答をそのままメモリへ載せると DoS になるためである。
 *
 * 読み出し中のソケットリセットや abort は生の `TypeError` として表面化するため、ここで
 * `VericertsError` へ正規化する（`requestCredential` の `@throws` 契約を破らないため）。
 *
 * @param response 2xx を確認済みのレスポンス。
 * @returns 正規化された応答。
 * @throws 本文読み出し失敗（通信失敗、code `3004`）・上限超過（応答不正、code `8020`）の場合
 *         （VericertsError）。
 */
export async function readCredentialResponse(response: Response): Promise<CredentialResponse> {
  let text: string | undefined;
  try {
    text = await readBodyWithinLimit(response);
  } catch {
    // 本文読み出し中のネットワークエラー / abort。本文・URL は載せない。
    throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
  }
  if (text === undefined) {
    // 上限超過。本文を取り出せないため応答不正として扱う。
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  }
  return parseCredentialResponse(text);
}
