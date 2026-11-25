/**
 * OID4VCI Authorization Code Flow の Attestation-Based Client Authentication 共通処理。
 *
 * PAR / Token Request の Wallet Attestation に適用する規格:
 * RFC 7521 §4.2（`client_assertion_type` は `client_assertion` 使用時に REQUIRED）、
 * RFC 9126 §2（PAR エンドポイントのクライアント認証は Token Endpoint と同一に扱う）。
 *
 * PAR と Token Request の双方で `client_assertion=<WUA>~<WUA-PoP>` を送る。
 * RFC 9126 §2 のとおり両経路のクライアント認証は同一に扱う。判定が経路ごとに
 * ずれると、片方だけ `client_assertion_type` 欠落を素通りさせて AS が解釈できない認証情報を送出したり、
 * 片方だけ `client_assertion` 単独送信を許してしまう。そこで不変条件を本モジュール 1 か所に集約し、
 * `oid4vci/par/par.ts` と `oid4vci-token.ts` から共有する。
 *
 * 不変条件:
 * - `client_assertion` を指定しながら `client_assertion_type` が未指定・空文字・空白のみなら
 *   送信前に `TOKEN_REQUEST_FAILED`（8010）で拒否する（RFC 7521 §4.2。SDK は既定値を補完しない。
 *   渡された assertion が Wallet Attestation なのか RFC 7523 の `jwt-bearer` assertion なのかを
 *   SDK からは判別できず、既定値を補うと別形式の assertion を誤ってラベル付けして送信しうるため）。
 * - body には**対でそろっているときだけ**両者を載せる（`client_assertion_type` 単独は AS 側で
 *   解釈できないため、どちらも送らない）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に `client_assertion`（`<WUA>~<WUA-PoP>`）を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';

/**
 * クライアント認証パラメータ（`client_assertion` / `client_assertion_type`）。
 *
 * **呼び出し側は、リクエストオブジェクトから own 限定（`ownProperty`）で 1 回だけ読んだ値を
 * 詰めて渡すこと。** 継承値を新しいオブジェクトリテラルへ詰め直すと `Object.prototype` の汚染値が
 * own プロパティに化け、本モジュールの判定では汚染値と正当な指定を区別できない
 * （`own-property.ts`「呼び出し側で無効化しないこと」）。未指定のキーは生やさず条件付き展開で落とすか、
 * `ownProperty` の戻り（`undefined` を含む）をそのまま渡す。
 */
export interface ClientAuthParams {
  /**
   * `client_assertion`。Wallet Attestation を使う場合の値は `<WUA>~<WUA-PoP>`
   * で、`buildClientAttestation`
   * （`internal/eudi/wua/proof.ts`）が組み立てる。SDK にとっては不透明な文字列であり、
   * 内容の検証・分解は行わない。
   */
  readonly clientAssertion?: string;
  /**
   * `client_assertion_type`（RFC 7521 §4.2 が `client_assertion` 使用時に REQUIRED と定める）。
   * Wallet Attestation を使う場合の値は公開定数 `WUA_CLIENT_ASSERTION_TYPE`
   * （`internal/eudi/wua/types.ts`）と同じ。SDK は既定値を補完しない。
   */
  readonly clientAssertionType?: string;
}

/**
 * `client_assertion` 指定時に `client_assertion_type` が非空であることを検査する（RFC 7521 §4.2）。
 *
 * 送信前に呼び、違反していれば `TOKEN_REQUEST_FAILED`（8010）で拒否する。
 *
 * @param auth own 限定で 1 回だけ読んだクライアント認証パラメータ。
 * @throws `client_assertion` 指定時に `client_assertion_type` が未指定・空文字・空白のみなら code `8010`。
 */
export function assertClientAssertionPair(auth: ClientAuthParams): void {
  if (auth.clientAssertion !== undefined && !isNonBlankString(auth.clientAssertionType)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }
}

/**
 * `client_assertion` / `client_assertion_type` が対でそろっているときだけ body へ載せる。
 *
 * `client_assertion_type` だけの指定は {@link assertClientAssertionPair} を通り抜けるが、AS 側で
 * 解釈できないためどちらも送らない。
 *
 * @param params 送信する form パラメータ（呼び出し側で生成した `URLSearchParams`）。
 * @param auth own 限定で 1 回だけ読んだクライアント認証パラメータ。
 */
export function appendClientAssertionParams(params: URLSearchParams, auth: ClientAuthParams): void {
  const { clientAssertion, clientAssertionType } = auth;
  if (clientAssertion !== undefined && clientAssertionType !== undefined) {
    params.set('client_assertion', clientAssertion);
    params.set('client_assertion_type', clientAssertionType);
  }
}
