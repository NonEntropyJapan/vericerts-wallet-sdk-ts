/**
 * Credential Request の `Authorization` / `DPoP` ヘッダの決定。
 *
 * `dpop` / `tokenType` から `Authorization: DPoP <access_token>` と `DPoP: <proof>` を
 * 送信する条件を決める（RFC 9449 §5 / §7.1）。
 *
 * `oid4vci.ts` から分離したのは、ヘッダの決定が (1) own 限定読み、(2) 空 proof の拒否、
 * (3) DPoP 束縛トークンの fail-closed という 3 つの判断を含み、`requestCredential` 本体の
 * 「HTTP を 1 往復する」責務と混ざると読み手が送出形式の根拠を追えなくなるためである
 * （PAR 経路が `oid4vci-client-auth.ts` にクライアント認証の判断を分離しているのと同じ構成）。
 *
 * セキュリティ上の注意:
 * - 例外の `context` は固定識別子（`reason`）のみ。access_token / proof / URL は載せない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';

/**
 * DPoP 束縛アクセストークンを表す `token_type`（RFC 9449 §5）。
 *
 * RFC 6749 §5.1 の `token_type` は**大文字小文字を区別しない**ため、比較は小文字化して行う。
 */
const DPOP_TOKEN_TYPE = 'dpop';

/**
 * `Authorization`（+ 必要なら `DPoP`）ヘッダを決める。
 *
 * `dpop` / `tokenType` は own 限定で 1 回だけ読む。どちらも**純データ**
 * （proof は RFC 9449 §4.2 の直列化済み JWT 文字列）なので、PAR / Token 経路の `dpop` と同じ
 * `ownProperty` を使う。**関数 DI seam ではないため `nonObjectPrototypeProperty` の対象ではない**
 * （同じオプションオブジェクトの `fetchImpl` だけが関数値として後者で読まれる）。鎖読みにすると:
 *
 * - `dpop`: proof を**指定していない**正当な呼び出しでも汚染値が `DPoP` ヘッダに載り、
 *   `Authorization` が `Bearer` から `DPoP` へ切り替わって攻撃者の proof で送出される。
 * - `tokenType`: 汚染値 `"DPoP"` を拾い、proof 未指定の正当な呼び出しが下の fail-closed で
 *   拒否されて DoS になる。
 *
 * @param options `requestCredential` に渡されたオプション（`dpop` / `tokenType` を読む）。
 * @param accessToken Token Response の access_token。
 * @returns `Authorization` と、proof 指定時のみ `DPoP` を含むヘッダ組。
 * @throws `dpop` が空文字・空白のみ（`reason: 'invalid_dpop_proof'`）、または `tokenType` が
 *         `DPoP` なのに proof が無い場合（`reason: 'dpop_proof_required'`）。いずれも code `8020`。
 */
export function resolveCredentialAuthHeaders(
  options: object,
  accessToken: string,
): Record<string, string> {
  const dpop = ownProperty<string>(options, 'dpop');
  const tokenType = ownProperty<string>(options, 'tokenType');

  if (dpop !== undefined && !isNonBlankString(dpop)) {
    // 空の proof は `DPoP` ヘッダとして無意味（Issuer 側で必ず落ちる）。PAR / Token 経路と同じ扱い。
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
      context: { reason: 'invalid_dpop_proof' },
    });
  }
  if (dpop === undefined) {
    if (tokenType?.toLowerCase() === DPOP_TOKEN_TYPE) {
      // DPoP 束縛 access_token を Bearer で送ると RFC 9449 §7.1 準拠の Issuer が拒否する。
      // HTTP を 1 度も発生させずに落として access_token の露出面を作らない（fail-closed）。
      throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
        context: { reason: 'dpop_proof_required' },
      });
    }
    return { Authorization: `Bearer ${accessToken}` };
  }
  // proof があれば DPoP スキーム + `DPoP` ヘッダ。
  return { Authorization: `DPoP ${accessToken}`, DPoP: dpop };
}
