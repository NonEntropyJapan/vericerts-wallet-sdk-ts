/**
 * JWT-VP payload の `vp` 取り出しと提示バインド（`iss` / `aud` / `nonce`）の検証。
 *
 * `presentation.ts` から切り出したもの（1 ファイル 300 行の上限を守るため）。VP レベルの Holder
 * Binding（`iss === vp.holder`）と OID4VP の Verifier バインドを 1 箇所に集めてある。**内包 VC**
 * が提示者のものかを見る `requireHolderBinding` の突合は本モジュールではなく
 * `credential-entry-verify.ts` とその配下 `credential-entry/` が担う（対象が VP 署名ではなく各 VC のため）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に VC 本文・開示値・JWT を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { timingSafeEqualString } from '../../timing-safe.js';
import { type AssertedVerifiablePresentation, assertVerifiablePresentationMembers } from './vp.js';

/**
 * VP payload の実測値（`aud` / `nonce`。`unknown`）が期待値と一致するかを定数時間で判定する。
 *
 * `aud` / `nonce` は `timingSafeEqualString` で照合する。文字列以外は不一致とする。
 */
function bindingMatches(actual: unknown, expected: string): boolean {
  return typeof actual === 'string' && timingSafeEqualString(actual, expected);
}

/**
 * JWT-VP payload の `vp` を取り出して構造検証し、`iss === vp.holder`・`aud` / `nonce` 整合を検証する。
 *
 * `vp` 自体の構造不正は構造不正（3002）。一方、`iss`・`aud`・`nonce` の不整合は OID4VP の提示バインド失敗
 * （Holder Binding 不一致）であり、提示者バインド系コード（3012）として拒否する。
 *
 * - `iss` と `vp.holder` の不一致は Holder Binding 不一致（3012）。
 * - 既定（束縛）モード（`allowUnbound !== true`）: `expectedAudience` / `expectedNonce` を必須とし、
 *   未指定または payload の `aud` / `nonce` と不一致なら 3012。OID4VP のリプレイ・対象者バインド未検証を防ぐ。
 * - `allowUnbound: true`（明示オプトアウト）: `expectedAudience` / `expectedNonce` を指定した場合のみ照合する。
 *
 * @param payload デコード済み JWT-VP ペイロード。
 * @param opts `verifyPresentation` に渡されたオプション（生のまま。読み方は本関数が決める）。
 * @returns 構造検証済みの VP（`payload.vp`）と、その検証に使った own メンバ
 *          （`holder` / `verifiableCredential`）。読み直さずにそのまま下流へ渡すこと。
 * @throws `vp` 構造不正の場合（code `3002`）、提示バインド不整合・バインド未指定の場合（code `3012`）（VericertsError）。
 */
export function assertVpClaims(
  payload: Record<string, unknown>,
  opts: object,
): AssertedVerifiablePresentation {
  // `payload.vp` を直接読むと、**`vp` クレームを持たない署名済み JWT でも
  // `Object.prototype.vp` の汚染値が VP として構造検証を通り、返り値の `verifiableCredential`
  // が丸ごと攻撃者制御になる**。JWT に実在するクレームだけを VP として受理する。
  // 検査済みメンバを**そのまま**受け取り、**そのまま**返す。`vp.holder` /
  // `vp.verifiableCredential` で読み直すと、own アクセサ付きの VP を渡された場合に 2 度目が
  // 別の値を返し得る（突合に使った DID と下流が使う DID が食い違う TOCTOU）。single-read に揃える。
  const asserted = assertVerifiablePresentationMembers(ownProperty<unknown>(payload, 'vp'));
  // `payload` は `credential/vc/jws.ts` の `decodeCompactJws` → `identity/jwt/jwt-codec.ts` の
  // `parseJson` → `parse-json.ts` の `parseJsonWithoutPrototype` を通って届くため **`null`
  // プロトタイプ**である。own 限定で読むのはその手法と**重畳する多層防御**で、`payload.iss` / `aud` /
  // `nonce` を鎖で読む形へ戻すと、パース境界を通らない値がここへ流入した時点で**そのクレームを
  // 持たない VP でも継承値が「payload に入っていた値」として照合に使われる**（汚染値が期待値と
  // 一致すればバインド検証を素通りする）。存在しないクレームは undefined として扱い、不一致で
  // 拒否させる。
  const iss = ownProperty<unknown>(payload, 'iss');
  const aud = ownProperty<unknown>(payload, 'aud');
  const nonce = ownProperty<unknown>(payload, 'nonce');
  if (iss !== asserted.holder) {
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }

  // 任意オプションも自身のプロパティに限って読む。`opts.allowUnbound !== true` だと
  // `Object.prototype.allowUnbound = true` の汚染下で **既定（束縛必須）で呼んだ検証が
  // 無言で unbound モードへ落ち、aud / nonce の照合がまるごと省略される**（リプレイ・
  // 対象者取り違えを検出できなくなる）。`expected*` も同様に、呼び出し側が指定していない
  // 期待値が汚染値で補われると「バインド未指定は拒否」の既定が骨抜きになる。
  const allowUnbound = ownProperty<boolean>(opts, 'allowUnbound');
  const expectedAudience = ownProperty<string>(opts, 'expectedAudience');
  const expectedNonce = ownProperty<string>(opts, 'expectedNonce');

  const bound = allowUnbound !== true;
  if (bound) {
    // 既定: Verifier バインド必須。expected 値の未指定（バインド未検証）も payload との不一致も拒否する。
    if (expectedAudience === undefined || !bindingMatches(aud, expectedAudience)) {
      throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
    }
    if (expectedNonce === undefined || !bindingMatches(nonce, expectedNonce)) {
      throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
    }
  } else {
    // unsafe（オプトアウト）: 指定された場合のみ照合する。
    if (expectedAudience !== undefined && !bindingMatches(aud, expectedAudience)) {
      throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
    }
    if (expectedNonce !== undefined && !bindingMatches(nonce, expectedNonce)) {
      throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
    }
  }
  return asserted;
}
