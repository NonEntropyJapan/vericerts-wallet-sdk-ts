/**
 * 内包 VC が提示者（`vp.holder`）のものかの突合と、そのガード群
 * （`credential-entry-verify.ts` から切り出し）。
 *
 * `requireHolderBinding` が要求されたときの判定だけを担う。JWT-VC は `sub` と `vp.holder` の一致、SD-JWT VC は KB-JWT を照合できる実効バインド値が
 * 揃っているかの事前検査（`hasEffectiveBinding`）を提供する。いずれも不成立は例外では
 * なく `3012` を返し、呼び出し側（`jwt-vc-entry.ts` / `sd-jwt-vc-entry.ts`）が `valid: false` に
 * 落とす（他の VC の結果を失わないため）。
 *
 * セキュリティ上の注意:
 * - 突合に使う入力（`holderDID`）は**使用地点で** own 限定に読む。緩和方向の
 *   汚染がそのまま fail-open になるため（関数のコメント参照）。
 */

import { type ErrorCode, ErrorCodes } from '../../../errors.js';
import { isNonEmptyString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { EmbeddedCredentialVerifyInput } from '../credential-results.js';

/**
 * 内包 JWT-VC が提示者（`vp.holder`）のものかを判定する。
 *
 * `requireHolderBinding: false`（既定）なら何も見ない（後方互換）。`true` のときは
 * **`sub` を持たない VC（bearer credential）も拒否する**。
 * 呼び出しは**発行者署名の検証に成功した後**に限る。未検証 payload の `sub` を突き合わせても
 * 攻撃者が自由に書ける値との比較にしかならないため。
 *
 * 突合が成立するのは**直接提示**（`sub === vp.holder`、holder 本人が自分の VC を提示している）だけ
 * である。独自の委任材料（`delegations`）による突合は削除した。
 *
 * @returns 不成立なら `3012`、突合不要 / 直接提示なら `undefined`。
 */
export function holderBindingErrorOf(
  payload: Record<string, unknown>,
  input: EmbeddedCredentialVerifyInput,
): ErrorCode | undefined {
  if (!ownProperty<boolean>(input, 'requireHolderBinding')) {
    return undefined;
  }
  // payload は署名済みだが `sub` を**持たない** VC では鎖読みが `Object.prototype.sub` の汚染値を
  // 拾う。汚染値が `holderDID` と一致すれば bearer VC が突合を素通りするため own 限定で読む。
  const sub = ownProperty<unknown>(payload, 'sub');
  if (typeof sub !== 'string') {
    return ErrorCodes.HOLDER_BIND_MISMATCH;
  }
  // `holderDID` も**使用地点で** own 限定に読む。鎖読みすると当該キーを持たない入力で
  // `Object.prototype.holderDID` の汚染値が提示者 DID として採用され、被害者の VC の `sub` を
  // 汚染値に据えるだけで第三者の VC が突合を素通りする（fail-open）。
  // 汚染が無ければ `undefined` になり、`sub` は文字列なので一致せず不成立になる（fail-closed）。
  const holderDID = ownProperty<string>(input, 'holderDID');
  return sub === holderDID ? undefined : ErrorCodes.HOLDER_BIND_MISMATCH;
}

/**
 * SD-JWT VC の KB-JWT を「この提示宛か」まで照合できる入力かを判定する。
 *
 * `requireHolderBinding: false`（既定）なら中継値の有無は問わない（従来どおり、渡された値が
 * あるときだけ照合する配線是正の範囲）。`true` のときは実効 `audience` / `nonce` の**両方**を
 * 要求する（空文字は「未指定」と同じ扱い。`internal/prototype-safety/non-empty-string.ts` の `isNonEmptyString`。
 * 委譲先 `verifySdJwt` が `requireKeyBinding: true` に**非空**の `audience` / `nonce` を要求する
 * ため、本層だけ空文字を通すと「委譲先が差し替わっても本層で fail-closed が保たれる」という
 * 多層防御の前提が崩れる）。どちらかが欠けていると
 * 委譲先が当該項目の照合をスキップし、鍵保持だけで突合成立と報告してしまうため。
 *
 * **多層防御として残している**: 恒久対策として委譲先の `verifySdJwt` 自身が
 * 「`requireKeyBinding: true` なら `audience` / `nonce` も必須」になったため、本ガードを外しても
 * 同じ `3012` にはなる。それでも残すのは、(1) 本経路の失敗面が例外ではなく
 * `credentialResults[].errors` であり、委譲先の失敗コードに依存せず本層で判定を確定させたいこと、
 * (2) 実効バインド値の算出（`delegatedOptions`）は本層の責務で、その欠落を本層で検知するのが
 * 責務境界として自然なこと、(3) 将来 SD-JWT VC の委譲先が差し替わっても fail-closed が保たれる
 * こと、による。回帰テストは本層の入力（`requireHolderBinding` + 実効値の欠落）に
 * 対する `3012` を固定するもので、委譲先の必須化とは独立に意味を持ち続ける。
 *
 * @returns 突合不要、または両方の実効バインド値が揃っていれば `true`。
 */
export function hasEffectiveBinding(input: EmbeddedCredentialVerifyInput): boolean {
  return (
    !ownProperty<boolean>(input, 'requireHolderBinding') ||
    (isNonEmptyString(ownProperty<unknown>(input, 'audience')) &&
      isNonEmptyString(ownProperty<unknown>(input, 'nonce')))
  );
}
