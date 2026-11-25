/**
 * `EmbeddedCredentialVerifyInput` の読み取りと、委譲先（`verifyCredential` / `verifySdJwt`）へ
 * 渡す入力の組み立て（`credential-entry-verify.ts` から切り出し）。
 *
 * 「呼び出し側が渡した入力をどう読み、委譲先へどう中継するか」だけを担う。中継漏れ・鎖読みは
 * どちらも fail-open に直結するため、その判断根拠を各関数の JSDoc に残している。
 */

import { nonObjectPrototypeProperty, ownProperty } from '../../../prototype-safety/own-property.js';
import type {
  EmbeddedCredentialKeyResolver,
  EmbeddedCredentialVerifyInput,
} from '../credential-results.js';

/**
 * 委譲先へ渡す共通オプション。
 *
 * `nowSeconds` / `clockSkewSeconds` / `issuerTrust` は**未指定でも必ず own キーとして生やす**
 * （条件付き展開で落とすと委譲先の own 読みが「未指定」と正しく判定できるのはよいが、こちら側の
 * 組み立てで分岐が増えるだけで利点が無い。`undefined` を明示すれば委譲先は既定値へ倒れる）。
 * とくに `clockSkewSeconds` は**必ず中継する**: VP 側で `clockSkewSeconds: 0` と厳格化したのに
 * 内包 VC だけ既定 120 秒で評価されると、呼び出し側の指定が黙って無視され、失効直後の VC が
 * `valid: true` で通る（`nowSeconds` だけ中継して skew を落とすのは非対称）。
 */
export function delegatedOptions(input: EmbeddedCredentialVerifyInput) {
  return {
    nowSeconds: nowSecondsOf(input),
    clockSkewSeconds: ownProperty<number>(input, 'clockSkewSeconds'),
    issuerTrust: ownProperty<EmbeddedCredentialVerifyInput['issuerTrust']>(input, 'issuerTrust'),
  };
}

/**
 * 検証時刻（秒）を **own 限定**で読む。`input.nowSeconds` を鎖読みすると、キーを省略した JS 呼び出しで
 * `Object.prototype.nowSeconds` の汚染値（過去時刻）が採用され、失効済みの内包 VC が `valid: true` / `isExpired: false`
 * になる。省略時は `undefined`（委譲先は現在時刻、`isExpiredAt` は判定不能として失効扱い = fail-closed）。
 */
export function nowSecondsOf(
  input: Pick<EmbeddedCredentialVerifyInput, 'nowSeconds'>,
): number | undefined {
  return ownProperty<number>(input, 'nowSeconds');
}

/**
 * 発行者鍵の DI を**使用地点で**取り出す。
 *
 * `verifyEmbeddedCredentials` は公開プリミティブであり、当該キーを**持たない**入力を渡す
 * 呼び出し側が存在する。鎖読みすると `Object.prototype.credentialKey` の汚染値が「呼び出し側が
 * 渡した鍵解決」として採用され、攻撃者が選んだ鍵で偽造 VC が `valid: true` になる（fail-open）。
 * 一方 DI は `class Deps { credentialKey() {} }` とプロトタイプメソッドで実装するのが正当なので
 * own 限定では読めない（正当な DI が無言で「未指定」になり全件検証不能に落ちる）。そこで
 * `Object.prototype` 由来だけを弾き、関数でない値は未指定として扱う
 * （`resolvePresentationVerificationFields` と同じ読み方）。
 */
export function credentialKeyOf(
  input: EmbeddedCredentialVerifyInput,
): EmbeddedCredentialKeyResolver | undefined {
  const resolver = nonObjectPrototypeProperty<EmbeddedCredentialKeyResolver>(
    input,
    'credentialKey',
  );
  return typeof resolver === 'function' ? resolver : undefined;
}
