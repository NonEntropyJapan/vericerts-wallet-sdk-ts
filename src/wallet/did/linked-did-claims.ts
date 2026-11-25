/**
 * Domain Linkage Credential（DLC）の検証済み payload に対して DLC 固有の条件を確認する。
 *
 * 署名・発行者 DID の解決・時刻クレームは `verifyCredentialWith` が担い、ここでは self-issued であること、
 * `credentialSubject.origin` が検証対象と一致することだけを確かめる。
 */

import { isPlainObject } from '../../internal/credential/object-guards.js';
import { jwtVcBodyOf } from '../../internal/credential/vc/jwt-vc-body.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import type { LinkedDIDResult } from './options.js';

/**
 * own 限定でオブジェクト型のメンバを読む（非オブジェクト・`null`・配列は「無し」に倒す）。
 *
 * 取得した JSON は外部入力なので、プロトタイプ鎖を辿ると `vc` / `credentialSubject` を**持たない**
 * JWT でも `Object.prototype` の汚染値が生え、それを検証済みの主張として読んでしまう。
 * 読み出した値は検証せずにキャストしない（`own-property.ts`）ため、型も本関数で絞る。
 */
function ownObject(source: object, key: string): object | undefined {
  const value = ownProperty<unknown>(source, key);
  return isPlainObject(value) ? value : undefined;
}

/**
 * 検証を通った DLC の payload が、self-issued かつ `origin` 一致であることを確かめる。
 *
 * `verifyCredentialWith` は `iss` = `vc.issuer` と `sub` = `vc.credentialSubject.id` の突合まで済ませて
 * いるため、self-issued 判定は envelope 側の `iss` / `sub` の比較で足りる。
 *
 * @param payload 署名検証済みの JWT payload。
 * @param origin 検証対象ドメインオリジン。
 * @returns 検証結果（失敗理由は固定の識別子のみで、JWT 本文は載せない）。
 */
export function checkDomainLinkageClaims(
  payload: Record<string, unknown>,
  origin: string,
): LinkedDIDResult {
  const subject = ownProperty<unknown>(payload, 'sub');
  const issuer = ownProperty<unknown>(payload, 'iss');
  const did = typeof subject === 'string' ? subject : '';
  if (did.length === 0 || issuer !== did) {
    // 発行者 ≠ 対象 DID の VC は「その DID 自身がドメインを主張した」ことにならない。
    return { did, valid: false, error: 'not_self_issued' };
  }
  // VC 本体の所在は検証側（`verifyCredentialWith`）と同じ判定で決める（`vc` claim か、payload 自体か）。
  const { body } = jwtVcBodyOf(payload);
  const credentialSubject = isPlainObject(body) ? ownObject(body, 'credentialSubject') : undefined;
  if (
    credentialSubject === undefined ||
    ownProperty<unknown>(credentialSubject, 'origin') !== origin
  ) {
    return { did, valid: false, error: 'origin_mismatch' };
  }
  return { did, valid: true };
}
