/**
 * JWT-VC の payload から「VC 本体」の所在を決める。
 *
 * JWT-VC には 2 つの表現がある:
 * - `wrapped`: JWT-VC 1.1 系。VC 本体は `vc` claim に入り、JWT claim（`iss` / `sub` / `nbf` / `exp` /
 *   `jti`）は本体の写しである。日付は `issuanceDate` / `expirationDate`。本 SDK の `issueCredential`
 *   はこの形で発行する。
 * - `flat`: VC-JOSE-COSE（VC 2.0 系）。`vc` で包まず、payload 自体が VC 本体である（`@context` /
 *   `type` / `issuer` / `credentialSubject` をトップレベルに持つ）。日付は `validFrom` / `validUntil`。
 *   walt.id が VC 2.0 の `@context` に対して出す形。
 *
 * 判定は**署名済み payload の own プロパティ**だけで行う（鎖読みすると `Object.prototype.vc` /
 * `Object.prototype['@context']` の汚染値が VC 本体に化け、表現の選択を汚染側へ倒せる）。
 * `vc` claim を持てば常に `wrapped`（`@context` を併せ持っていても 1.1 の厳格な検査を維持する）。
 * `vc` が無く own の `@context` があるときだけ `flat`。どちらでもなければ本体を持たない
 * （`wrapped` で `body: undefined`）ため、呼び出し側の構造検証が 3002 に倒す。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';

/** JWT-VC の表現（本ファイル冒頭参照）。 */
export type JwtVcForm = 'wrapped' | 'flat';

/** VC 本体の所在。`body` は未検証の値で、構造検証は呼び出し側が行う。 */
export interface JwtVcBody {
  readonly form: JwtVcForm;
  /** `wrapped` では `vc` claim の値（無ければ `undefined`）、`flat` では payload そのもの。 */
  readonly body: unknown;
}

/** payload から VC 本体の所在を返す。 */
export function jwtVcBodyOf(payload: Record<string, unknown>): JwtVcBody {
  const vc = ownProperty<unknown>(payload, 'vc');
  if (vc === undefined && ownProperty<unknown>(payload, '@context') !== undefined) {
    return { form: 'flat', body: payload };
  }
  return { form: 'wrapped', body: vc };
}
