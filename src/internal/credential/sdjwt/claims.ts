/**
 * SD-JWT VC 検証時の untrusted payload 検証とクレーム復元ヘルパ。
 *
 * `verifySdJwt`（`sdjwt-verify.ts`）から分離した、Issuer payload の `cnf` / `status` 形状検証と、
 * Disclosure の digest 照合・平文クレーム復元（`_sd_alg` 検査。再帰適用は `recover-disclosures.ts`）を担う。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に salt・開示値・公開鍵・JWT を含めない。
 * - 不正形状の `cnf` を crypto（`verifyWithJwk`）へ渡す前に弾き、@noble / Web Crypto 由来例外が
 *   正規化されずに表出するのを防ぐ。
 * - `cnf.jwk` の曲線は署名用（`ALG_SPECS` 由来の `SIGNING_CRVS_BY_KTY`）に限定する。鍵合意専用の
 *   `X25519` などを Holder 署名鍵として受理しない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { SIGNING_CRVS_BY_KTY } from '../../identity/jwt/jwk-key.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { isPlainObject as isObject } from '../object-guards.js';
import { applyDisclosures } from './recover-disclosures.js';
import type { ConfirmationClaim, SdJwtParts, StatusReference } from './sdjwt.js';
import { SD_ALG } from './sdjwt.js';

/**
 * `source` の**自身のプロパティを 1 度だけ**読み出し、`null` プロトタイプの素データへ写す。
 *
 * 検証と戻り値で同じオブジェクトを二度読むと、own アクセサ（`{ get y() {…} }`）が呼ばれるたびに
 * 別の値を返せるため、**検証を通った値と呼び出し元へ返る値が食い違う**（検証時は `y` 未定義、
 * 返す時は `y: '…'` のような TOCTOU）。読み取りを 1 回に固定してから検証・返却の両方をこの写しに
 * 対して行うことで、その乖離を構造的に無くす。
 *
 * `Object.assign` を使わないのは、列挙可能な own しか複製せず、`ownProperty`（列挙可否を問わない）で
 * 検証を通った**非列挙 own メンバが戻り値から欠落する**ため。`getOwnPropertyNames` は非列挙も含む。
 * 値は `source[key]` で読むのでアクセサはちょうど 1 回評価され、写した先は常にデータプロパティになる。
 *
 * 写しは元と完全に同形ではない。以下は JSON 由来の JWK では生じないが、「own メンバを黙って
 * 落とさない」という上記の一文に対する例外である:
 *
 * - 非列挙 own は**列挙可能な**データプロパティとして写る（値は保たれる）。
 * - `getOwnPropertyNames` は Symbol キーを拾わないため、Symbol own は写らない。
 *
 * 浅い写しである点も意図的。**検証対象のメンバ**（`kty` / `crv` / `x` / `y`）は string 以外を弾く
 * ため入れ子を持たないが、`kid` のような検証対象外メンバには任意の JSON 値が入り得る。その入れ子の
 * 鎖は保持される（断つ対象は crypto と公開 API に渡る `jwk` 直下のメンバであり、戻り値の
 * オブジェクトグラフ全体ではない）。
 */
function ownDataSnapshot(source: Record<string, unknown>): Record<string, unknown> {
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of Object.getOwnPropertyNames(source)) {
    snapshot[key] = source[key];
  }
  return snapshot;
}

/**
 * untrusted payload の `cnf` を実行時検証する。
 *
 * `{ jwk: ... }` の形状で、`jwk.kty` に応じた必須フィールドが揃っていなければ不正とみなす:
 * - `kty: 'EC'`（`ES256` / `ES256K`）: `crv` / `x` / `y` がいずれも string。`crv` は `P-256` か `secp256k1`。
 * - `kty: 'OKP'`（`EdDSA`）: `crv` / `x` が string で `crv` は `Ed25519`。OKP 鍵は `y` を持たないため、
 *   `y` があれば拒否する。鍵合意専用の `X25519` は署名鍵ではないため受理しない。
 *
 * それ以外の `kty`（RSA 等）も拒否する。未検証のまま `verifyWithJwk` へ流すと不正 JWK 形状由来の
 * @noble / Web Crypto 例外が正規化されずに表出し得るため、ここで形状を保証してから crypto に渡す。
 * 許可 `crv` は `SIGNING_CRVS_BY_KTY`（`ALG_SPECS` から導出）を SSOT とし、SDK が実際に検証できる
 * alg の集合と常に一致させる。
 *
 * `cnf` の `jwk` と JWK の `kty` / `crv` / `x` / `y` は、いずれも**自身のプロパティ**としてのみ読む
 * （`dpop-common.ts`・ `jwk-key.ts` と同型の是正）。鎖で読むと、汚染下で
 * 読み取りの欠陥が両方向に生じる:
 *
 * - 可用性 / DoS: `Object.prototype.y` 汚染下で、OKP 分岐の `y` 不在チェックが継承値を拾い、
 *   **`y` を持たない RFC 8037 準拠の正当な Ed25519 JWK が誤って拒否される**。この面は `jwk-key.ts`
 *   側を own 限定にしても塞がらない。形状検証を先に行う本関数で拒否が確定し、下流の
 *   `jwkToOkpPublicKey` まで到達しないためである。
 * - fail-open: `jwk` / `kty` / `crv` / `x` 汚染下で、それらを**欠く JWK が継承値で補われて形状検証を
 *   通過する**。
 *
 * **現時点の到達性（多層防御としての位置づけ）**: 現行の呼び出し元（`verify.ts` の `verifySdJwt` /
 * `key-binding.ts` の `extractCnfJwk`）に届く `cnf` はパース境界（`parseJsonWithoutPrototype`）で
 * 入れ子まで `null` プロトタイプ化されるため、上記 2 面は公開 API 経由では現状到達しない。それでも
 * own 化するのはパース境界と重畳させる多層防御のためで、読み取り時点で鎖を断つ責務は本関数側に残る。
 *
 * JWK のメンバは純データでクラスインスタンス・関数値を取らないため、`nonObjectPrototypeProperty`
 * ではなく own 限定の `ownProperty` が正しい（`own-property.ts` の使い分け）。
 *
 * 戻り値の `jwk` は、`ownDataSnapshot` で **own メンバを 1 度だけ読み出した `null` プロトタイプの
 * 写し**を返す（検証もこの写しに対して行う）。元オブジェクトをそのまま返すと、own 限定で検証したのに
 * **鎖を持ったままの JWK** が公開 API の `VerifiedSdJwt.cnf` へ露出し、汚染下では `cnf.jwk.y` のような
 * 継承値が読めてしまう。検証済みの `kty` / `crv` / `x` / `y` だけで組み直さないのは、`kid` / `alg` /
 * `use` 等の own メンバを黙って落とさないためである（`ConfirmationClaim.jwk` の `PublicKeyJwk` は任意
 * メンバを許す JWK 型で、下流の `verifyWithJwk` にもそのまま渡る）。通常経路の `cnf.jwk` は元から
 * `null` プロトタイプなので、写した後の形状は現在の挙動と一致する。
 *
 * 鎖を断つ範囲は `jwk` 自身に限る点に注意する。返す `ConfirmationClaim` の外側リテラルは通常の
 * オブジェクトで `Object.prototype` を継承し、写しも浅い（入れ子の値があればその鎖は保持される）。
 * JWK のメンバは文字列なので実際の入れ子は生じないが、断つ対象は「crypto と公開 API に渡る `jwk` の
 * メンバ」であって戻り値のオブジェクトグラフ全体ではない。
 *
 * @param value payload の `cnf`。
 * @param requireKeyBinding KB-JWT 必須か（必須時の不正は 3012、それ以外は 3010）。
 * @returns 形状検証済み `ConfirmationClaim`。未設定（undefined）はそのまま返す。
 * @throws 形状不正の場合（VericertsError、3012 または 3010）。
 */
export function validateCnf(
  value: unknown,
  requireKeyBinding: boolean,
): ConfirmationClaim | undefined {
  if (value === undefined) {
    return undefined;
  }
  const code = requireKeyBinding ? ErrorCodes.HOLDER_BIND_MISMATCH : ErrorCodes.SIG_INVALID;
  if (!isObject(value)) {
    throw new VericertsError(code);
  }
  const rawJwk = ownProperty<unknown>(value, 'jwk');
  if (!isObject(rawJwk)) {
    throw new VericertsError(code);
  }
  // own メンバを **1 度だけ** 読み出した写しを作り、以降の検証と戻り値の両方でこれを使う。
  // 元オブジェクトを二度読むと own アクセサが検証値と戻り値を食い違わせられる（TOCTOU）。
  // 写しの生成で throwing getter が例外を投げた場合も、契約内のコードへ正規化して漏らさない。
  let jwk: Record<string, unknown>;
  try {
    jwk = ownDataSnapshot(rawJwk);
  } catch {
    throw new VericertsError(code);
  }
  // 以降の `ownProperty` は写し（`null` プロトタイプ・own データのみ）に対しては意味的に no-op だが、
  // 「JWK メンバは own 限定で読む」規律を読み取り位置に残すため明示する（多層防御）。鎖を断っている
  // のは上の写しの層であり、この 4 行はその不変条件に依存していることを示す。
  const kty = ownProperty<unknown>(jwk, 'kty');
  const crv = ownProperty<unknown>(jwk, 'crv');
  const x = ownProperty<unknown>(jwk, 'x');
  const y = ownProperty<unknown>(jwk, 'y');
  if (typeof crv !== 'string' || typeof x !== 'string') {
    throw new VericertsError(code);
  }
  if (kty === 'EC') {
    if (typeof y !== 'string') {
      throw new VericertsError(code);
    }
  } else if (kty === 'OKP') {
    // OKP 鍵は `y` を持たない（RFC 8037）。EC JWK の偽装を弾く。
    if (y !== undefined) {
      throw new VericertsError(code);
    }
  } else {
    throw new VericertsError(code);
  }
  if (SIGNING_CRVS_BY_KTY.get(kty)?.has(crv) !== true) {
    // 署名検証に使えない曲線（`X25519` 等の鍵合意専用曲線を含む）は crypto へ渡す前に拒否する。
    throw new VericertsError(code);
  }
  // 検証に使ったのと**同一の**写しを返す（再読み取りしないので検証値と戻り値が必ず一致する）。
  return { jwk };
}

/**
 * untrusted payload の `status` を実行時検証する。
 *
 * `{ status_list: { idx: 非負整数, uri: string } }` の形状でなければ 3010 で拒否する。未検証の任意形状が
 * 呼び出し側や `resolveStatus` / `resolver.resolve` へそのまま渡らないようにする。
 *
 * `status_list` と `idx` / `uri` は、いずれも**自身のプロパティ**としてのみ読む（
 * `validateCnf` と同クラス）。鎖読みだと、`status` に own の `{}` を持つ VC が
 * `Object.prototype.status_list` 汚染下で継承値を拾って形状検証を通過し、**攻撃者が選んだ
 * status list URI** が下流の `resolveStatus` / `resolver.resolve` へ渡る（fail-open）。到達性の
 * 位置づけ（パース境界との重畳）は `validateCnf` と同じ。読む対象は `JSON.parse` 由来の純データで
 * クラスインスタンスにならないため `nonObjectPrototypeProperty` ではなく `ownProperty` が正しい。
 *
 * @param value payload の `status`。
 * @returns 形状検証済み `StatusReference`。未設定（undefined）はそのまま返す。
 * @throws 形状不正の場合（VericertsError、3010）。
 */
export function validateStatus(value: unknown): StatusReference | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isObject(value)) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  // own 限定で **1 度だけ** 読む（2 度読むと own アクセサが読むたびに別値を返せる）。
  const list = ownProperty<unknown>(value, 'status_list');
  if (!isObject(list)) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  const idx = ownProperty<unknown>(list, 'idx');
  const uri = ownProperty<unknown>(list, 'uri');
  // `idx` は非負整数（Token Status List §6.2）。負数・小数・NaN / Infinity は、失効リゾルバー
  // （`assertIndex`、3002）に届く前の検証時点で 3010 にする。resolver を使わない経路でも不正な
  // `idx` が `VerifiedSdJwt.status` に残らないようにするため。
  if (typeof idx !== 'number' || !Number.isInteger(idx) || idx < 0 || typeof uri !== 'string') {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  // 詰め直しは own 読みした `idx` / `uri` からのみ行う（継承値が own へ昇格するのを防ぐ）。
  return { status_list: { idx, uri } };
}

/**
 * 同梱 Disclosure を payload へ再帰的に適用し、平文クレームへ復元する（RFC 9901 §7.1）。
 *
 * Issuer payload の平文クレーム（`vct` / `cnf` / `status` 等を含む）に、照合できた Disclosure の
 * クレームをマージして返す。Disclosure はオブジェクトプロパティ（3 要素）と配列要素（2 要素）の
 * 両方を扱い、入れ子の `_sd` / `{"...": digest}` も任意の深さで復元する（適用の詳細と拒否条件の
 * 一覧は `recover-disclosures.ts` の `applyDisclosures`）。以下はいずれも 3010 として拒否する:
 * - payload に `_sd_alg` があり、本実装の対応値（`sha-256`）と異なる（ハッシュアルゴリズム混同・
 *   ダウングレード攻撃の防止。SD-JWT draft が要求する検証者の `_sd_alg` 検査）。
 * - 参照されない Disclosure（改竄・捏造）/ 同一 digest の重複 / 同名クレームの衝突。
 * - 最上位クレームが `NON_DISCLOSABLE_CLAIMS`（`exp` / `status` / `cnf` / `aka_vcts` 等、検証が
 *   payload 本体で評価するクレーム）の Disclosure になっている（評価回避の防止）。
 */
export function recoverClaims(
  payload: Record<string, unknown>,
  parts: SdJwtParts,
): Record<string, unknown> {
  // `payload` は `credential/vc/jws.ts` の `decodeCompactJws` → `identity/jwt/jwt-codec.ts` の
  // `parseJson` → `parse-json.ts` の `parseJsonWithoutPrototype` を通って届くため **`null`
  // プロトタイプ**である。own 限定で読むのはその手法と**重畳する多層防御**で、鎖で読む形へ戻すと、
  // パース境界を通らない値がここへ流入した時点で
  // **`_sd` / `_sd_alg` を持たない** SD-JWT が汚染値を「実際に入っていた値」として扱う:
  // - `_sd`: 汚染された digest 配列が参照元になり、Issuer が署名していない digest に
  //   対応する偽造 Disclosure が照合を通過して平文クレームへ復元される（fail-open）。
  // - `_sd_alg`: 汚染値（`sha-256` 以外）を拾って正当な VC が一律 3010 で拒否される（可用性）。
  // 対象は `JSON.parse` 済みの素のオブジェクトでクラスインスタンス・関数値にはならないため、
  // `nonObjectPrototypeProperty` ではなく own 限定の `ownProperty` が正しい。
  const sdAlg = ownProperty<unknown>(payload, '_sd_alg');
  if (sdAlg !== undefined && sdAlg !== SD_ALG) {
    // 未対応の `_sd_alg`（ハッシュアルゴリズム混同・ダウングレード）を明示的に拒否する。
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  // 戻り値は `Object.create(null)` で作る。`payload` はパース境界
  // （`parse-json.ts`）で `null` プロトタイプになって届くので、ここで `{}` リテラルへ写すと
  // **公開境界でプロトタイプを復元する repack** になる。公開境界で
  // `Object.prototype` を継承するオブジェクトへ詰め直すと、継承値がクレームに見えてしまう。
  // `VerifiedSdJwt.claims` は任意の
  // クレーム名で読まれる面（`verified.claims.isAdmin` 等）であり、`Object.prototype.isAdmin` の
  // 汚染下では**そのクレームを持たない VC でも継承値が「検証済みクレーム」として読めてしまう**。
  // `claims` は `hasOwnProperty` を継承しない。呼び出し側では `Object.hasOwn` を使える。
  // 復元は `applyDisclosures` が `null` プロトタイプのオブジェクトで組む（`_sd` の own 限定読みと
  // `__proto__` クレームの扱いも同所）。
  return applyDisclosures(payload, parts.disclosures);
}
