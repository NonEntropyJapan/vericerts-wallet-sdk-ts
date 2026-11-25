/**
 * WUA JWT の構造解析・検証。
 *
 * 提供機能:
 * - `parseWalletUnitAttestation`: WUA JWT を解析し `WalletUnitAttestation` へ復元（形式検査のみ）
 * - `verifyWalletUnitAttestation`: Wallet Provider 署名 + 期限 + `vct` を検証
 * - `isWalletAttestationExpired`: 期限切れ検知（リフレッシュ判定）
 * - `refreshWalletAttestation`: 期限切れ WUA を再発行 WUA へ差し替え（10103 回復経路）
 * - `verifyWscdBinding`: `cnf.jwk` が WSCD（Passkey）鍵に一致するか検証
 *
 * 署名検証は既存の `verifyWithJwk`（`credential/vc/jws.ts`）を再利用し、`jose` は導入しない。
 * Wallet Provider の公開鍵 JWK は信頼判定（ETSI TSL / Federation / ARF Catalogue）を経て
 * 呼び出し側から渡される前提とし、信頼アンカー解決は本モジュールの責務外とする。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に JWT 本文・鍵素材を含めない。
 * - `alg=none` 等の未対応 alg は署名検証不成立として 10102 に正規化する。
 */

import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import type { CredentialAlg } from '../../credential/vc/jws.js';
import {
  decodeCompactJws,
  SUPPORTED_CREDENTIAL_ALGS,
  verifyWithJwkOrFalse,
} from '../../credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { publicKeyJwkMatches } from './jwk-match.js';
import { type WalletUnitAttestation, WUA_VCT, type WuaConfirmation } from './types.js';

// WUA payload は `decodeCompactJws` → `identity/jwt/jwt-codec.ts` の `parseJson` →
// `parse-json.ts` の `parseJsonWithoutPrototype` を通るため **`null` プロトタイプ**である。
// own 限定で読むのは
// その手法と**重畳する多層防御**で、鎖読みへ戻すと、パース境界を通らない値の流入時に
// 次の破れが復活する。クレームを鎖読みすると、
// 当該クレームを own に持たない WUA でも汚染値が拾われ、しかも `parseWalletUnitAttestation` が
// それを**戻り値の own プロパティへ詰め直す**（`own-property.ts` が警告する repack パターン）。
// 詰め直した後は下流の own 限定読み取りでは汚染値と正当な値を区別できないため、
// `verifyWscdBinding` の own 化が丸ごと無効化される。読み取り時点で own 限定に倒す。
// 具体的な破れ: `Object.prototype.cnf` 汚染で cnf を持たない WUA が攻撃者鍵にバインドされ、
// `Object.prototype.exp` 汚染で期限切れ判定が永久に false になり、`Object.prototype.iss` 汚染で
// `walletProviderDID` が攻撃者の選んだ値になる。クレームは JSON 由来の純データなので
// `ownProperty` を使う。

/** 文字列クレームを own 限定で取り出す。欠落・型不正は null。 */
function stringClaim(payload: Record<string, unknown>, key: string): string | null {
  const value = ownProperty<unknown>(payload, key);
  return isNonEmptyString(value) ? value : null;
}

/** NumericDate クレーム（非負整数秒）を own 限定で取り出す。欠落・型不正・負値・非整数は null。 */
function numericDateClaim(payload: Record<string, unknown>, key: string): number | null {
  const value = ownProperty<unknown>(payload, key);
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null;
}

/** `cnf.jwk`（EC 公開鍵）を own 限定で取り出す。構造不正は null。 */
function confirmationClaim(payload: Record<string, unknown>): WuaConfirmation | null {
  const cnf = ownProperty<unknown>(payload, 'cnf');
  if (typeof cnf !== 'object' || cnf === null) {
    return null;
  }
  const jwk = ownProperty<unknown>(cnf, 'jwk');
  if (typeof jwk !== 'object' || jwk === null) {
    return null;
  }
  return { jwk: jwk as PublicKeyJwk };
}

/**
 * WUA JWT を解析し `WalletUnitAttestation` へ復元する（署名検証はしない）。
 *
 * `vct` が `urn:eudi:wallet-attestation:1` であること、必須クレーム（`iss` / `sub` / `iat` /
 * `exp` / `cnf.jwk`）が揃っていることを構造検査する。署名・期限・バインドの検証は別関数が担う。
 *
 * @param jwt WUA JWT（コンパクト JWS）。
 * @returns 解析済み WUA。
 * @throws 形式不正・必須クレーム欠落の場合（VericertsError、code `10102`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export function parseWalletUnitAttestation(jwt: string): WalletUnitAttestation {
  let payload: Record<string, unknown>;
  try {
    payload = decodeCompactJws(jwt).payload;
  } catch {
    // JWT 本文はメッセージに含めず検証失敗へ正規化する。
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
  }

  const iss = stringClaim(payload, 'iss');
  const sub = stringClaim(payload, 'sub');
  const iat = numericDateClaim(payload, 'iat');
  const exp = numericDateClaim(payload, 'exp');
  const cnf = confirmationClaim(payload);
  if (
    ownProperty<unknown>(payload, 'vct') !== WUA_VCT ||
    iss === null ||
    sub === null ||
    iat === null ||
    exp === null ||
    cnf === null
  ) {
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
  }

  // `sub`（Wallet Instance の識別子）は構造検査の必須クレームだが、`WalletUnitAttestation` 自体は
  // `walletInstanceId` を持たない。値を要する箇所
  // （`buildWuaProofOfPossession` の PoP `iss`）は `wua.jwt` を都度デコードして読む。

  return {
    jwt,
    vct: WUA_VCT,
    walletProviderDID: iss,
    cnf,
    // 発行時刻と有効期限は ISO 8601 文字列で持つ。JWT 本体の `iat` / `exp` は
    // NumericDate のまま（JWT 標準に従う、変更不可）で、ここは復元後の表現だけを変換する。
    issuedAt: new Date(iat * 1000).toISOString(),
    expiresAt: new Date(exp * 1000).toISOString(),
  };
}

/**
 * WUA が期限切れか判定する。
 *
 * `expiresAt`（ISO 8601）を `nowSeconds * 1000` 以下なら期限切れとみなす。リフレッシュ要否の判定に使う。
 *
 * @param wua 検証対象の WUA。
 * @param nowSeconds 現在時刻（NumericDate、秒）。
 * @returns 期限切れなら `true`。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export function isWalletAttestationExpired(
  wua: WalletUnitAttestation,
  nowSeconds: number,
): boolean {
  // `expiresAt` は**自身のプロパティに限って**読み、ISO 8601 文字列であることを検査する。
  // `WalletUnitAttestation` は呼び出し側が組み立てて渡す入力でパース境界
  // を通らないため、`wua.expiresAt` の鎖読みには 2 つの破れがあった。
  // - **汚染なしでも**: own に `expiresAt` を持たない WUA では `undefined <= nowSeconds` が
  //   false になり、**期限切れでないと判定されて期限ゲートを素通りする**（fail-open）。
  // - 汚染下: `Object.prototype.expiresAt` の値が「実測の有効期限」として採用される。
  // 取得できない・文字列でない・日時として解釈できない場合は**期限切れとして扱う**
  // （fail-closed）。リフレッシュ要否の判定に使う公開 API なので、判定不能を「まだ有効」に
  // 倒してはならない。
  const expiresAt = ownProperty<unknown>(wua, 'expiresAt');
  if (typeof expiresAt !== 'string') {
    return true;
  }
  const expiresAtMs = parseIsoDateTimeMs(expiresAt);
  if (Number.isNaN(expiresAtMs)) {
    return true;
  }
  // 時計が非有限（NaN 等）だと比較が常に false になり期限切れ WUA を「有効」と判定してしまう。
  // `expiresAt` 側と同じく判定不能は期限切れに倒す（fail-closed）。
  if (!Number.isFinite(nowSeconds)) {
    return true;
  }
  return expiresAtMs <= nowSeconds * 1000;
}

/**
 * 期限切れ WUA を、Wallet Provider が再発行した WUA JWT へ差し替える。
 *
 * 期限切れ（`isWalletAttestationExpired` = `true` / error code 10103）の回復経路。WUA JWT の
 * 発行（Wallet Provider Backend への再取得リクエスト）は本 SDK の責務外のため、リフレッシュで
 * 取得した新 WUA JWT を引数で受け取り、以下を検証して差し替え後の WUA を返す:
 *
 * - 新 WUA JWT が構造・署名・`vct` について正当で、`nowSeconds` 時点で期限内であること
 *   （`verifyWalletUnitAttestation` と同一の判定。不正は 10102、期限切れは 10103）
 * - 新 WUA の確認鍵 `cnf.jwk` が旧 WUA の `cnf.jwk`（= WSCD/Passkey 鍵）と一致すること。
 *   リフレッシュ後も同一 WSCD 鍵にバインドされ続けることを保証し、鍵すり替えを防ぐ
 *   （不一致は WSCD バインド不成立として 10102）。
 *
 * `providerJwk` の信頼判定（ETSI TSL / Federation / ARF Catalogue）は呼び出し側の責務。
 *
 * @param previous 期限切れ（または期限が近い）現行 WUA。
 * @param refreshedJwt Wallet Provider が再発行した新 WUA JWT（コンパクト JWS）。
 * @param providerJwk 信頼済み Wallet Provider の EC 公開鍵 JWK。
 * @param nowSeconds 現在時刻（NumericDate、秒）。
 * @returns 検証済みの新 WUA（差し替え後の現行 WUA として利用する）。
 * @throws 新 WUA が署名・vct・WSCD バインド不正の場合（code `10102`）、期限切れの場合（code `10103`）。
 *         `previous` の `cnf` / `cnf.jwk` を own 読みできない場合も `10102`（fail-closed）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export function refreshWalletAttestation(
  previous: WalletUnitAttestation,
  refreshedJwt: string,
  providerJwk: PublicKeyJwk,
  nowSeconds: number,
): WalletUnitAttestation {
  const refreshed = parseWalletUnitAttestation(refreshedJwt);
  verifyWalletUnitAttestation(refreshed, providerJwk, nowSeconds);
  // 照合の**基準側**（旧 WUA の `cnf.jwk`）も own 限定で読む。鎖読みで渡すと
  // `verifyWscdBinding` 内部を own 化しても、渡す前に `Object.prototype.cnf` の汚染値が
  // 基準に化けて鍵すり替えを許す。own に無ければ WSCD バインド不成立として閉じる。
  const previousCnf = ownProperty<unknown>(previous, 'cnf');
  const previousJwk =
    typeof previousCnf === 'object' && previousCnf !== null
      ? ownProperty<unknown>(previousCnf, 'jwk')
      : undefined;
  if (typeof previousJwk !== 'object' || previousJwk === null) {
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
  }
  // リフレッシュ前後で同一 WSCD 鍵にバインドされ続けることを保証する。
  verifyWscdBinding(refreshed, previousJwk as PublicKeyJwk);
  return refreshed;
}

/**
 * WUA を Wallet Provider 署名・期限・`vct` について検証する。
 *
 * - `vct` が `urn:eudi:wallet-attestation:1` であること
 * - `providerJwk`（信頼済み Wallet Provider 公開鍵）で JWT 署名が検証できること（不一致は 10102）
 * - `nowSeconds` 時点で期限切れでないこと（期限切れは 10103）
 *
 * `providerJwk` の信頼判定（ETSI TSL / Federation / ARF Catalogue）は呼び出し側の責務。
 *
 * @param wua 検証対象の WUA。
 * @param providerJwk 信頼済み Wallet Provider の EC 公開鍵 JWK。
 * @param nowSeconds 現在時刻（NumericDate、秒）。
 * @throws 署名・vct 不正の場合（code `10102`）、期限切れの場合（code `10103`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export function verifyWalletUnitAttestation(
  wua: WalletUnitAttestation,
  providerJwk: PublicKeyJwk,
  nowSeconds: number,
): void {
  // `vct` は**自身のプロパティに限って**読む（`eudi/pid/schema.ts` の
  // `validatePIDSchema` と同クラス）。`WalletUnitAttestation` は呼び出し側が組み立てて渡す入力で
  // パース境界では守られないため、鎖読みだと own に `vct` を持たない WUA が
  // `Object.prototype.vct = 'urn:eudi:wallet-attestation:1'` の汚染下で**型識別子ゲート（10102）を
  // 素通りする**。
  if (ownProperty<string>(wua, 'vct') !== WUA_VCT) {
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
  }

  // 署名検証の対象そのものも own 限定で読む。鎖読みだと own に `jwt` を持たない WUA へ
  // `Object.prototype.jwt` の汚染値が**検証対象の JWT として供給される**。
  const jwt = ownProperty<unknown>(wua, 'jwt');
  if (typeof jwt !== 'string' || jwt.length === 0) {
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
  }

  let decoded: ReturnType<typeof decodeCompactJws>;
  let alg: unknown;
  try {
    decoded = decodeCompactJws(jwt);
    alg = ownProperty<unknown>(decoded.header, 'alg');
  } catch {
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
  }

  if (typeof alg !== 'string' || !SUPPORTED_CREDENTIAL_ALGS.has(alg)) {
    // alg=none や未対応 alg は署名検証不成立として拒否する。
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
  }

  // JWK 形式不正・alg と鍵種別の不一致も署名検証不成立（false）として拒否する。
  if (!verifyWithJwkOrFalse(alg as CredentialAlg, decoded, providerJwk)) {
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
  }

  // 署名検証後に期限を評価する（期限切れは再取得/リフレッシュで解消し得るため別コード）。
  if (isWalletAttestationExpired(wua, nowSeconds)) {
    throw new VericertsError(ErrorCodes.WUA_LIFETIME_EXPIRED);
  }
}

/**
 * WUA `cnf.jwk` が WSCD（Passkey）由来の公開鍵にバインドされているか検証する。
 *
 * WSCD が保持する公開鍵と WUA `cnf.jwk` が同一の鍵を表すことを検査する（`publicKeyJwkMatches`）。
 * これにより WUA-PoP の署名鍵（= WSCD 鍵）が WUA にバインドされていることを保証する。
 *
 * `y` は EC 鍵のみが持つため、比較は `kty` に応じて分岐する（OKP / Ed25519 は `y` を持たない）。
 * かつて `y` を無条件に要求していたため、Ed25519 の `cnf.jwk` は同一鍵同士でも常に `10102` で
 * 失敗していた（WUA 署名検証は EdDSA を通すのに WSCD バインドだけ通らない非対称）。
 *
 * @param wua 検証対象の WUA。
 * @param wscdPublicKeyJwk WSCD（Passkey）由来の公開鍵 JWK（EC または OKP / Ed25519）。
 * @throws `cnf.jwk` と WSCD 鍵が一致しない場合、および `cnf` / `cnf.jwk` を own 読みできない
 *         場合（VericertsError、code `10102`。汚染値を比較基準に採らず fail-closed に倒す）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export function verifyWscdBinding(
  wua: WalletUnitAttestation,
  wscdPublicKeyJwk: PublicKeyJwk,
): void {
  // `cnf` / `cnf.jwk` 自体も own 限定で読む。鎖読みだと `cnf` を持たない WUA でも
  // `Object.prototype.cnf` の汚染値が比較基準に化け、`publicKeyJwkMatches` を own 化しても
  // バインド検査が攻撃者の選んだ鍵で成立する。欠落・型不正は `as` で流さず fail-closed に倒す。
  const cnf = ownProperty<unknown>(wua, 'cnf');
  const cnfJwk =
    typeof cnf === 'object' && cnf !== null ? ownProperty<unknown>(cnf, 'jwk') : undefined;
  if (typeof cnfJwk !== 'object' || cnfJwk === null) {
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
  }
  const matches = publicKeyJwkMatches(
    cnfJwk as Record<string, unknown>,
    wscdPublicKeyJwk as Record<string, unknown>,
  );
  if (!matches) {
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
  }
}
