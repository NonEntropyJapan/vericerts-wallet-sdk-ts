/**
 * 取得済み Status List Token の真正性検証とビット読み取り。
 *
 * IETF draft-ietf-oauth-status-list に沿って署名と `sub` を検証し、`lst` を展開してビットを読み取る。
 *
 * Token の**取得経路**（ネットワーク / キャッシュ / stale 再利用）と**検証**を分離するために
 * `status-list-resolver.ts` から切り出した。取得経路がどれであっても検証は同一であり、
 * キャッシュ命中時も stale な Token を FO-2 で再利用する時も本モジュールを必ず通す
 * （キャッシュに入った時点で検証済みとは扱わない）。
 *
 * `exp` の扱いは**型検証と期限超過判定を分ける**。
 *
 * - **型検証は本モジュールで行う**。`exp` があるのに NumericDate（非負整数）でない Token は
 *   構造不正として `VC_SCHEMA_INVALID`（3002）で拒否する。ここを素通りさせると `exp` を
 *   `"soon"` や `-1` や `1.5` にするだけで期限超過判定と TTL 切り詰めの両方が黙って無効化され、
 *   Token が上限いっぱいの TTL を得る。`exp` が無い Token は受理する。
 * - 期限超過（`now >= exp`）の判定は取得経路を知る `status-list-resolver.ts` が担う。
 *   新規取得した Token の期限切れは `VC_EXPIRED`（3024）。stale な Token を使う場合にも署名とビット値は検証する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URL・インデックス・ビット値・JWT を含めない。
 */

import type { CredentialAlg } from '../credential/vc/jws.js';
import {
  decodeCompactJws,
  SUPPORTED_CREDENTIAL_ALGS,
  verifyWithJwkOrFalse,
} from '../credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { PublicKeyJwk } from '../identity/did.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { decompressBitstring, type StatusBits, StatusBitstring } from './bitstring.js';
import { STATUS_LIST_TOKEN_TYP } from './status-list-token.js';

/** 許容されるエントリビット幅。 */
const ALLOWED_BITS: ReadonlySet<number> = new Set([1, 2, 4, 8]);

/** 署名・`sub` 一致まで確認できた Status List Token。 */
export interface VerifiedStatusListToken {
  /** デコード済み payload（`exp` などキャッシュ TTL 決定に使う項目を含む）。 */
  readonly payload: Record<string, unknown>;
  /** エントリあたりのビット数（1 / 2 / 4 / 8）。 */
  readonly bits: StatusBits;
  /** `base64url(zlib(bitstring))`。 */
  readonly lst: string;
  /**
   * 検証済みの `exp`（エポック秒）。`exp` を持たない Token では `undefined`。
   *
   * 「`undefined` = `exp` 不在」だけを意味する。不正な `exp` は `undefined` に落とさず
   * `VC_SCHEMA_INVALID`（3002）で拒否済みである（不在との取り違えが fail-open を生むため）。
   */
  readonly expSeconds?: number;
  /**
   * 検証済みの `iat`（Token の発行時刻、エポック秒）。
   *
   * draft-ietf-oauth-status-list §5.1 は `iat` を REQUIRED と定める。不在・不正は 3002 で拒否済み。
   * 鮮度（古い Token の再生）の判定に使う（`status-list-freshness.ts`）。
   */
  readonly iatSeconds: number;
  /**
   * 検証済みの `ttl`（消費者が再取得せずに使ってよい最大秒数）。`ttl` を持たない Token では
   * `undefined`。あるなら正の整数でなければならない（不正は 3002 で拒否済み）。
   */
  readonly ttlSeconds?: number;
}

/**
 * NumericDate（非負整数のエポック秒）かを判定する。
 *
 * `NaN` / `Infinity` / 小数 / 負値 / 非数値はいずれも期限判定を狂わせるため受理しない
 * （Federation の `statement.ts` と同じ規律）。
 */
function isNumericDate(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

/** デコード済み payload から評価に必要なフィールドを取り出し検証する。 */
function extractPayload(payload: Record<string, unknown>): {
  sub: string;
  bits: StatusBits;
  lst: string;
  expSeconds: number | undefined;
  iatSeconds: number;
  ttlSeconds: number | undefined;
} {
  // `exp` は任意だが、あるなら NumericDate でなければならない。不正値を `undefined` に丸めると
  // 期限超過判定と TTL 切り詰めが同時に無効化され Token が上限 TTL を得てしまう。
  if (payload.exp !== undefined && !isNumericDate(payload.exp)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const expSeconds = payload.exp === undefined ? undefined : (payload.exp as number);
  // `iat` は REQUIRED（draft-ietf-oauth-status-list §5.1）。鮮度判定の起点なので、不在・不正を
  // 受理すると古い Token の再生を検知できなくなる。
  if (!isNumericDate(payload.iat)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const iatSeconds = payload.iat;
  if (payload.ttl !== undefined && !(isNumericDate(payload.ttl) && payload.ttl > 0)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const ttlSeconds = payload.ttl === undefined ? undefined : (payload.ttl as number);
  const sub = payload.sub;
  const rawStatusList = payload.status_list;
  // status_list はオブジェクトであることを要求する（null / 配列 / プリミティブは構造不正）。
  if (
    typeof sub !== 'string' ||
    typeof rawStatusList !== 'object' ||
    rawStatusList === null ||
    Array.isArray(rawStatusList)
  ) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const statusList = rawStatusList as Record<string, unknown>;
  const bits = statusList.bits;
  const lst = statusList.lst;
  if (typeof bits !== 'number' || !ALLOWED_BITS.has(bits) || typeof lst !== 'string') {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return { sub, bits: bits as StatusBits, lst, expSeconds, iatSeconds, ttlSeconds };
}

/**
 * Status List Token の署名・`typ`・`sub` 一致を検証する。
 *
 * `alg=none` は専用コードで拒否し、未対応 alg は署名検証不能のため署名不一致に正規化する
 * （`verify.ts` と同じ severity 規約）。JOSE ヘッダ `typ` は `statuslist+jwt` を必須とし、欠落・
 * 別値（`JWT` / `vc+jwt` 等）は構造不正（3002）として拒否する（跨種混同対策）。署名検証に通った
 * うえでの不一致は改ざんではなく「別種の JWT を渡された」ことなので、署名不一致の 3010 は使わない
 * （SD-JWT VC の `typ` 混同と同じ規約）。`sub` と参照 `uri` の
 * 一致確認は confused deputy 対策で、別リストの Token を掴まされる攻撃を防ぐ。
 *
 * @param token コンパクト JWT 文字列。
 * @param uri 参照元の Status List URI（`sub` と一致しなければならない）。
 * @param issuerPublicKey Issuer の公開鍵 JWK。
 * @returns payload とビット列（`bits` / `lst`）。
 * @throws `alg=none` の場合 `ALG_NONE`（3011）。
 * @throws 署名不一致 / 未対応 alg / `sub` 不一致の場合 `SIG_INVALID`（3010）。
 * @throws `typ` が `statuslist+jwt` でない（欠落を含む）場合、および payload 構造が不正な場合
 *         （`sub` が文字列でない、`exp` があるのに NumericDate でない等）`VC_SCHEMA_INVALID`（3002）。
 */
export function verifyStatusListToken(
  token: string,
  uri: string,
  issuerPublicKey: PublicKeyJwk,
): VerifiedStatusListToken {
  const decoded = decodeCompactJws(token);
  const alg = decoded.header.alg;
  if (alg === 'none') {
    // 自明な攻撃（alg=none）は専用コードで拒否する。
    throw new VericertsError(ErrorCodes.ALG_NONE);
  }
  if (typeof alg !== 'string' || !SUPPORTED_CREDENTIAL_ALGS.has(alg)) {
    // 未対応 alg は署名検証不能のため署名不一致に正規化する。
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  // alg と鍵種別の不一致も署名不一致に正規化する。
  if (!verifyWithJwkOrFalse(alg as CredentialAlg, decoded, issuerPublicKey)) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  // 明示的型付け（RFC 8725 §3.11 / draft-ietf-oauth-status-list §5.1）: 同じ Issuer 鍵が署名した
  // 別種の JWT（`vc+jwt` 等）を Status List Token として受理しない。`alg=none` と同様 fail-closed。
  // 署名は上で検証済み（＝改ざんではなく、別種の JWT を渡された）ので、署名不一致の 3010 ではなく
  // 構造不正の 3002 で返す（SD-JWT VC の `typ` 混同 `sdjwt/typ.ts` と同じ規約・Go 実装と同じコード）。
  // 検査は payload を読む前に行うので、別種 JWT の payload を Status List として解釈することはない。
  if (ownProperty<unknown>(decoded.header, 'typ') !== STATUS_LIST_TOKEN_TYP) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  // payload の構造不正（3002）と sub 不一致（3010）は区別する。
  const { sub, bits, lst, expSeconds, iatSeconds, ttlSeconds } = extractPayload(decoded.payload);
  if (sub !== uri) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  return {
    payload: decoded.payload,
    bits,
    lst,
    iatSeconds,
    ...(expSeconds === undefined ? {} : { expSeconds }),
    ...(ttlSeconds === undefined ? {} : { ttlSeconds }),
  };
}

/** 展開済みバイト長とビット幅から収容エントリ数（容量）を求める。 */
function computeSize(byteLength: number, bits: StatusBits): number {
  return Math.floor((byteLength * 8) / bits);
}

/**
 * 検証済み Token の `lst` を展開し、インデックス `idx` のビット値を読み取る。
 *
 * @param verified `verifyStatusListToken` の戻り値。
 * @param idx 読み取るビットインデックス。
 * @returns ビット値（0 なら有効）。
 * @throws `idx` が Token の容量外の場合 `VC_SCHEMA_INVALID`（3002）。
 */
export async function readStatusBit(
  verified: VerifiedStatusListToken,
  idx: number,
): Promise<number> {
  const bytes = await decompressBitstring(verified.lst);
  const size = computeSize(bytes.length, verified.bits);
  const bitstring = StatusBitstring.fromBytes(bytes, size, verified.bits);
  if (idx >= bitstring.size) {
    // idx が token の容量外。リスト不整合のため構造不正として拒否する。
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return bitstring.get(idx);
}
