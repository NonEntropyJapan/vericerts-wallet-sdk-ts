/**
 * Status List Token（JWT）のペイロード構造と署名（再署名）。
 *
 * IETF draft-ietf-oauth-status-list 準拠。
 *
 * 本モジュールは「ビット列の状態管理」（`token-status-list.ts` の `StatusListManager`）から
 * 「Token の直列化・署名」を分離したもの。Status List Token は**状態が変わるたびに再発行**される
 * （失効指示 → 再署名 → 配信）ため、署名処理を独立させて再署名を単独でテスト・再利用できるようにする。
 *
 * 署名は credential ドメインと同じく `CredentialSigner`（`signer.ts`）で DI する（生 privateKey を
 * 渡さない）。`jose` は使わずコンパクト JWS を `issue.ts` と同方針で組み立てる。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URL・インデックス・ビット値・JWT を含めない。
 */

import { signCompactJws, signCompactJwsAsync } from '../credential/vc/compact-jws.js';
import {
  type AnyCredentialSigner,
  buildJwsHeader,
  type CredentialSigner,
} from '../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { isEpochSeconds } from '../primitives/option-guard.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { StatusBits } from './bitstring.js';

/** Status List Token の JWS ヘッダ `typ`（draft §5.1）。 */
export const STATUS_LIST_TOKEN_TYP = 'statuslist+jwt' as const;

/** Status List Token のペイロード（StatusListTokenPayload）。 */
export interface StatusListTokenPayload {
  /** Issuer 識別子。 */
  readonly iss: string;
  /** Status List URI（VC の `status.status_list.uri` と一致する）。 */
  readonly sub: string;
  /** 発行日時（エポック秒）。 */
  readonly iat: number;
  /** 有効期限（エポック秒、任意）。 */
  readonly exp?: number;
  /**
   * 再取得までキャッシュしてよい秒数（任意。draft-ietf-oauth-status-list の `ttl`）。
   *
   * 検証側（`createStatusListFreshness`）は「取得した Token を何秒まで新鮮とみなすか」の上限として
   * これを読む。出力しないと検証側は既定の年齢上限（24 時間）へフォールバックし、`exp` が十分先でも
   * 24 時間を過ぎた Token が `3024` で拒否される。
   */
  readonly ttl?: number;
  /** ビット列本体。 */
  readonly status_list: {
    /** エントリあたりのビット数（1 / 2 / 4 / 8）。 */
    readonly bits: StatusBits;
    /** `base64url(zlib(bitstring))`。 */
    readonly lst: string;
  };
}

/** `issueToken` / `signStatusListToken` のオプション。 */
export interface IssueTokenOptions {
  /** 発行時刻（エポック秒）。既定は現在時刻。テストの決定性のため注入可能。 */
  readonly iatSeconds?: number;
  /** 有効期限（エポック秒、任意）。`ttlSeconds` より優先される。 */
  readonly expSeconds?: number;
  /**
   * 発行時刻からの有効期間（秒、任意）。`exp = iat + ttlSeconds` と `ttl = ttlSeconds` を設定する。
   *
   * 失効反映 SLA に合わせて Token の寿命を短く保つための指定（例: 60 秒 SLA なら `ttlSeconds: 60`）。
   * `expSeconds` が指定されている場合はそちらが優先され、本項目は無視される（`ttl` も出力しない）。
   *
   * `ttl` クレームも出すのは、検証側の年齢上限が既定 24 時間であり、これを出さないと 24 時間超の
   * `ttlSeconds` で発行した Token を SDK 自身の既定 resolver が `exp` 内でも拒否するため。
   */
  readonly ttlSeconds?: number;
}

/** `signStatusListToken` の入力（ビット列の由来に依存しない Token 素材）。 */
export interface StatusListTokenInput {
  /** Issuer 識別子（`iss`）。 */
  readonly issuer: string;
  /** Status List URI（`sub`）。 */
  readonly uri: string;
  /** エントリあたりのビット数。 */
  readonly bits: StatusBits;
  /** `base64url(zlib(bitstring))`。 */
  readonly lst: string;
}

/** Token の寿命に関わるクレーム（`exp` / `ttl`）。設定しないものは undefined。 */
interface TokenLifetime {
  readonly exp: number | undefined;
  readonly ttl: number | undefined;
}

/**
 * `iat` とオプションから `exp`（エポック秒）と `ttl`（秒）を決める。
 *
 * `ttlSeconds` 指定時は `exp` と `ttl` の両方を出す。`ttl` は検証側が年齢上限として読むため、
 * 出さないと 24 時間超の Token が `exp` 内でも拒否される。`expSeconds` 優先時は
 * 寿命の起点が `iat` とは限らないため `ttl` を出さない（既定の年齢上限に委ねる）。
 */
function resolveLifetime(iat: number, opts: IssueTokenOptions): TokenLifetime {
  // 任意プロパティは自身のプロパティに限って読む。ここで決めた `exp` は
  // **署名済み Status List Token** に載るため、継承値を拾うと、これらを省略した正当な発行でも
  // 攻撃者が選んだ有効期限（無期限に近い値も可）で失効リストが署名される。
  const expSeconds = ownProperty<number>(opts, 'expSeconds');
  if (expSeconds !== undefined) {
    return { exp: expSeconds, ttl: undefined };
  }
  const ttlSeconds = ownProperty<number>(opts, 'ttlSeconds');
  if (ttlSeconds === undefined) {
    return { exp: undefined, ttl: undefined };
  }
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return { exp: iat + ttlSeconds, ttl: ttlSeconds };
}

/**
 * Status List Token のペイロードを組み立てる（同期版 / 非同期版で共有）。
 *
 * @param input issuer / uri / bits / lst。
 * @param opts iat / exp / ttl。
 * @returns `StatusListTokenPayload`。
 * @throws `ttlSeconds` が正の整数でない場合（VericertsError、code `3002`）。
 */
function buildStatusListTokenPayload(
  input: StatusListTokenInput,
  opts: IssueTokenOptions,
): StatusListTokenPayload {
  // `iatSeconds` も同様に own 限定で読む（署名済み Token の `iat` が攻撃者の時刻になる）。
  const iat = ownProperty<number>(opts, 'iatSeconds') ?? Math.floor(Date.now() / 1000);
  // 非有限・負値・文字列の `iat` は署名済み Token に `null` 等で載る。
  if (!isEpochSeconds(iat)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const { exp, ttl } = resolveLifetime(iat, opts);
  return {
    iss: input.issuer,
    sub: input.uri,
    iat,
    ...(exp !== undefined ? { exp } : {}),
    ...(ttl !== undefined ? { ttl } : {}),
    status_list: { bits: input.bits, lst: input.lst },
  };
}

/**
 * Status List Token（コンパクト JWS / JWT）を組み立てて署名する。
 *
 * header は `buildJwsHeader(signer, 'statuslist+jwt')`（draft §5.1。`signer.kid` 設定時は
 * `alg` と `typ` の間に `kid` を挿入する）、payload は `StatusListTokenPayload`。
 * **同じ入力でも呼ぶたびに新しい Token を生成する**ため、失効更新後の再署名にそのまま使える。
 *
 * KMS / HSM のような非同期署名が必要な場合は `signStatusListTokenAsync` を用いる。
 *
 * @param input issuer / uri / bits / lst。
 * @param signer Issuer の署名鍵（alg / publicKeyJwk / sign）。
 * @param opts iat / exp / ttl。
 * @returns コンパクト JWT 文字列（`header.payload.signature`）。
 * @throws `ttlSeconds` が正の整数でない場合（VericertsError、code `3002`）、
 *         signer による署名演算が失敗した場合（code `1020`）。
 */
export function signStatusListToken(
  input: StatusListTokenInput,
  signer: CredentialSigner,
  opts: IssueTokenOptions = {},
): string {
  const payload = buildStatusListTokenPayload(input, opts);
  return signCompactJws(buildJwsHeader(signer, STATUS_LIST_TOKEN_TYP), payload, signer);
}

/**
 * Status List Token を署名する（非同期署名対応版）。
 *
 * header / payload の組み立ては `signStatusListToken` と完全に同一で、署名だけを `await` する。
 * 同期の local signer（`createPrivateKeySigner`）と非同期の Remote Signer（`createRemoteSigner`。
 * KMS / HSM）のどちらも受け付けるため `AnyCredentialSigner` を取る。同期 signer を渡した場合の
 * 出力は `signStatusListToken` とバイト単位で一致する（後方互換）。
 *
 * @param input issuer / uri / bits / lst。
 * @param signer Issuer の署名鍵（同期 `CredentialSigner` / 非同期 `AsyncCredentialSigner`）。
 * @param opts iat / exp / ttl。
 * @returns コンパクト JWT 文字列（`header.payload.signature`）の Promise。
 * @throws `ttlSeconds` が正の整数でない場合（VericertsError、code `3002`）、
 *         signer による署名演算・外部署名呼び出しが失敗した場合（code `1020`）。
 */
export function signStatusListTokenAsync(
  input: StatusListTokenInput,
  signer: AnyCredentialSigner,
  opts: IssueTokenOptions = {},
): Promise<string> {
  const payload = buildStatusListTokenPayload(input, opts);
  return signCompactJwsAsync(buildJwsHeader(signer, STATUS_LIST_TOKEN_TYP), payload, signer);
}
