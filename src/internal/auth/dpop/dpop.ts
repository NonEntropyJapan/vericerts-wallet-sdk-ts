/**
 * DPoP（RFC 9449）proof JWT の生成とアクセストークンの鍵束縛。
 *
 * RFC 9449 §4.2 の構造の proof JWT を生成し、§6.1 の `cnf.jkt` でアクセストークンを鍵に束縛する。
 * 提供機能:
 * - `createDpopProof`: `htm` / `htu` / `iat` / `jti` と任意の `ath` / `nonce` を持つ proof JWT を生成
 * - `bindAccessTokenToDpopKey`: アクセストークン payload に `cnf.jkt`（RFC 7638 サムプリント）を付与
 *
 * スコープ境界:
 * - コンパクト JWS 直列化は `credential/vc/compact-jws.ts` の `signCompactJws` に委譲する。
 * - 検証は `dpop-verify.ts`、`jti` の一意性管理（リプレイ検出）は呼び出し側の責務。
 * - HTTP 送信・`DPoP-Nonce` ヘッダの往復は本モジュールの責務外（`nonce` は引数で受け取る）。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` にアクセストークン・
 * proof JWT・鍵素材・クレーム値を含めない。署名鍵は `CredentialSigner` 経由で DI し、本モジュールは
 * privateKey を保持しない。
 */

import { signCompactJws } from '../../credential/vc/compact-jws.js';
import type { CredentialSigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isEpochSeconds } from '../../primitives/option-guard.js';
import { resolveProofJti } from '../../primitives/proof-jti.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import {
  computeAth,
  computeJwkThumbprint,
  DPOP_JWT_TYP,
  type DpopAlg,
  type DpopProof,
  isDpopAlg,
  normalizeHtu,
  toDpopPublicKeyJwk,
} from './dpop-common.js';

/** `createDpopProof` の入力（RFC 9449 §4.2 のクレームに対応）。 */
export interface CreateDpopProofOptions {
  /** HTTP メソッド。大文字のトークン（例 `'POST'`）で指定する。 */
  readonly htm: string;
  /** HTTP target URI。クエリ・フラグメントは `htu` 生成時に除去される。 */
  readonly htu: string;
  /** 指定時のみ `ath` クレーム（アクセストークンの SHA-256）を付与する。 */
  readonly accessToken?: string;
  /** AS / RS が発行した DPoP-Nonce（RFC 9449 §8）。指定時のみ `nonce` クレームを付与する。 */
  readonly nonce?: string;
  /**
   * proof の一意識別子。UUIDv4（ハイフンなし 32 文字 / 正準形 36 文字）でなければ `4013` で拒否する。
   * 省略時は `crypto.randomUUID()` で生成する。
   */
  readonly jti?: string;
  /** 現在時刻（エポック秒）。省略時は `Math.floor(Date.now() / 1000)`。 */
  readonly nowSeconds?: number;
}

/** DPoP proof JWT の payload（RFC 9449 §4.2）。 */
interface DpopProofClaims {
  /** proof の一意識別子（リプレイ検出キー）。 */
  readonly jti: string;
  /** 対象リクエストの HTTP メソッド。 */
  readonly htm: string;
  /** 対象リクエストの正規化済み HTTP target URI。 */
  readonly htu: string;
  /** proof 生成時刻（エポック秒）。 */
  readonly iat: number;
  /** アクセストークンの SHA-256（束縛時のみ）。 */
  readonly ath?: string;
  /** AS / RS が発行した DPoP-Nonce（要求された場合のみ）。 */
  readonly nonce?: string;
}

/**
 * DPoP proof JWT（コンパクト JWS）を生成する。
 *
 * header は `{ typ: 'dpop+jwt', alg, jwk }` で、`jwk` は `toDpopPublicKeyJwk` により
 * `{kty, crv, x, y}` のみへ正規化される（秘密鍵メンバ `d` や余分なメンバは載らない）。
 * payload は `{ jti, htm, htu, iat }` に加え、`accessToken` 指定時のみ `ath`、`nonce` 指定時のみ
 * `nonce` を含む（未指定のクレームはキー自体を出力しない）。
 *
 * `htu` は `normalizeHtu` でクエリ・フラグメントを除去して正規化する。パースできない `htu` からは
 * RFC 9449 §4.2 に適合した proof を組み立てられないため、生成を中止して形式不正とする。
 *
 * @param options `htm` / `htu` と任意の `accessToken` / `nonce` / `jti` / `nowSeconds`。
 * @param signer DPoP 鍵の署名抽象（`publicKeyJwk` が proof header の `jwk` になる）。
 * @returns DPoP proof JWT（コンパクト JWS 直列化された `DpopProof` = 文字列）。
 * @throws `htm` が空文字列、`htu` がパース不能、`signer.alg` が `DpopAlg`（`ES256` / `ES256K`）
 *         以外、または `signer.publicKeyJwk` が EC 公開鍵として不正な場合
 *         （VericertsError、code `4080`）。`jti` を指定し、それが UUIDv4（ハイフンなし 32 文字 /
 *         正準形 36 文字）でない場合（VericertsError、code `4013`）。
 */
export function createDpopProof(
  options: CreateDpopProofOptions,
  signer: CredentialSigner,
): DpopProof {
  // 検査と署名で**同じ own 値**を使う。従来は検査が鎖読み・署名が own 読みで
  // 食い違っており、`htm` を持たない proof が 4080 を素通りしたうえで署名されていた。
  // `htu` も同様に、汚染値がそのまま署名済み proof に載る。
  const htm = ownProperty<string>(options, 'htm');
  if (typeof htm !== 'string' || htm.length === 0) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  const rawHtu = ownProperty<string>(options, 'htu');
  const htu = typeof rawHtu === 'string' ? normalizeHtu(rawHtu) : undefined;
  if (htu === undefined) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  // `CredentialSigner.alg` は DPoP より広い（`EdDSA` を含む）。DPoP が受理する alg は
  // DPoP 用の公開鍵に対応する署名アルゴリズムに限定する。
  if (!isDpopAlg(signer.alg)) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  const header = {
    typ: DPOP_JWT_TYP,
    alg: signer.alg,
    jwk: toDpopPublicKeyJwk(signer.publicKeyJwk, signer.alg),
  };
  // 任意プロパティは自身のプロパティに限って読む。ここで組み立てた claims は
  // そのまま署名されるため、継承値を拾うと、その項目を**省略した**正当な生成でも汚染値が
  // **署名済み DPoP proof** に載る。特に `jti` は継承値だと proof ごとに同じ値へ固定され、
  // サーバ側の jti ベースのリプレイ検知が「毎回同じ proof」を見分けられなくなる
  // （＝ ランダム UUID による一意性が失われる）。`nowSeconds` は `iat` を、`nonce` /
  // `accessToken` はサーバ側のバインド対象を攻撃者の値にする。
  // 指定された `jti` は UUIDv4（32〜36 文字）だけ通す。
  // 固定値・空文字の `jti` を署名すると、サーバ側の jti ベースのリプレイ検知が成立しない。
  const jti = resolveProofJti(ownProperty(options, 'jti'));
  const attackerNonce = ownProperty<string>(options, 'nonce');
  const accessToken = ownProperty<string>(options, 'accessToken');
  const iat = ownProperty<number>(options, 'nowSeconds') ?? Math.floor(Date.now() / 1000);
  // 非有限・負値・文字列の `iat` は JWT に `null` 等で載り、サーバ側の鮮度判定が成立しない。
  if (!isEpochSeconds(iat)) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  const claims: DpopProofClaims = {
    jti,
    htm,
    htu,
    iat,
    // 未指定時はキーごと省く（JSON.stringify は undefined 値のキーを出力しない）。
    ...(accessToken === undefined ? {} : { ath: computeAth(accessToken) }),
    ...(attackerNonce === undefined ? {} : { nonce: attackerNonce }),
  };
  return signCompactJws(header, claims, signer);
}

/**
 * アクセストークン payload を DPoP 公開鍵へ束縛する（RFC 9449 §6.1）。
 *
 * `cnf.jkt` に RFC 7638 サムプリントを設定した**新しいオブジェクト**を返す。入力 `tokenPayload` は
 * 変更しない。既存の `cnf` がオブジェクトの場合はそのメンバを保持したまま `jkt` を追加する
 * （`cnf` がオブジェクト以外の場合は `jkt` のみの `cnf` で置き換える）。
 *
 * @param tokenPayload 束縛対象のアクセストークン payload。
 * @param jwk DPoP 公開鍵 JWK。
 * @param alg DPoP 鍵の署名アルゴリズム。
 * @returns `cnf.jkt` を持つ新しい payload。
 * @throws `jwk` が EC 公開鍵として不正な場合（VericertsError、code `4080`）。
 */
export function bindAccessTokenToDpopKey<T extends object>(
  tokenPayload: T,
  jwk: Readonly<Record<string, unknown>>,
  alg: DpopAlg,
): T & { readonly cnf: { readonly jkt: string } } {
  const jkt = computeJwkThumbprint(jwk, alg);
  // own 限定で読む。プロパティアクセスでプロトタイプ鎖を辿ると、
  // `Object.prototype.cnf` が汚染された環境では `cnf` を own で持たない正当な tokenPayload でも
  // 継承値を拾い、その余分なメンバが `{ ...baseCnf, jkt }` 経由で署名対象の `cnf` に紛れ込む
  // （`createDpopProof` と同じ規約。`own-property.ts` 参照）。
  const existing = ownProperty<unknown>(tokenPayload, 'cnf');
  const baseCnf =
    typeof existing === 'object' && existing !== null && !Array.isArray(existing)
      ? (existing as Record<string, unknown>)
      : {};
  return { ...tokenPayload, cnf: { ...baseCnf, jkt } };
}
