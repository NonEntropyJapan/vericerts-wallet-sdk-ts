/**
 * DPoP（RFC 9449）proof JWT の検証。
 *
 * RFC 9449 §4.3 の proof 検証と §6.1 の `cnf.jkt` 束縛を行う。鮮度窓の既定値は前後 30 秒。
 * MCP Gateway / A2A Gateway 等の Resource Server が DPoP-bound アクセストークンを検証するための
 * 汎用プリミティブとして提供する。
 *
 * スコープ境界:
 * - 本モジュールは単一 proof の構造・署名・HTTP 束縛・鮮度・`ath` / `jkt` 照合までを担う。
 * - **`jti` の一意性によるリプレイ検出は呼び出し側の責務**。
 *   検証結果として `jti` / `jkt` / `iat` を返すことでその実装を可能にする。
 * - HTTP 層（`DPoP` ヘッダの取り出し、`DPoP-Nonce` の発行）は本モジュールの責務外。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` にアクセストークン・
 * proof JWT・鍵素材・クレーム値を含めない。`ath` / `jkt` の照合はタイミングセーフな定数時間比較を
 * 用いる。
 */

import { assertFiniteClock } from '../../cache/system-clock.js';
import { decodeCompactJws } from '../../credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { jwkToUncompressedPublicKey } from '../../identity/jwt/jwk-key.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { timingSafeEqualString } from '../../timing-safe.js';
import {
  computeAth,
  computeJwkThumbprint,
  DPOP_JWT_TYP,
  type DpopAlg,
  type DpopProof,
  type DpopPublicKeyJwk,
  isDpopAlg,
  requireDpopAlgSpec,
  toDpopPublicKeyJwk,
} from './dpop-common.js';
import {
  assertAccessTokenKeyBinding,
  assertHttpBinding,
  type DpopAccessTokenBinding,
  type DpopFreshnessWindow,
  resolveDpopAccessTokenBinding,
  resolveDpopFreshnessWindow,
  type VerifyDpopProofOptions,
} from './dpop-verify-options.js';

/**
 * `ES256` / `ES256K` の JWS 署名バイト長。
 *
 * RFC 7515 §3.1 / RFC 7518 §3.4 は ECDSA の JWS 署名を、曲線位数のオクテット長へ左ゼロ埋めした
 * `R || S` の**固定長**と定めている（P-256 / secp256k1 はいずれも 32 バイト × 2）。
 */
export const DPOP_SIGNATURE_BYTE_LENGTH = 64;

/** 検証済み DPoP proof。呼び出し側の replay 検出（seen-nonces）に必要な値を返す。 */
export interface VerifiedDpopProof {
  /** proof の一意識別子。seen-nonces のキーとして使う。 */
  readonly jti: string;
  /** proof 公開鍵の RFC 7638 サムプリント。replay キー / 鍵束縛照合用。 */
  readonly jkt: string;
  /** proof 生成時刻（エポック秒）。seen-nonces の失効判定に使う。 */
  readonly iat: number;
  /** proof が束縛する HTTP メソッド。 */
  readonly htm: string;
  /** proof が束縛する HTTP target URI（正規化済み）。 */
  readonly htu: string;
  /** proof の署名アルゴリズム。 */
  readonly alg: DpopAlg;
  /** proof header の公開鍵 JWK（必須メンバのみへ正規化済み）。 */
  readonly publicKeyJwk: DpopPublicKeyJwk;
  /** `ath` クレーム（proof に含まれる場合のみ）。 */
  readonly ath?: string;
  /** `nonce` クレーム（proof に含まれる場合のみ）。 */
  readonly nonce?: string;
}

/**
 * クレーム値を非空文字列として取り出す。
 *
 * @param value 未検証のクレーム値。
 * @returns 非空文字列。
 * @throws 文字列でない / 空文字列の場合（VericertsError、code `4080`）。
 */
function requireNonEmptyString(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  return value;
}

/**
 * header の `alg` を対応済み DPoP アルゴリズムとして取り出す。
 *
 * 判定は DPoP 固有の許容集合 `DPOP_SUPPORTED_ALGS`（`ES256` / `ES256K`）のみで行う。共有レジストリ
 * `ALG_SPECS` のキー集合には委ねない — レジストリは他機能のために拡張され得る可変マップであり、
 * そこへ alg が追加されるだけで DPoP の受理範囲が暗黙に広がってしまうため。
 * 許容集合は列挙で閉じているので、`none` / `EdDSA` / `RS256` / `HS256` 等はもちろん、
 * `toString` / `constructor` / `__proto__` のような `Object.prototype` のメンバ名も拒否される
 * （`Set.has` はプロトタイプチェーンを参照しない）。RFC 9449 §4.3 step 4。
 *
 * @param value header の `alg` 値（未検証）。
 * @returns 対応済みの DPoP 署名アルゴリズム。
 * @throws 文字列でない / 未対応 alg の場合（VericertsError、code `4080`）。
 */
function requireDpopAlg(value: unknown): DpopAlg {
  if (!isDpopAlg(value)) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  return value;
}

/**
 * header の `jwk` をオブジェクトとして取り出す。
 *
 * EC 公開鍵としての妥当性（`kty` / `crv` / `x` / `y` と `d` の不在）は `toDpopPublicKeyJwk` が
 * 担うため、ここでは非 null・非配列のオブジェクトであることのみを確認する。
 *
 * @param value header の `jwk` 値（未検証）。
 * @returns JWK として解釈するオブジェクト。
 * @throws `jwk` が欠落・非オブジェクト・配列の場合（VericertsError、code `4080`）。
 */
function requireJwkObject(value: unknown): Readonly<Record<string, unknown>> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  return value as Readonly<Record<string, unknown>>;
}

/**
 * `iat` クレームの鮮度を評価する（RFC 9449 §4.3 step 10）。
 *
 * 窓は `resolveDpopFreshnessWindow` が解決済み（キャップ検査後）の値を受け取る。ここで再度
 * 既定値へフォールバックしないのは、検査を迂回した値が入り込む経路を作らないため。
 *
 * @param iat proof の生成時刻（エポック秒）。
 * @param now 現在時刻（エポック秒）。
 * @param window 実効の鮮度窓（`clockSkewSeconds` / `maxAgeSeconds`）。
 * @throws 未来方向にスキュー超過、または経過秒数が上限超過の場合（VericertsError、code `4082`）。
 */
function assertFreshIat(iat: number, now: number, window: DpopFreshnessWindow): void {
  // `now` が NaN だと下の比較が常に false になり期限切れ・未来 iat の proof を通す（fail-open）。
  assertFiniteClock(now);
  if (iat > now + window.clockSkewSeconds || now - iat > window.maxAgeSeconds) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_EXPIRED);
  }
}

/**
 * DPoP proof JWT を検証する（RFC 9449 §4.3）。
 *
 * 検証順序と失敗時のエラーコード:
 * 1. コンパクト JWS としてデコード可能（code `4080`）。
 * 2. header `typ` が `dpop+jwt`（code `4080`）。
 * 3. header `alg` が DPoP 許容集合（`ES256` / `ES256K`）に含まれる（`none` / `EdDSA` 等の未対応
 *    alg は拒否、code `4080`）。
 * 4. header `jwk` が EC 公開鍵（`crv` が `alg` に対応し `x` / `y` が 32 バイトへ base64url
 *    デコード可能、秘密鍵メンバ `d` を含むものは拒否、code `4080`）。
 * 5. 署名長が厳密に `DPOP_SIGNATURE_BYTE_LENGTH`（64）バイトで、`jwk` による署名検証に成功する
 *    （code `4081`）。
 * 6. `jti` / `htm` / `htu` / `iat` の型（code `4080`）。
 * 7. `htm` の一致（code `4083`）。
 * 8. `htu` の一致（正規化後、code `4083`）。
 * 9. `nonce` の一致（`options.nonce` 指定時のみ。欠落・不一致とも code `4086`）。
 * 10. `iat` の鮮度（code `4082`）。
 * 11. `ath` の一致（`options.accessToken` 指定時のみ、code `4084`）。
 * 12. `cnf.jkt` の一致（`options.expectedJkt` 指定時。`accessToken` 指定時は省略不可、code `4085`）。
 *
 * step 12 は `accessToken` を指定した場合に必須である（RFC 9449 §4.3 step 12）。`expectedJkt` の
 * 併記は `VerifyDpopProofOptions` が型で強制し、型を迂回した呼び出しは
 * `assertAccessTokenKeyBinding` がランタイムで拒否する（code `4085`）。**このランタイム判定は上記
 * ステップ表の前提条件として step 1 のデコードより前に評価される**。
 * `expectedJkt` の欠落は proof の不備ではなく呼び出し側の設定ミスなので、暗号処理
 * を始める前に fail-fast で弾く。そのため「`accessToken` 指定 + `expectedJkt` 未指定 + 形式不正な
 * proof」に対しては 4080 ではなく 4085 を返す。
 *
 * `jti` の一意性（リプレイ検出）は本関数では判定しない。戻り値の `jti` / `jkt` / `iat` を用いて
 * 呼び出し側が seen-nonces で判定する。
 *
 * @param proof DPoP proof JWT（コンパクト JWS 直列化された `DpopProof` = 文字列）。
 * @param options 検証条件。`accessToken` 指定時は `expectedJkt` も必須。
 * @returns 検証済み proof の要約。
 * @throws `clockSkewSeconds` / `maxAgeSeconds` がキャップ超過・非負整数でない（code `4015`）／
 *         形式不正（code `4080`）／署名不正・署名長不正（code `4081`）／期限切れ（code `4082`）／
 *         HTTP 束縛不一致（code `4083`）／`ath` 不一致（code `4084`）／
 *         鍵束縛不一致・`expectedJkt` 欠落（code `4085`）／`nonce` 欠落・不一致（code `4086`）の
 *         場合（いずれも VericertsError）。
 */
export function verifyDpopProof(
  proof: DpopProof,
  options: VerifyDpopProofOptions,
): VerifiedDpopProof {
  assertAccessTokenKeyBinding(options);
  // 鮮度オプションのキャップ検査も呼び出し側の設定ミスなので、`expectedJkt` 欠落と同じく
  // デコード・署名検証より前に fail-fast で弾く。
  const freshness = resolveDpopFreshnessWindow(options);
  // 束縛値も own 限定で確定させる。`htm` / `htu` / `nonce` の照合値は
  // `assertHttpBinding` が同じ規則で読む。
  const tokenBinding: DpopAccessTokenBinding = resolveDpopAccessTokenBinding(options);
  let decoded: ReturnType<typeof decodeCompactJws>;
  try {
    decoded = decodeCompactJws(proof);
  } catch {
    // decodeCompactJws は code 2001 を投げるため、DPoP 固有の形式不正へ正規化する
    // （proof 本文を含み得るため cause は渡さない）。
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  // header / payload は `decodeCompactJws`（`credential/vc/jws.ts`）→ `identity/jwt/jwt-codec.ts` の
  // `parseJson` → `parse-json.ts` の `parseJsonWithoutPrototype` を通るため **`null` プロトタイプ**
  // である。own 限定で読むのはその手法と**重畳する
  // 多層防御**で、鎖読みへ戻すとパース境界を通らない値の流入時に**そのクレームを持たない proof**
  // が汚染値を持つものとして通る（`typ` 無しの JWT が `dpop+jwt` とみなされる、`ath` を持たない
  // proof が盗んだアクセストークンの `ath` と一致する、`nonce` 無しの proof が nonce 照合を通る 等）。
  // proof は外部入力そのものなので、クレームは必ず own プロパティとして読む。
  if (ownProperty<unknown>(decoded.header, 'typ') !== DPOP_JWT_TYP) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  const alg = requireDpopAlg(ownProperty(decoded.header, 'alg'));
  const headerJwk = requireJwkObject(ownProperty(decoded.header, 'jwk'));
  const publicKeyJwk = toDpopPublicKeyJwk(headerJwk, alg);

  const spec = requireDpopAlgSpec(alg);
  // `kty` / `crv` の alg 束縛は 2 行上の `toDpopPublicKeyJwk(headerJwk, alg)` が済ませている
  // （不一致なら 4080 で送出済み）。ここは座標のみを見れば足りるため `expectedCrv: null` を明示する。
  const publicKey = jwkToUncompressedPublicKey(headerJwk, {
    expectedCrv: null,
    errorCode: ErrorCodes.DPOP_SIGNATURE_INVALID,
  });
  // 署名は固定長 R||S（RFC 7515 §3.1）。長さを見ないと、末尾に 1 バイト付けた 65 バイト署名
  // （recovery 付きとみなされ先頭 64B へ切り詰められる）や DER 再エンコードが通り、同一クレーム・
  // 同一 jti に対して無数の有効な proof 文字列が作れてしまう（proof 文字列を重複判定キーに使う
  // 呼び出し側のリプレイ検出を回避できる）。
  if (decoded.signature.length !== DPOP_SIGNATURE_BYTE_LENGTH) {
    throw new VericertsError(ErrorCodes.DPOP_SIGNATURE_INVALID);
  }
  // `AlgSpec.verify` は signing-input を受け取り、ECDSA の事前ハッシュは spec 側が行う。
  // ここで `decoded.digest` を渡すと二重ハッシュになり、正当な proof が 4081 で落ちる。
  // ES256 の high-S は受理しない（`allowHighS: false` を明示して low-S 強制）。他の JWS 検証経路の既定は
  // high-S 受理だが、呼び出し側が proof 文字列を重複判定キーに使うと、`s` と `n - s` の 2 通りが
  // 同一 jti に対して有効になり回避されるため（上の署名長検査と同じ理由）。
  if (!spec.verify(decoded.signingInput, decoded.signature, publicKey, false)) {
    throw new VericertsError(ErrorCodes.DPOP_SIGNATURE_INVALID);
  }

  const { payload } = decoded;
  const jti = requireNonEmptyString(ownProperty(payload, 'jti'));
  const htm = requireNonEmptyString(ownProperty(payload, 'htm'));
  const rawHtu = requireNonEmptyString(ownProperty(payload, 'htu'));
  const iat = ownProperty<unknown>(payload, 'iat');
  if (typeof iat !== 'number' || !Number.isInteger(iat)) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  const nonce = ownProperty<unknown>(payload, 'nonce');
  const htu = assertHttpBinding(
    { htm, htu: rawHtu, ...(typeof nonce === 'string' ? { nonce } : {}) },
    options,
  );
  // 任意オプションは自身のプロパティに限って読む。継承した `nowSeconds` は
  // DPoP proof の `iat` を攻撃者が選んだ「現在時刻」で評価させ、古い proof のリプレイを通す。
  assertFreshIat(
    iat,
    ownProperty<number>(options, 'nowSeconds') ?? Math.floor(Date.now() / 1000),
    freshness,
  );

  const rawAth = ownProperty<unknown>(payload, 'ath');
  const ath = typeof rawAth === 'string' ? rawAth : undefined;
  if (tokenBinding.accessToken !== undefined) {
    if (ath === undefined || !timingSafeEqualString(ath, computeAth(tokenBinding.accessToken))) {
      throw new VericertsError(ErrorCodes.DPOP_ATH_MISMATCH);
    }
  }
  const jkt = computeJwkThumbprint(headerJwk, alg);
  if (
    tokenBinding.expectedJkt !== undefined &&
    !timingSafeEqualString(jkt, tokenBinding.expectedJkt)
  ) {
    throw new VericertsError(ErrorCodes.DPOP_KEY_BINDING_MISMATCH);
  }

  return {
    jti,
    jkt,
    iat,
    htm,
    htu,
    alg,
    publicKeyJwk,
    ...(ath === undefined ? {} : { ath }),
    ...(typeof nonce === 'string' ? { nonce } : {}),
  };
}
