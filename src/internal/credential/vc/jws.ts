/**
 * JWT-VC 用のコンパクト JWS プリミティブ（署名・検証ヘルパ）。
 *
 * 既存の `identity/jwt/jwt-codec.ts` のデコードヘルパ・`identity/jwt/jwk-key.ts` の alg 仕様表を
 * 再利用し、`jose` 等の JWT ライブラリは導入しない。コンパクト JWS（`header.payload.signature`）の
 * 組み立ては署名鍵抽象を持つ `issue.ts` が担い、本モジュールは VC 用のデコード（`decodeCompactJws`）・
 * ヘッダ `alg` 検証（`assertAlg`）・署名検証（`verifyWithJwk` / `verifyWithJwkOrFalse`）を提供する。
 *
 * 対応署名アルゴリズム（header.alg）:
 *
 * | alg     | kty | 曲線      | 署名 / 検証                                   |
 * | ------- | --- | --------- | --------------------------------------------- |
 * | `ES256` | EC  | P-256     | `signP256` / `verifyP256`                     |
 * | `ES256K`| EC  | secp256k1 | `signSecp256k1Recoverable` / `verifySecp256k1` |
 * | `EdDSA` | OKP | Ed25519   | `signEd25519` / `verifyEd25519`               |
 *
 * ECDSA（`ES256` / `ES256K`）は signing-input（`base64url(header).base64url(payload)`）の SHA-256
 * digest に対して署名・検証する。`EdDSA`（PureEdDSA / RFC 8032）は事前ハッシュを行わず、
 * signing-input そのものに対して署名・検証する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に privateKey・VC 本文・JWT を含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { ALG_SPECS, jwkToVerificationKey } from '../../identity/jwt/jwk-key.js';
import {
  assertNoCriticalHeaders,
  base64urlDecode,
  parseJson,
} from '../../identity/jwt/jwt-codec.js';
import { ES256K_R_ALG, verifyEip191Address } from '../../keymanager/eip191.js';
import type { CredentialAlg, CredentialSignerAlg } from '../../keymanager/jws/signer-types.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';

/**
 * JWT-VC が対応する IANA 登録済みの JWS 署名アルゴリズム（`ES256` / `ES256K` / `EdDSA`）。`CredentialSignerAlg` は標準外の `ES256K-R` を加える。
 *
 * 実体は Foundation の `keymanager/jws/signer-types.ts`（`keymanager` 側も同じ型を必要とするため）。
 * ここでは互換のため再エクスポートする。
 */
export type { CredentialAlg, CredentialSignerAlg } from '../../keymanager/jws/signer-types.js';

/**
 * 対応 JWS 署名アルゴリズムの許可リスト（全 JWS 検証経路で共有する単一の SSOT）。
 *
 * `verify.ts` / `sdjwt/verify.ts` / `presentation.ts` / `wua.ts` / `federation/statement/statement.ts` /
 * `status-list-resolver.ts` が本セットを参照する。`alg=none` の拒否は各呼び出し側の責務
 * （エラーコードが経路ごとに異なるため）。
 */
export const SUPPORTED_CREDENTIAL_ALGS: ReadonlySet<string> = new Set<CredentialAlg>([
  'ES256',
  'ES256K',
  'EdDSA',
]);

/**
 * JWS ヘッダの `alg` を検証し、`alg=none` および未対応 alg を拒否する。
 *
 * `presentation-signature.ts`（JWT-VP）・`sdjwt/verify.ts`（Issuer-signed JWT）・`vc/verify.ts`
 * （JWT-VC）の 3 経路が共有する単一の検証ロジック（重複実装の統合）。
 *
 * `header` はいずれの経路でも `decodeCompactJws` → `identity/jwt/jwt-codec.ts` の `parseJson` →
 * `parse-json.ts` の `parseJsonWithoutPrototype` を通って届くため **`null` プロトタイプ**である。own 限定
 * 読みはそれと**重畳する多層防御**で、鎖読みへ戻すと **`alg` を持たないヘッダでも
 * `Object.prototype.alg` の汚染値が「ヘッダに入っていた alg」として採用され**、本来 3010 で
 * 閉じるはずの検証が続行される（汚染値が `'none'` なら 3011 へ、対応 alg なら鍵種別の一致次第で
 * 署名検証まで進む）。
 *
 * @param header デコード済み JWS ヘッダ。
 * @param opts `allowEs256kR`: `ES256K-R`（IANA 登録外。did:pkh / did:ethr の controller 鍵用の標準外の例外）を
 *        受理するか。既定 `false`。自分の DID の署名を検証する経路（JWT-VC / JWT-VP / SIOPv2 id_token / `did_signMessage`）だけが
 *        `true` を渡す。SD-JWT・Status List・Federation・WUA など発行者・事業者の署名の経路は受理しない。
 * @returns 検証済みの `alg`（`ES256` / `ES256K` / `EdDSA`、`allowEs256kR` のとき `ES256K-R` も）。
 * @throws `alg=none` の場合（VericertsError、code `3011`）。未対応 alg・型不正の場合（code
 *   `3010`。署名検証不能のため検証失敗に正規化する）。
 */
export function assertAlg(header: Record<string, unknown>): CredentialAlg;
export function assertAlg(
  header: Record<string, unknown>,
  opts: { readonly allowEs256kR: true },
): CredentialSignerAlg;
export function assertAlg(
  header: Record<string, unknown>,
  opts: { readonly allowEs256kR?: boolean } = {},
): CredentialSignerAlg {
  const alg = ownProperty<unknown>(header, 'alg');
  if (alg === 'none') {
    throw new VericertsError(ErrorCodes.ALG_NONE);
  }
  const allowEs256kR = ownProperty<boolean>(opts, 'allowEs256kR') === true;
  if (
    typeof alg !== 'string' ||
    !(SUPPORTED_CREDENTIAL_ALGS.has(alg) || (allowEs256kR && alg === ES256K_R_ALG))
  ) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  return alg as CredentialSignerAlg;
}

/** デコード済みコンパクト JWS の構成要素。 */
export interface DecodedJws {
  /** デコード済み JWS ヘッダ。 */
  readonly header: Record<string, unknown>;
  /** デコード済み JWS ペイロード。 */
  readonly payload: Record<string, unknown>;
  /**
   * signing-input（`header.payload`）の SHA-256 digest（32B）。
   *
   * ECDSA（`ES256` / `ES256K`）の事前ハッシュ。digest ベースの検証コールバック
   * （`CredentialVerifierKey.verify` 等）に渡すために保持する。`EdDSA` の検証には使えない。
   */
  readonly digest: Uint8Array;
  /**
   * signing-input（`header.payload`）の UTF-8 バイト列。
   *
   * `EdDSA` が実際に署名する対象。`ES256` / `ES256K` でもここから `digest` を導出する。
   */
  readonly signingInput: Uint8Array;
  /** raw 署名バイト列。 */
  readonly signature: Uint8Array;
}

/**
 * コンパクト JWS（`header.payload.signature`）をデコードする。
 *
 * 検証は呼び出し側（`verify.ts`）が行う。ここでは形式分解と base64url / JSON デコードのみを行う。
 *
 * @param jws コンパクト JWS 文字列。
 * @returns ヘッダ・ペイロード・signing-input・digest・署名。
 * @throws 3 セグメントでない / base64url・JSON として不正な場合（VericertsError、code `2001`）。
 */
export function decodeCompactJws(jws: string): DecodedJws {
  const parts = jws.split('.');
  const [headerSeg, payloadSeg, signatureSeg] = parts;
  if (parts.length !== 3 || !headerSeg || !payloadSeg || !signatureSeg) {
    // 入力（JWT 本文）はメッセージに含めず形式不正へ正規化する。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const header = parseJson(base64urlDecode(headerSeg));
  assertNoCriticalHeaders(header);
  const payload = parseJson(base64urlDecode(payloadSeg));
  const signature = base64urlDecode(signatureSeg);
  const signingInput = new TextEncoder().encode(`${headerSeg}.${payloadSeg}`);
  const digest = sha256(signingInput);
  return { header, payload, digest, signingInput, signature };
}

/**
 * コンパクト JWS をデコードし、構造不正を呼び出し側の失敗面のコードへ正規化する。
 *
 * `decodeCompactJws` は構造不正に `2001 INVALID_DID` を投げるが、これは **DID 解決の失敗**を表す
 * コードである。
 * 検証 API がこれをそのまま漏らすと、呼び出し側に「DID が不正」と誤解させる。VC / VP / SD-JWT の
 * 検証 API の失敗面は 30xx 系で定義されているため、各経路の契約内コードへ寄せる。
 *
 * @param jws コンパクト JWS 文字列。
 * @param code 構造不正時に送出するエラーコード（呼び出し側の失敗面に合わせる）。
 * @returns デコード済み JWS。
 * @throws 構造不正の場合（VericertsError、`code`）。
 */
export function decodeCompactJwsOrThrow(jws: string, code: ErrorCode): DecodedJws {
  try {
    return decodeCompactJws(jws);
  } catch {
    // 入力（JWT 本文）は例外に載せない。cause も渡さない。
    throw new VericertsError(code);
  }
}

/**
 * JWS ヘッダの `alg` と JWK 公開鍵から署名を検証する。
 *
 * `ALG_SPECS` から alg に対応する検証仕様を引き、`jwkToVerificationKey` で alg が要求する鍵種別
 * （`ES256` / `ES256K` は EC、`EdDSA` は OKP/Ed25519）に厳密に束縛して公開鍵を取り出したうえで、
 * signing-input と署名を突き合わせる。ECDSA の SHA-256 事前ハッシュを行うかは alg 仕様側の責務。
 * alg=none の拒否や exp/nbf 評価は呼び出し側（`verify.ts` 等）の責務とする。
 *
 * @param alg JWS ヘッダの `alg`（`ES256` / `ES256K` / `EdDSA`）。
 * @param decoded デコード済み JWS（signing-input と raw 署名を使う）。
 * @param jwk 発行者の公開鍵 JWK（EC または OKP）。
 * @returns 署名が有効なら `true`、無効なら `false`。
 * @throws JWK が alg の要求する kty / crv と一致しない・形状不正の場合（VericertsError、code `2001`）。
 */
export function verifyWithJwk(
  alg: CredentialAlg,
  decoded: Pick<DecodedJws, 'signingInput' | 'signature'>,
  jwk: PublicKeyJwk,
): boolean {
  const spec = ALG_SPECS[alg];
  if (spec === undefined) {
    return false;
  }
  const publicKey = jwkToVerificationKey(jwk, spec);
  // ES256 の high-S は `ALG_SPECS` の既定どおり受理する（RFC 7518）。ES256K は
  // spec 側で常に low-S のみ。
  return spec.verify(decoded.signingInput, decoded.signature, publicKey);
}

/**
 * `verifyWithJwk` を呼び出し、鍵解決時の `VericertsError` を「検証失敗」（`false`）へ正規化する。
 *
 * なぜ必要か:
 * `verifyWithJwk` は alg ↔ kty / crv の束縛違反（例: ヘッダ `alg: EdDSA` に対し EC 鍵）を
 * `jwkToVerificationKey` 経由で `INVALID_DID`（2001）として投げる。しかしこれは
 * 「DID 文字列の形式が不正」ではなく「その鍵ではこの署名を検証できない」＝署名検証の失敗であり、
 * 2001 が VC / VP 検証 API の外へ漏れると、失敗面を 30xx 系で定義している各 API の
 * エラーコード契約に反する。header の `alg` は攻撃者が自由に指定できるため、この不一致は
 * 恒常的に到達可能である。本関数で `false` に畳み込み、呼び出し側が自経路のコード
 * （3010 / 3012 / TRUST_CHAIN_INVALID 等）で拒否できるようにする。
 *
 * fail-closed 特性:
 * 例外を握りつぶす方向は常に「検証失敗」であり、`true` を返す経路は
 * `verifyWithJwk` が実際に署名検証に成功した場合のみ。したがって署名バイパスは生じない。
 * `VericertsError` 以外の想定外例外は握りつぶさず再送出する。
 *
 * @param alg JWS ヘッダの `alg`（`ES256` / `ES256K` / `EdDSA`）。
 * @param decoded デコード済み JWS（signing-input と raw 署名を使う）。
 * @param jwk 検証鍵 JWK（EC または OKP）。
 * @returns 署名が有効なら `true`。署名不一致・alg と鍵種別の不一致・JWK 形状不正なら `false`。
 */
export function verifyWithJwkOrFalse(
  alg: CredentialAlg,
  decoded: Pick<DecodedJws, 'signingInput' | 'signature'>,
  jwk: PublicKeyJwk,
): boolean {
  try {
    return verifyWithJwk(alg, decoded, jwk);
  } catch (error) {
    if (error instanceof VericertsError) {
      // 鍵解決失敗は検証失敗として扱う。入力を含み得るため error は伝播させない。
      return false;
    }
    throw error;
  }
}

/**
 * `verifyWithKey` が受け取る検証鍵（`CredentialVerifierKey` / `PresentationVerifierKey` の共通形）。
 *
 * `ethereumAddress` は `alg: "ES256K-R"` 専用（did:pkh / did:ethr の controller 鍵。検証メソッドが公開鍵を持たず
 * Ethereum アドレスだけを持つ）。`ES256K-R` はこの鍵でしか検証せず、ほかの alg はこの鍵を使わない。
 */
export interface JwsVerifierKey {
  readonly publicKeyJwk?: PublicKeyJwk;
  readonly ethereumAddress?: string;
  readonly verify?: (
    digest: Uint8Array,
    signature: Uint8Array,
    signingInput: Uint8Array,
  ) => boolean;
}

/**
 * DI された検証鍵（公開鍵 JWK or 検証関数）でデコード済み JWS の署名を検証する（JWT-VC / JWT-VP 共通）。
 *
 * - `publicKeyJwk` / `verify` は `nonObjectPrototypeProperty` で読む。`key` はクラスインスタンスも
 *   取り得る（KMS / HSM ラッパ）ため own 限定にはできないが、`Object.prototype` 由来の汚染値は
 *   「未指定」とみなす。
 * - `verify` は `key` をレシーバにして呼ぶ（インスタンス状態を参照する鍵のため）。
 * - 戻り値は**厳密に `true` のときだけ**成功とする。HSM / WebCrypto 向けの `async` 検証関数が返す
 *   `Promise`（thenable）や `'yes'` / `1` のような非 boolean 真値は同期 API では検証不能であり、
 *   truthiness で判定すると署名が不正でも通る（fail-open）ため `false` に倒す。
 * - 検証手段がどちらも無い鍵は `false`（fail-closed）。
 *
 * @returns 署名が有効なら `true`。それ以外は `false`。
 */
export function verifyWithKey(
  alg: CredentialSignerAlg,
  decoded: Pick<DecodedJws, 'digest' | 'signature' | 'signingInput'>,
  key: JwsVerifierKey,
): boolean {
  if (alg === ES256K_R_ALG) {
    // 標準外の alg（IANA 登録外）は、アドレス鍵（EIP-191 の署名から復元した鍵のアドレスと照合）だけで検証する。公開鍵 JWK や
    // 検証関数 DI では検証しない（署名者が「公開鍵を持つ鍵」を ES256K-R で名乗る経路を作らない）。
    const address = nonObjectPrototypeProperty<unknown>(key, 'ethereumAddress');
    return (
      typeof address === 'string' &&
      verifyEip191Address(decoded.signingInput, decoded.signature, address)
    );
  }
  const publicKeyJwk = nonObjectPrototypeProperty<PublicKeyJwk>(key, 'publicKeyJwk');
  if (publicKeyJwk !== undefined) {
    return verifyWithJwkOrFalse(alg, decoded, publicKeyJwk);
  }
  const verify = nonObjectPrototypeProperty<unknown>(key, 'verify');
  if (typeof verify !== 'function') {
    return false;
  }
  const result: unknown = verify.call(key, decoded.digest, decoded.signature, decoded.signingInput);
  if (result !== true && typeof (result as { then?: unknown } | null)?.then === 'function') {
    // 拒否する Promise の未処理 rejection（プロセス終了）を避ける。結果は使わない。意図的に捨てる: 結論は
    // `false` で、理由は影響しない。入力ごとに出せる失敗なので `onWarning` には流さない（呼び出し側が入力で警告を埋められる）。
    Promise.resolve(result).catch(() => undefined);
  }
  return result === true;
}
