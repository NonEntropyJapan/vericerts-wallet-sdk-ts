/**
 * DPoP（RFC 9449）proof の生成・検証で共有するプリミティブ群。
 *
 * 仕様 SoT: RFC 9449 "OAuth 2.0 Demonstrating Proof of Possession (DPoP)"、
 * RFC 7638 "JSON Web Key (JWK) Thumbprint"。
 * 生成側（`dpop.ts`）と検証側（`dpop-verify.ts`）の双方から参照される純粋関数のみを置く。
 *
 * スコープ境界:
 * - 本モジュールは JWK サムプリント（`jkt`）・`ath`・`htu` 正規化・定数時間比較のみを担う。
 * - コンパクト JWS の直列化は `credential/vc/compact-jws.ts` の `signCompactJws` に委譲し、重複実装しない。
 * - `jti` の一意性（リプレイ検出）と seen-nonces 管理は呼び出し側の責務。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` にアクセストークン・
 * proof JWT・鍵素材・クレーム値を含めない。本モジュールは privateKey を一切保持しない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ALG_SPECS, type AlgSpec, jwkToUncompressedPublicKey } from '../../identity/jwt/jwk-key.js';
import { ownProperty } from '../../prototype-safety/own-property.js';

/**
 * DPoP proof JWT（RFC 9449 §4.2）。
 *
 * 実体は**コンパクト JWS 直列化された文字列**（`<base64url(header)>.<base64url(payload)>.<base64url(signature)>`）
 * であり、構造体ではない。RFC 9449 は proof を HTTP の `DPoP` ヘッダへ載せる 1 個の JWT と定めており、
 * ヘッダ値として送れるのは文字列だけである。
 *
 * 素の `string` ではなくこの別名を用いるのは、`createDpopProof` の戻り値・`verifyDpopProof` の入力・
 * `PARRequest.dpop` が同一の値であることを型名で示すためで、構造的には
 * `string` と同一（互いに代入可能）である。
 */
export type DpopProof = string;

/** DPoP proof JWT の `typ` ヘッダ値（RFC 9449 §4.2）。 */
export const DPOP_JWT_TYP = 'dpop+jwt';

/**
 * DPoP proof が対応する署名アルゴリズム（`ES256` = P-256 / `ES256K` = secp256k1）。
 *
 * SDK が DPoP に対応するアルゴリズムは `ES256` と `ES256K`。
 * `CredentialAlg` の別名にすると、他機能のための alg 追加（例: `EdDSA`）だけで DPoP の型上の
 * 受理範囲が暗黙に広がる（`DPOP_SUPPORTED_ALGS` の実行時ガードとも食い違う）。
 */
export type DpopAlg = 'ES256' | 'ES256K';

/**
 * `DpopAlg` が表す DPoP proof の署名アルゴリズムを実行時に検査するための集合。
 *
 * **共有レジストリ `ALG_SPECS` のキー集合とは意図的に独立させている。** `ALG_SPECS` は
 * `Record<string, AlgSpec>` として可変であり、did:jwt など他機能のために alg が追加され得る。
 * 許容判定をそのキー集合に委ねると、DPoP が許可すべきでない alg まで将来の追加だけで自動的に
 * 通ってしまう（許容集合の暗黙拡大）。本集合を DPoP 側で閉じて持つことで、レジストリが増えても
 * DPoP の受理範囲は仕様どおり `ES256` / `ES256K` に固定される。
 */
export const DPOP_SUPPORTED_ALGS: ReadonlySet<DpopAlg> = new Set<DpopAlg>(['ES256', 'ES256K']);

/**
 * 値が DPoP で許可された署名アルゴリズムかを判定する型述語。
 *
 * @param value 判定対象の未検証値。
 * @returns `DPOP_SUPPORTED_ALGS` に含まれる文字列なら `true`。
 */
export function isDpopAlg(value: unknown): value is DpopAlg {
  return typeof value === 'string' && DPOP_SUPPORTED_ALGS.has(value as DpopAlg);
}

/**
 * DPoP で許可された alg の検証パラメータ（`crv` / 検証関数）を取り出す。
 *
 * 許容判定は `DPOP_SUPPORTED_ALGS` が担い、`ALG_SPECS` は曲線名と検証関数の供給元としてのみ
 * 参照する（重複実装を避けるため）。許容集合にあるのにレジストリ側に定義が無い場合は、署名検証を
 * 実施できないため形式不正として拒否する（fail-safe）。
 *
 * @param alg 判定済みの DPoP 署名アルゴリズム。
 * @returns 対応する検証パラメータ。
 * @throws 未許可 alg、またはレジストリに定義が無い場合（VericertsError、code `4080`）。
 */
export function requireDpopAlgSpec(alg: DpopAlg): AlgSpec {
  // プロパティアクセスでは `Object.prototype` のメンバ名が継承値を返すため、自身のメンバのみを見る。
  if (!isDpopAlg(alg) || !Object.hasOwn(ALG_SPECS, alg)) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  const spec = ALG_SPECS[alg];
  if (spec === undefined) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  return spec;
}

/** RFC 7638 サムプリント計算に用いる EC 公開鍵 JWK の必須メンバ。 */
export interface DpopPublicKeyJwk {
  /** 鍵種別。EC 鍵のみ対応するため常に `'EC'`。 */
  readonly kty: 'EC';
  /** 曲線名（`ES256` なら `P-256`、`ES256K` なら `secp256k1`）。 */
  readonly crv: string;
  /** X 座標（base64url、パディングなし）。 */
  readonly x: string;
  /** Y 座標（base64url、パディングなし）。 */
  readonly y: string;
}

/**
 * 任意の JWK を DPoP 用の EC 公開鍵 JWK へ正規化する。
 *
 * `kty` が `EC`、`crv` が `alg` に対応する曲線、`x` / `y` が文字列であることを検証し、秘密鍵メンバ
 * `d` が存在しないことを要求する。さらに `x` / `y` が base64url としてちょうど 32 バイトへデコード
 * できることまで検証する（座標長を見ないと、実在しない鍵に対して RFC 7638 サムプリントが算出でき
 * てしまうため）。戻り値は `{kty, crv, x, y}` のみで構成されるため、`d` 以外の余分なメンバ
 * （`kid` / `use` / 独自拡張）も含めて除去され、proof ヘッダへ漏出しない。
 *
 * `kty` / `crv` / `x` / `y` / `d` はいずれも**自身のプロパティ**としてのみ読む。継承したメンバは
 * 「存在しない」として扱われる。
 *
 * @param jwk 検証対象の JWK（未検証の任意オブジェクト）。
 * @param alg 期待する署名アルゴリズム。`crv` の一致判定に使う。
 * @returns 必須メンバのみを持つ EC 公開鍵 JWK。
 * @throws `kty` / `crv` / `x` / `y` が自身のプロパティとして不正・欠落（座標長・base64url 不正を
 *         含む）、または秘密鍵メンバ `d` を自身のプロパティとして含む場合
 *         （VericertsError、code `4080`）。
 */
export function toDpopPublicKeyJwk(
  jwk: Readonly<Record<string, unknown>>,
  alg: DpopAlg,
): DpopPublicKeyJwk {
  const spec = requireDpopAlgSpec(alg);
  // JWK メンバは自身のプロパティに限って読む。プロパティアクセス・分割代入は
  // プロトタイプ鎖を辿るため、`Object.prototype.d` 汚染下では `d` を持たない**正当な JWK が
  // 誤って拒否**され（DoS）、`kty` / `crv` / `x` / `y` 汚染下では逆に**それらを欠く JWK が
  // 継承値で補われて受理**される（読み取りの非対称性）。`verifyDpopProof` 経路の proof header は
  // `jws.ts` が `parseJsonWithoutPrototype` で読むため既に null プロトタイプだが、本関数は
  // `createDpopProof`（`signer.publicKeyJwk`）や呼び出し側が用意した JWK も受け取るため、
  // 鎖を断つ責務は読み取り時点の本関数側にある。JWK のメンバは純データなので `ownProperty` を使う。
  // 秘密鍵メンバを含む JWK は公開鍵として扱わない（proof ヘッダへの秘密鍵漏出を防ぐ）。
  if (ownProperty<unknown>(jwk, 'd') !== undefined) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  const kty = ownProperty<unknown>(jwk, 'kty');
  const crv = ownProperty<unknown>(jwk, 'crv');
  const x = ownProperty<unknown>(jwk, 'x');
  const y = ownProperty<unknown>(jwk, 'y');
  if (kty !== 'EC' || crv !== spec.crv) {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  if (typeof x !== 'string' || typeof y !== 'string') {
    throw new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
  // 座標長・base64url 妥当性の検証は jwkToUncompressedPublicKey に委譲する（重複実装しない）。
  // `kty` / `crv` は直上（本関数内の `kty !== 'EC' || crv !== spec.crv` ガード）で
  // spec.crv に対して検査済みのため、`expectedCrv: null`（曲線束縛なし）を明示して座標のみを
  // 検証させる。曲線束縛の責務はこの関数側にある。
  // 戻り値は不要で、DPoP では形式不正として 4080 を投げる。
  jwkToUncompressedPublicKey(
    { x, y },
    { expectedCrv: null, errorCode: ErrorCodes.DPOP_PROOF_MALFORMED },
  );
  return { kty: 'EC', crv: spec.crv, x, y };
}

/**
 * EC 公開鍵 JWK の RFC 7638 サムプリント（`jkt`）を計算する。
 *
 * 正準化は RFC 7638 §3 に従い、必須メンバのみを辞書順（`crv` → `kty` → `x` → `y`）で並べた
 * 空白なしの JSON `{"crv":"…","kty":"EC","x":"…","y":"…"}` を UTF-8 で符号化し、その SHA-256 を
 * base64url（パディングなし）で表現する。**メンバ順は RFC 7638 §3.2 が定める lexicographic order で
 * 固定されており、並べ替えるとサムプリントが変わるため変更してはならない。**
 *
 * @param jwk サムプリント計算対象の JWK（`toDpopPublicKeyJwk` で正規化してから計算する）。
 * @param alg 期待する署名アルゴリズム。
 * @returns RFC 7638 サムプリント（base64url、パディングなし）。
 * @throws JWK が EC 公開鍵として不正な場合（`x` / `y` の座標長・base64url 不正を含む。
 *         VericertsError、code `4080`）。
 */
export function computeJwkThumbprint(jwk: Readonly<Record<string, unknown>>, alg: DpopAlg): string {
  // 分割代入の対象は `toDpopPublicKeyJwk` が組み立てた新しいリテラルで、4 メンバとも own である
  // （入力 jwk の鎖を辿らない）。汚染耐性は `toDpopPublicKeyJwk` 側の own 読みが担保する。
  const { kty, crv, x, y } = toDpopPublicKeyJwk(jwk, alg);
  // RFC 7638 §3.2: メンバは辞書順（crv, kty, x, y）・空白なし。順序を変更しないこと。
  const canonical = JSON.stringify({ crv, kty, x, y });
  return base64urlnopad.encode(sha256(new TextEncoder().encode(canonical)));
}

/**
 * アクセストークンの `ath` クレーム値（RFC 9449 §4.2）を計算する。
 *
 * `ath` はアクセストークン文字列の SHA-256 を base64url（パディングなし）で表現した値。
 * アクセストークン自体はログ出力せず、例外メッセージ・`context` にも含めない。
 *
 * @param accessToken 対象のアクセストークン（値は保持・記録しない）。
 * @returns `ath` クレーム値（base64url、パディングなし）。
 */
export function computeAth(accessToken: string): string {
  return base64urlnopad.encode(sha256(new TextEncoder().encode(accessToken)));
}

/**
 * `htu` クレーム用に HTTP target URI を正規化する。
 *
 * RFC 9449 §4.3 step 9 は `htu` からクエリとフラグメントを除いた比較を要求する。`URL` パーサに
 * 委譲することで、スキーム・ホストの小文字化と既定ポート（`https` の 443 等）の省略も同時に
 * 施され、表記揺れに強い比較が可能になる。
 *
 * userinfo（`user:pass@`）もクエリ・フラグメントと同様に除去する。`htu` は HTTP target URI
 * （RFC 9110 §7.1）であり、http(s) URI の userinfo は RFC 9110 §4.2.4 が生成を禁じているため、
 * 本来 `htu` に現れてはならない。除去しないと (1) userinfo の有無だけで正規の proof が束縛不一致に
 * なり、(2) 正規化結果は `VerifiedDpopProof.htu` として呼び出し側へ返るため、埋め込まれた資格情報が
 * ログ等へ伝播する。
 *
 * @param uri 正規化対象の URI 文字列。
 * @returns クエリ・フラグメント・userinfo を除去した正規化 URI。パース不能な場合は `undefined`
 *          （例外は投げず、判定は呼び出し側の責務とする）。
 */
export function normalizeHtu(uri: string): string | undefined {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    // 入力 URI は例外に含めないため、失敗は undefined で表現する。
    return undefined;
  }
  url.search = '';
  url.hash = '';
  // userinfo は HTTP target URI に現れてはならない（RFC 9110 §4.2.4）。password を先に空へ戻す。
  url.password = '';
  url.username = '';
  return url.href;
}
