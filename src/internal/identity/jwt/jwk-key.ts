/**
 * JWS `alg` ごとの検証パラメータと、公開鍵 JWK → 生バイト列の変換ヘルパ。
 *
 * `jwt-codec.ts` から分離した鍵変換レイヤ（1 ファイル 300 行以下のため）。
 * did:jwt / JWT-VC / SD-JWT VC / KB-JWT など、`alg` 駆動で署名検証する全経路が共有する。
 *
 * 対応署名アルゴリズム（header.alg）:
 *
 * | alg     | kty | 曲線      | 検証関数          | 検証入力                 |
 * | ------- | --- | --------- | ----------------- | ------------------------ |
 * | `ES256` | EC  | P-256     | `verifyP256`      | signing-input の SHA-256 |
 * | `ES256K`| EC  | secp256k1 | `verifySecp256k1` | signing-input の SHA-256 |
 * | `EdDSA` | OKP | Ed25519   | `verifyEd25519`   | signing-input そのもの   |
 *
 * `ES256` の検証は既定で **high-S も受理**する（JWS の ES256 は RFC 7518 §3.4 が low-S を要求しない。
 * 第三者 Issuer / HSM / KMS / WebCrypto / OIDF Conformance Suite は high-S の P-256 署名を出す）。
 * `ES256K`（secp256k1）は `allowHighS` を無視し常に low-S のみ。署名バイト列が識別子・重複判定キーに
 * なる経路（DPoP / did:jwt）だけが `verify(…, false)` を明示して low-S を強制する。
 *
 * ECDSA は digest ベース、Ed25519（PureEdDSA / RFC 8032）は事前ハッシュを行わないため、prehash の
 * 有無は `AlgSpec.verify` 側の責務とし、呼び出し側は常に signing-input を渡す。
 *
 * セキュリティ上の注意:
 * - `alg` → `kty` / `crv` の束縛は `ALG_SPECS` に集約し、`jwkToVerificationKey` を必ず経由することで
 *   alg confusion（`EdDSA` を EC 鍵で、`ES256` を OKP 鍵で検証する等）を構造的に排除する。
 * - 例外メッセージや `context` に DID 文字列・JWT・公開鍵などの入力データを含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import type { ErrorCode } from '../../errors.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { verifyEd25519 } from '../../keymanager/ed25519.js';
import { verifyP256, verifySecp256k1 } from '../../keymanager/signer.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { PublicKeyJwk } from '../did.js';
import { base64urlDecode } from './jwt-codec.js';

/** EC 公開鍵 JWK の座標長（P-256 / secp256k1 とも 32 バイト）。 */
export const EC_COORDINATE_LENGTH = 32;

/**
 * ECDH-ES 鍵合意が対応する EC 曲線（P-256 のみ）。`auth/jwe/ecdh.ts` の受信者鍵検証・
 * `wallet-migration/kdf/backup-ecdh.ts` の `recipientKey` 検証が共有する定数（
 * 従来は両ファイルが同名・同値の定数を独立定義していた）。
 */
export const SUPPORTED_EC_CRV = 'P-256';

/** OKP 公開鍵 JWK の `x` 長（Ed25519 は 32 バイト）。 */
export const OKP_KEY_LENGTH = 32;

/** 非圧縮 EC 公開鍵の SEC1 プレフィックス（`0x04`）。 */
const UNCOMPRESSED_POINT_PREFIX = 0x04;

/** 署名アルゴリズムごとの検証パラメータ（JWK kty / crv と検証関数）。 */
export interface AlgSpec {
  /** 期待する JWK `crv` 値。 */
  readonly crv: string;
  /** 期待する JWK `kty` 値（`EC` = ECDSA / `OKP` = EdDSA）。 */
  readonly kty: 'EC' | 'OKP';
  /**
   * 署名検証関数。
   *
   * 入力は常に signing-input（`base64url(header).base64url(payload)` の UTF-8 バイト列）で、
   * ECDSA の事前ハッシュ（SHA-256）が必要かどうかは各 spec の実装が判断する。
   *
   * `allowHighS` は ES256 の high-S を受理するか（既定 `true` = RFC 7518 どおり受理）。`false` は
   * low-S 強制で、署名バイト列が識別子・重複判定キーになる経路だけが明示する。ES256K は常に
   * low-S のみで、EdDSA には無関係（いずれも無視する）。
   */
  readonly verify: (
    signingInput: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
    allowHighS?: boolean,
  ) => boolean;
}

/**
 * 対応 alg → 検証パラメータの対応表。
 *
 * `alg` と `kty` / `crv` の対応は厳密に固定する（alg confusion 対策）。`EdDSA` は OKP/Ed25519 の
 * JWK でのみ、`ES256` / `ES256K` は EC の JWK でのみ検証される。
 *
 * プロトタイプを持たないオブジェクト（`Object.create(null)`）として構築する。`alg` は JWS ヘッダ
 * 由来＝攻撃者が自由に指定できる値であり、通常のオブジェクトリテラルだと `alg: "constructor"` /
 * `"toString"` 等が `Object.prototype` のプロパティにヒットして `ALG_SPECS[alg] === undefined`
 * の未対応 alg ガードをすり抜ける。その結果 `spec.kty` / `spec.crv` が `undefined` のまま
 * `jwkToVerificationKey` を通過し、`spec.verify` が関数でないため `VericertsError(2001)` ではなく
 * 未捕捉の `TypeError` が送出される（`resolveDidJwt` で再現）。プロトタイプを断つことで、
 * 呼び出し側がガードを書き忘れても構造的に未対応 alg が弾かれる。
 */
export const ALG_SPECS: Record<string, AlgSpec> = Object.assign(
  Object.create(null) as Record<string, AlgSpec>,
  {
    ES256: {
      crv: 'P-256',
      kty: 'EC',
      verify: (m, s, p, allowHighS = true) => verifyP256(sha256(m), s, p, { allowHighS }),
    },
    ES256K: { crv: 'secp256k1', kty: 'EC', verify: (m, s, p) => verifySecp256k1(sha256(m), s, p) },
    // Ed25519（PureEdDSA）は事前ハッシュせず signing-input そのものを検証する。
    EdDSA: { crv: 'Ed25519', kty: 'OKP', verify: verifyEd25519 },
  } satisfies Record<string, AlgSpec>,
);

/** `kty` → 許可 `crv` 集合の読み取り専用テーブル。 */
type CrvsByKty = ReadonlyMap<string, ReadonlySet<string>>;

/** `ALG_SPECS` から `kty` → 許可 `crv` 集合を導出する（対応 alg の増減に自動追従させる）。 */
function buildSigningCrvsByKty(): CrvsByKty {
  const table = new Map<string, Set<string>>();
  for (const spec of Object.values(ALG_SPECS)) {
    const crvs = table.get(spec.kty) ?? new Set<string>();
    crvs.add(spec.crv);
    table.set(spec.kty, crvs);
  }
  return table;
}

/**
 * 署名検証に使用できる `kty` → `crv` の許可リスト（`ALG_SPECS` から導出）。
 *
 * 現時点の内容は `EC` → `P-256` / `secp256k1`、`OKP` → `Ed25519`。JWK を crypto へ渡す前に
 * 曲線を先行検査したい経路（`sdjwt/claims.ts` の `validateCnf` 等）が参照する。
 * 鍵合意専用の `X25519` は `ALG_SPECS` に存在しないため、署名鍵として受理されることはない。
 */
export const SIGNING_CRVS_BY_KTY: CrvsByKty = buildSigningCrvsByKty();

/** `jwkToUncompressedPublicKey` の検証オプション。 */
export interface UncompressedPublicKeyOptions {
  /**
   * 期待する `crv` 値。文字列を指定した場合は `kty === 'EC'` と `crv` の一致を先行検査する
   * （alg / 曲線が確定している DID・署名検証経路向け）。
   *
   * `null` は「曲線束縛を行わない」ことの明示的な宣言で、この場合 `kty` / `crv` を一切見ず、
   * 座標（`x` / `y`）の形式のみを検証する。DPoP のように呼び出し側が別レイヤで `kty` / `crv` を
   * 検証済みの経路や、座標だけを持つ部分 JWK を検証する経路がこちらを使う。
   *
   * 省略を許さず必須プロパティとしているのは、曲線束縛こそが安全側の既定であり、それを外すのは
   * 意図的でレビュー可能な判断でなければならないためである。省略可能だと、書き忘れ 1 つで
   * alg confusion（`ES256` を期待する経路が secp256k1 や他曲線の鍵を受理する等）に対する
   * 構造的防御が、コンパイラにもレビュアにも無警告のまま失われる。`null` を明示的に書かせることで、
   * 束縛を外す判断が必ず差分に現れるようにする。
   */
  readonly expectedCrv: string | null;
  /** 検証失敗時に送出する `VericertsError` のコード（全ての失敗モードで共通）。 */
  readonly errorCode: ErrorCode;
}

/**
 * EC 公開鍵 JWK（`x` / `y` 座標）を SEC1 非圧縮形式（`0x04 || x(32) || y(32)`）へ変換する。
 *
 * `verifyP256` / `verifySecp256k1` / `p256.getSharedSecret` は非圧縮 65 バイト公開鍵を受理するため、
 * JWK 座標から直接組み立てる。曲線束縛の要否は `options.expectedCrv` で切り替える
 * （`string` = 束縛する / `null` = 束縛しないことの明示宣言）。
 *
 * `x` / `y` は base64url（パディングなし）文字列で、各 32 バイトであること。型不正・欠落・長さ不正・
 * デコード失敗はいずれも `options.errorCode` で拒否する。例外メッセージ・`context` には鍵素材を
 * 含めず、`cause` も渡さない。
 *
 * JWK メンバは**自身のプロパティ**としてのみ読み、継承したメンバは「存在しない」として扱う
 * 対象は `expectedCrv` が文字列のときに読む `kty` / `crv` と、常に読む `x` / `y`
 * である（`expectedCrv: null` では `kty` / `crv` をそもそも読まない）。
 *
 * @param jwk EC 公開鍵 JWK（少なくとも `x` / `y` を含む）。
 * @param options `expectedCrv`（必須。`null` で曲線束縛なしを明示）と `errorCode`（必須）。
 * @returns 65 バイトの非圧縮公開鍵バイト列。
 * @throws JWK 形式不正・座標長不正・base64url 不正、および `expectedCrv` が文字列のときの
 *         `kty` / `crv` 不一致の場合（VericertsError、`options.errorCode`）。
 */
export function jwkToUncompressedPublicKey(
  jwk: PublicKeyJwk,
  options: UncompressedPublicKeyOptions,
): Uint8Array {
  const { expectedCrv, errorCode } = options;
  // JWK メンバは自身のプロパティに限って読む（先行事例は `toDpopPublicKeyJwk`）。
  // 本層に JWK を届けるパース経路（did:jwk の `identity/jwk/codec.ts`、did:jwt の `jwt-codec.ts`、
  // SD-JWT の `cnf`、did:web の `identity/web/did-web-fetch.ts`）は
  // `parseJsonWithoutPrototype`（`internal/prototype-safety/parse-json.ts`）を通るため、そこ由来の JWK は `null`
  // プロトタイプで `Object.prototype` を継承しない。本関数に継承付きの JWK が届くのは、パース境界を
  // 通らない経路――**呼び出し側供給 / DI 由来 / SDK 内部生成**――である（`verifyCredential` の
  // `opts.key.publicKeyJwk`、W2W の `lenderPublicKeyJwk` / `signerPublicKeyJwk`、
  // `encryptJweCompact` の受信者 JWK（`auth/jwe/ecdh.ts` の `recipientPublicKey` 経由）、カスタム
  // resolver が返す DID Document の `publicKeyJwk`、`dpop-common.ts` の `toDpopPublicKeyJwk` が
  // その場で組む `{ x, y }` リテラル、`eudi/pseudonym/attestation.ts` の内部生成 `cnfJwk` 等）。
  // これは `parse-json.ts` が「呼び出し側が渡すオプションと DI には一切効かない」「既存の
  // `ownProperty` 呼び出しを削ってはならない（多層防御）」と明記する範囲そのものである。鎖読みだと
  // 汚染下で `kty` / `crv` / `x` / `y` を**欠く JWK が継承値で補われて受理**される。JWK のメンバは
  // 純データなので `ownProperty` を使う。
  if (expectedCrv !== null) {
    // `expectedCrv: null`（曲線束縛なし）の宣言を尊重し、その場合は `kty` / `crv` を読みもしない。
    const kty = ownProperty<unknown>(jwk, 'kty');
    const crv = ownProperty<unknown>(jwk, 'crv');
    if (kty !== 'EC' || crv !== expectedCrv) {
      throw new VericertsError(errorCode);
    }
  }
  const xValue = ownProperty<unknown>(jwk, 'x');
  const yValue = ownProperty<unknown>(jwk, 'y');
  if (typeof xValue !== 'string' || typeof yValue !== 'string') {
    throw new VericertsError(errorCode);
  }
  let x: Uint8Array;
  let y: Uint8Array;
  try {
    // `base64urlDecode` は 2001 固定のため使わない（呼び出し側の errorCode を尊重する）。
    x = base64urlnopad.decode(xValue);
    y = base64urlnopad.decode(yValue);
  } catch {
    // base64url でない文字列を含む = 不正な JWK。鍵素材を含み得るため cause は渡さない。
    throw new VericertsError(errorCode);
  }
  if (x.length !== EC_COORDINATE_LENGTH || y.length !== EC_COORDINATE_LENGTH) {
    throw new VericertsError(errorCode);
  }
  const publicKey = new Uint8Array(1 + EC_COORDINATE_LENGTH * 2);
  publicKey[0] = UNCOMPRESSED_POINT_PREFIX;
  publicKey.set(x, 1);
  publicKey.set(y, 1 + EC_COORDINATE_LENGTH);
  return publicKey;
}

/**
 * OKP 公開鍵 JWK（`x` のみ）を生の公開鍵バイト列（32 バイト）へ変換する。
 *
 * `verifyEd25519` は 32 バイトの圧縮エドワーズ点を受理するため、`x` をそのまま decode する。
 * OKP JWK は EC のような `y` を持たないため、`y` が存在する場合は EC JWK の偽装（alg confusion）
 * とみなして拒否する。
 *
 * `kty` / `crv` / `x` / `y` はいずれも**自身のプロパティ**としてのみ読む。継承したメンバは
 * 「存在しない」として扱われる。
 *
 * @param jwk OKP 公開鍵 JWK（`kty` / `crv` / `x` を持つ）。
 * @param expectedCrv alg から期待される `crv` 値（`Ed25519`）。
 * @returns 32 バイトの公開鍵バイト列。
 * @throws JWK 形式不正・`x` 長不正・crv 不一致・`y` 混入の場合（VericertsError、code `2001`）。
 */
export function jwkToOkpPublicKey(jwk: PublicKeyJwk, expectedCrv: string): Uint8Array {
  // JWK メンバは自身のプロパティに限って読む。`kty` / `crv` / `x` を鎖で読むと、
  // 汚染下で**それらを欠く JWK が継承値で補われて受理**される。逆に `y` の不在チェックを鎖で読むと、
  // `Object.prototype.y` 汚染下で `y` を持たない**正当な OKP JWK が誤って拒否**される（DoS）。
  // この読み取りの非対称は `d` 不在チェックと同型で、own 限定にすることで両方が塞がる。
  // 本関数の呼び出し元は `jwkToVerificationKey` のみで、そこへ `Object.prototype` を継承した JWK が
  // 届くのは呼び出し側供給の経路（`verifyCredential` の `opts.key.publicKeyJwk`、カスタム resolver が
  // 返す DID Document の `publicKeyJwk` 等）に限られる。did:jwt の `publicKeyJwk` や SD-JWT の `cnf` は
  // `parseJsonWithoutPrototype` 由来で `null` プロトタイプのため、そもそも鎖読みの影響を受けない。
  const kty = ownProperty<unknown>(jwk, 'kty');
  if (kty !== 'OKP') {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const crv = ownProperty<unknown>(jwk, 'crv');
  if (crv !== expectedCrv) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const xValue = ownProperty<unknown>(jwk, 'x');
  if (typeof xValue !== 'string') {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (ownProperty<unknown>(jwk, 'y') !== undefined) {
    // OKP 鍵は `y` を持たない。EC JWK を OKP と偽装する入力を弾く。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const x = base64urlDecode(xValue);
  if (x.length !== OKP_KEY_LENGTH) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return x;
}

/**
 * `AlgSpec` の `kty` に応じて、JWK を検証関数が受理する公開鍵バイト列へ変換する。
 *
 * alg 駆動の検証経路はすべて本関数を経由することで、alg と鍵種別の食い違いを排除する。
 *
 * @param jwk 検証鍵 JWK。
 * @param spec alg から引いた検証パラメータ。
 * @returns 検証関数へ渡す公開鍵バイト列（EC は非圧縮 65 バイト / OKP は 32 バイト）。
 * @throws JWK 形式不正・kty / crv 不一致の場合（VericertsError、code `2001`）。
 */
export function jwkToVerificationKey(jwk: PublicKeyJwk, spec: AlgSpec): Uint8Array {
  return spec.kty === 'OKP'
    ? jwkToOkpPublicKey(jwk, spec.crv)
    : jwkToUncompressedPublicKey(jwk, {
        expectedCrv: spec.crv,
        errorCode: ErrorCodes.INVALID_DID,
      });
}
