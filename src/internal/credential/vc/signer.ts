/**
 * JWT-VC 署名のための署名抽象（`CredentialSigner`）。
 *
 * VC 発行で生 privateKey を外部へ渡す従来の API（アンチパターン）を解消するための seam。
 * `issueCredential` は本インターフェースのみに依存し、署名鍵そのものは保持しない。
 * これにより keymanager のように鍵を非公開のまま保持する実装（鍵レジストリ）からでも、
 * privateKey を露出せず JWT-VC 署名できる（keymanager 側は構造的に互換な戻り値で橋渡しする）。
 *
 * 後方互換・テスト・直接利用のために、生 privateKey から `CredentialSigner` を生成する
 * `createPrivateKeySigner` を提供する（従来 `issueCredential(vc, privateKey, alg)` のロジックを内包）。
 *
 * KMS / HSM / 外部署名サービスのように署名が非同期になる実装のために `AsyncCredentialSigner`
 * （`sign` が `Promise<Uint8Array>` を返す）を併せて定義する。具体的な adapter は
 * `keymanager/jws/remote-signer.ts` の `createRemoteSigner` が提供する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に privateKey・VC 本文を含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { getEd25519PublicKey, signEd25519 } from '../../keymanager/ed25519.js';
import { signEip191 } from '../../keymanager/eip191.js';
import type {
  AnyCredentialSigner,
  AsyncCredentialSigner,
  CredentialSigner,
} from '../../keymanager/jws/signer-types.js';
import {
  getP256PublicKey,
  getSecp256k1PublicKey,
  signP256,
  signSecp256k1Recoverable,
} from '../../keymanager/signer.js';
import type { CredentialAlg, CredentialSignerAlg } from './jws.js';

// 署名鍵の契約は Foundation（`keymanager/jws/signer-types.ts`）が SSOT。ここでは互換のため
// 再エクスポートする（`keymanager` が `credential` を import しないようにするための移設）。
export type { AnyCredentialSigner, AsyncCredentialSigner, CredentialSigner };

/**
 * `buildJwsHeader` がヘッダ組み立てに必要とする最小の入力。
 *
 * `CredentialSigner` / `AsyncCredentialSigner` はいずれもこの形を満たす。秘密鍵を持たない経路
 * （分離型 Holder Service の KB-JWT テンプレート等）からも同じ組み立てを共有できるよう、
 * signer そのものではなく `alg` / `kid` だけを要求する。
 */
export interface JwsHeaderSource<A extends CredentialSignerAlg = CredentialAlg> {
  /** JWS 署名アルゴリズム。 */
  readonly alg: A;
  /** JWS ヘッダへ載せる鍵 ID（`kid`）。未指定なら header に `kid` を出力しない。 */
  readonly kid?: string;
}

/** `buildJwsHeader` が返す JWS ヘッダ（`typ` は呼び出し側のリテラル型を保つ）。 */
export interface JwsHeader<
  Typ extends string = string,
  A extends CredentialSignerAlg = CredentialAlg,
> {
  /** JWS 署名アルゴリズム。 */
  readonly alg: A;
  /** 鍵 ID。`source.kid` 未設定時はプロパティ自体が存在しない。 */
  readonly kid?: string;
  /** JWS ヘッダの `typ`。 */
  readonly typ: Typ;
}

/**
 * signer から JWS ヘッダを組み立てる（`kid` の有無を発行 API 間で統一する）。
 *
 * キー順は `alg` → `kid` → `typ` に固定する。`source.kid` 未設定時は `kid` を出力しないため、
 * シリアライズ結果は従来どおり `{"alg":...,"typ":...}` と完全に一致する（後方互換）。
 *
 * `kid` の有無は `Object.hasOwn` で判定する。`source.kid !== undefined` だとプロトタイプ鎖を
 * 辿るため、`Object.prototype.kid` が汚染されている環境では **`kid` を持たない signer が
 * 署名した JWS のヘッダに、攻撃者が選んだ鍵 ID が載る**（検証側の鍵解決を誤導できる）。
 * 同じ理由で `format-negotiation/types.ts` / `schema-validation/dispatch.ts` も `Object.hasOwn`
 * を用いている。
 *
 * @param source JWS ヘッダの素（`CredentialSigner` / `AsyncCredentialSigner` もそのまま渡せる）。
 * @param typ JWS ヘッダの `typ`（JWT-VC は `JWT`、SD-JWT VC は `dc+sd-jwt`、KB-JWT は `kb+jwt`）。
 * @returns JWS ヘッダオブジェクト。
 */
export function buildJwsHeader<Typ extends string, A extends CredentialSignerAlg = CredentialAlg>(
  source: JwsHeaderSource<A>,
  typ: Typ,
): JwsHeader<Typ, A> {
  // キー順をリテラルで表現し、`kid` の有無で分岐する（後から代入するとキー順が読み取りにくい）。
  // 継承した `kid` を拾わないよう、自身のプロパティであることを確かめてから読む。
  const kid = Object.hasOwn(source, 'kid') ? source.kid : undefined;
  return kid === undefined ? { alg: source.alg, typ } : { alg: source.alg, kid, typ };
}

/**
 * 署名鍵が IANA 登録済みの `alg`（`ES256` / `ES256K` / `EdDSA`）であることを確かめ、そう型付けして返す。
 *
 * `ES256K-R`（did:pkh / did:ethr の controller 鍵。IANA 登録外の標準外の例外）の署名鍵を、許可していない
 * 署名経路（OID4VCI の proof・EUDI の PID/EAA 受信・WUA・DIDComm・SD-JWT・Status List・Dashboard ログなど）へ渡さないための関門。
 * ES256K-R を許す経路は JWT-VC / JWT-VP / SIOPv2 id_token / `did_signMessage` だけで、それ以外は本関数を通す。
 *
 * @throws `ES256K-R` の署名鍵の場合（VericertsError、code `1030`、`context.reason: "es256k_r_not_allowed"`）。
 */
export function requireStandardSigner(
  signer: CredentialSigner<CredentialSignerAlg>,
): CredentialSigner<CredentialAlg> {
  if (!hasStandardAlg(signer)) {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM, {
      context: { reason: 'es256k_r_not_allowed' },
    });
  }
  // 同じ署名鍵をそのまま返す（コピーしない。クラスインスタンスの署名鍵・同一性を保つ）。
  return signer;
}

/** 署名鍵の `alg` が IANA 登録済みのものか（型ガード）。 */
function hasStandardAlg(
  signer: CredentialSigner<CredentialSignerAlg>,
): signer is CredentialSigner<CredentialAlg> {
  return signer.alg !== 'ES256K-R';
}

/** alg ごとの署名パラメータ（公開鍵 JWK 構築と signing-input への署名）。 */
interface SignerSpec {
  /** privateKey から検証側へ渡す公開鍵 JWK を構築する。 */
  readonly publicKeyJwk: (privateKey: Uint8Array) => PublicKeyJwk;
  /** signing-input に署名し 64 バイトの raw 署名を返す（事前ハッシュの要否は alg ごと）。 */
  readonly sign: (signingInput: Uint8Array, privateKey: Uint8Array) => Uint8Array;
}

/**
 * 非圧縮公開鍵（`0x04 || x(32) || y(32)`）から EC 公開鍵 JWK を構築する。
 *
 * @param uncompressed 非圧縮公開鍵（65 バイト）。
 * @param crv JWK の `crv` 値。
 * @returns `{ kty:'EC', crv, x, y }`（x / y は base64url）。
 */
function toEcJwk(uncompressed: Uint8Array, crv: string): PublicKeyJwk {
  // @scure/base の base64urlnopad に統一（Node の Buffer に依存せずブラウザでも動作）。
  return {
    kty: 'EC',
    crv,
    x: base64urlnopad.encode(uncompressed.subarray(1, 33)),
    y: base64urlnopad.encode(uncompressed.subarray(33, 65)),
  };
}

/**
 * Ed25519 公開鍵（32 バイト）から OKP 公開鍵 JWK を構築する。
 *
 * OKP 鍵は EC のような `y` を持たない（RFC 8037）。
 *
 * @param publicKey Ed25519 公開鍵（32 バイト）。
 * @returns `{ kty:'OKP', crv:'Ed25519', x }`（x は base64url）。
 */
function toOkpJwk(publicKey: Uint8Array): PublicKeyJwk {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: base64urlnopad.encode(publicKey),
  };
}

/**
 * alg → 署名パラメータの対応表。
 *
 * `ALG_SPECS`（`identity/jwt/jwk-key.ts`）と同じ理由でプロトタイプを持たないオブジェクトとして
 * 構築する。通常のオブジェクトリテラルだと JS からの型外呼び出し
 * （`createPrivateKeySigner(key, 'constructor' as CredentialSignerAlg)` 等）が `Object.prototype` に
 * ヒットし、直下の未対応 alg ガードをすり抜けて `TypeError` になる。
 */
const SIGNER_SPECS: Record<CredentialSignerAlg, SignerSpec> = Object.assign(
  Object.create(null) as Record<CredentialSignerAlg, SignerSpec>,
  {
    ES256: {
      publicKeyJwk: (privateKey) => toEcJwk(getP256PublicKey(privateKey, false), 'P-256'),
      sign: (signingInput, privateKey) => signP256(sha256(signingInput), privateKey),
    },
    ES256K: {
      publicKeyJwk: (privateKey) => toEcJwk(getSecp256k1PublicKey(privateKey, false), 'secp256k1'),
      // JWS は recovery 不要のため r||s の先頭 64B のみを使う。
      sign: (signingInput, privateKey) =>
        signSecp256k1Recoverable(sha256(signingInput), privateKey).signature.subarray(0, 64),
    },
    'ES256K-R': {
      publicKeyJwk: (privateKey) => toEcJwk(getSecp256k1PublicKey(privateKey, false), 'secp256k1'),
      // 標準外の例外（IANA 登録外）: signing-input を EIP-191 メッセージとした 65 バイトの recoverable 署名。
      sign: (signingInput, privateKey) => signEip191(signingInput, privateKey),
    },
    EdDSA: {
      publicKeyJwk: (privateKey) => toOkpJwk(getEd25519PublicKey(privateKey)),
      // Ed25519（PureEdDSA）は事前ハッシュせず signing-input そのものに署名する。
      sign: (signingInput, privateKey) => signEd25519(signingInput, privateKey),
    },
  } satisfies Record<CredentialSignerAlg, SignerSpec>,
);

/**
 * 生 privateKey から `CredentialSigner` を生成する（後方互換・テスト・直接利用向け）。
 *
 * 従来の `issueCredential(vc, privateKey, alg)` の署名ロジックを内包する。`ES256` は P-256、
 * `ES256K` は secp256k1、`EdDSA` は Ed25519（privateKey は 32 バイトのシード）。`publicKeyJwk` は
 * privateKey から導出した公開鍵から構築する（EC は非圧縮座標、Ed25519 は OKP の `x`）。
 *
 * @param privateKey 発行者の秘密鍵（32 バイト。`EdDSA` では Ed25519 シード）。
 * @param alg JWS 署名アルゴリズム（`ES256` / `ES256K` / `EdDSA`。標準外の例外として `ES256K-R`）。
 * @returns `CredentialSigner`。
 * @throws privateKey が不正な場合（VericertsError、code `1003`）、
 *         型外の alg の場合（VericertsError、code `1030`）。
 */
export function createPrivateKeySigner<A extends CredentialSignerAlg = CredentialAlg>(
  privateKey: Uint8Array,
  alg: A,
): CredentialSigner<A> {
  const spec = SIGNER_SPECS[alg];
  // alg は閉じた union のため通常は未定義にならないが、将来の alg 追加時の取りこぼしと
  // JS からの型外呼び出しに対する防御として未対応アルゴリズムを明示的に弾く。
  if (spec === undefined) {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  const publicKeyJwk = spec.publicKeyJwk(privateKey);
  return {
    alg,
    publicKeyJwk,
    // 事前ハッシュの要否を含め、signing-input から raw 署名を作るのは signer の責務。
    sign: (signingInput: Uint8Array): Uint8Array => spec.sign(signingInput, privateKey),
  };
}
