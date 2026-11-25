/**
 * did:jwt の生成 API（JWT 署名 → base64url エンコード）。
 *
 * 秘密鍵で JWT に署名し、`did:jwt:<base64url(JWT)>`
 * を組み立てる。解決は `method-jwt.ts` の `resolveDidJwt`、JWT デコード・JWK 変換・検証は
 * `jwt-codec.ts` が担当する（1 ファイル 300 行以下のため分割）。
 *
 * 対応署名アルゴリズム（header.alg）:
 *
 * | alg     | kty | 曲線      | 署名関数（keymanager / 純粋関数）                     | 署名入力                 |
 * | ------- | --- | --------- | ---------------------------------------------------- | ------------------------ |
 * | `ES256` | EC  | P-256     | `signP256`（64B P1363 raw）                          | signing-input の SHA-256 |
 * | `ES256K`| EC  | secp256k1 | `signSecp256k1Recoverable(...).signature` の先頭 64B | signing-input の SHA-256 |
 * | `EdDSA` | OKP | Ed25519   | `signEd25519`（64B）                                 | signing-input そのもの   |
 *
 * JWS は recovery 不要のため secp256k1 は r||s の 64 バイトのみを使う。ECDSA は digest ベース、
 * Ed25519（PureEdDSA / RFC 8032）は事前ハッシュを行わないため、prehash の有無は
 * `AlgGenerator.sign` 側の責務とし、`assembleDidJwt` は常に signing-input
 * （`base64url(header).base64url(payload)` の UTF-8 バイト列）を渡す。検証側 `ALG_SPECS`
 * （`jwk-key.ts`）および `credential/vc/signer.ts` の `SIGNER_SPECS` と同じ契約に揃える。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に privateKey・DID 文字列・JWT を含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { base64urlText } from '../../base64url.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { getEd25519PublicKey, signEd25519 } from '../../keymanager/ed25519.js';
import {
  getP256PublicKey,
  getSecp256k1PublicKey,
  signP256,
  signSecp256k1Recoverable,
} from '../../keymanager/signer.js';
import { isEpochSeconds, isLifetimeSeconds } from '../../primitives/option-guard.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { PublicKeyJwk } from '../did.js';
import { EC_COORDINATE_LENGTH } from './jwk-key.js';
import { DID_JWT_PREFIX } from './jwt-codec.js';

/** did:jwt が対応する JWS 署名アルゴリズム。 */
export type JwtAlg = 'ES256' | 'ES256K' | 'EdDSA';

/** 既定の有効期間。24 時間を秒で表す。 */
const DEFAULT_EXPIRES_IN_SECONDS = 24 * 60 * 60;

/** alg ごとの公開鍵 JWK 構築と raw 署名関数（64 バイト）。 */
interface AlgGenerator {
  /** 秘密鍵から検証用の公開鍵 JWK（EC なら x/y、OKP なら x）を構築する。 */
  publicKeyJwk(privateKey: Uint8Array): PublicKeyJwk;
  /**
   * signing-input に署名し 64 バイト raw 署名を返す。
   *
   * 入力は常に signing-input（`base64url(header).base64url(payload)` の UTF-8 バイト列）で、
   * ECDSA の事前ハッシュ（SHA-256）が必要かどうかは各エントリの実装が判断する。
   */
  sign(signingInput: Uint8Array, privateKey: Uint8Array): Uint8Array;
}

/**
 * 非圧縮公開鍵（`0x04 || x || y`）から EC 公開鍵 JWK を構築する。
 *
 * @param uncompressed 65 バイトの非圧縮公開鍵。
 * @param crv JWK `crv` 値。
 * @returns `{ kty: 'EC', crv, x, y }` 形式の公開鍵 JWK。
 */
function buildEcJwk(uncompressed: Uint8Array, crv: string): PublicKeyJwk {
  return {
    kty: 'EC',
    crv,
    x: base64urlnopad.encode(uncompressed.subarray(1, 1 + EC_COORDINATE_LENGTH)),
    y: base64urlnopad.encode(
      uncompressed.subarray(1 + EC_COORDINATE_LENGTH, 1 + EC_COORDINATE_LENGTH * 2),
    ),
  };
}

/**
 * Ed25519 公開鍵（32 バイト）から OKP 公開鍵 JWK を構築する。
 *
 * OKP 鍵は EC のような `y` を持たない（RFC 8037）。
 *
 * @param publicKey Ed25519 公開鍵（32 バイト）。
 * @returns `{ kty: 'OKP', crv: 'Ed25519', x }` 形式の公開鍵 JWK。
 */
function buildOkpJwk(publicKey: Uint8Array): PublicKeyJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: base64urlnopad.encode(publicKey) };
}

/**
 * alg → 生成パラメータの対応表。
 *
 * `ALG_SPECS`（`jwk-key.ts`）と同じ理由でプロトタイプを持たないオブジェクトとして構築する。
 * 通常のオブジェクトリテラルだと JS からの型外呼び出し（`createDidJwt({ alg: 'constructor' })`
 * 等）が `Object.prototype` のプロパティにヒットし、`createDidJwt` の未対応 alg ガード
 * （`=== undefined`）をすり抜けて `VericertsError(1030)` ではなく `TypeError` になる。
 */
const ALG_GENERATORS: Record<JwtAlg, AlgGenerator> = Object.assign(
  Object.create(null) as Record<JwtAlg, AlgGenerator>,
  {
    ES256: {
      publicKeyJwk: (privateKey) => buildEcJwk(getP256PublicKey(privateKey, false), 'P-256'),
      sign: (signingInput, privateKey) => signP256(sha256(signingInput), privateKey),
    },
    ES256K: {
      publicKeyJwk: (privateKey) =>
        buildEcJwk(getSecp256k1PublicKey(privateKey, false), 'secp256k1'),
      // JWS は recovery 不要のため r||s の先頭 64B のみを使う。
      sign: (signingInput, privateKey) =>
        signSecp256k1Recoverable(sha256(signingInput), privateKey).signature.subarray(0, 64),
    },
    EdDSA: {
      publicKeyJwk: (privateKey) => buildOkpJwk(getEd25519PublicKey(privateKey)),
      // Ed25519（PureEdDSA）は事前ハッシュせず signing-input そのものに署名する（RFC 8032）。
      sign: (signingInput, privateKey) => signEd25519(signingInput, privateKey),
    },
  } satisfies Record<JwtAlg, AlgGenerator>,
);

/**
 * header / payload オブジェクトと署名関数から did:jwt 文字列を組み立てる純粋プリミティブ。
 *
 * `base64url(header).base64url(payload)` を signing-input とし、その UTF-8 バイト列を **そのまま**
 * `sign` に渡して 64 バイト raw 署名を得る。最終的に `did:jwt:<base64url(JWT)>` を返す。生成本体
 * （`createDidJwt`）とテストフィクスチャ（`jwt-fixtures.ts`）で共有し、エンコード・署名ロジックの
 * 重複を排除する。
 *
 * 事前ハッシュ（ECDSA の SHA-256）は行わない。Ed25519（PureEdDSA / RFC 8032）は digest ではなく
 * メッセージそのものに署名するため、prehash をここで固定すると EdDSA が検証側 `ALG_SPECS` と
 * 食い違い、検証不能な JWT を生成してしまう。prehash の有無は `sign` 側の責務とする。
 *
 * @param header JWT ヘッダオブジェクト。
 * @param payload JWT ペイロードオブジェクト。
 * @param sign signing-input の UTF-8 バイト列を受け取り 64 バイト raw 署名を返す関数。
 * @returns did:jwt 文字列（`did:jwt:<base64url(JWT)>`）。
 */
export function assembleDidJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  sign: (signingInput: Uint8Array) => Uint8Array,
): string {
  const headerSeg = base64urlText(JSON.stringify(header));
  const payloadSeg = base64urlText(JSON.stringify(payload));
  const signingInput = `${headerSeg}.${payloadSeg}`;
  const signature = sign(new TextEncoder().encode(signingInput));
  const jwt = `${signingInput}.${base64urlnopad.encode(signature)}`;
  return `${DID_JWT_PREFIX}${base64urlText(jwt)}`;
}

/** `createDidJwt` の入力オプション。 */
export interface CreateDidJwtOptions {
  /** JWS 署名アルゴリズム。`ES256`（P-256）/ `ES256K`（secp256k1）/ `EdDSA`（Ed25519）。 */
  readonly alg: JwtAlg;
  /** 署名に使う秘密鍵（32 バイト。`EdDSA` では Ed25519 シード）。 */
  readonly privateKey: Uint8Array;
  /**
   * DID 主体クレーム（`iss` / `sub` / `id`）に設定する DID。省略時は `did:jwt:` プレフィックス。
   *
   * did:jwt は `did:jwt:<base64url(JWT)>` で DID 自身が JWT を内包するため、生成時点では最終
   * DID を確定できない（自己参照）。`resolveDidJwt` は「`did:jwt:` メソッド束縛」のみ
   * 要求するため、既定ではプレフィックス `did:jwt:` をそのまま用いる。
   */
  readonly subjectDid?: string;
  /** 発行時刻（NumericDate / エポック秒）。既定は現在時刻。 */
  readonly iat?: number;
  /** 有効化前時刻（NumericDate / エポック秒）。既定は `iat`。 */
  readonly nbf?: number;
  /** 有効期間（秒）。`exp = iat + expiresInSeconds`。既定は 24 時間。 */
  readonly expiresInSeconds?: number;
}

/**
 * did:jwt 文字列を生成する。
 *
 * header `{ alg, typ: 'JWT' }` と DID Document 相当の payload を JWT として署名し、
 * `did:jwt:<base64url(JWT)>` を返す。生成物は `resolveDidJwt` で解決でき、署名検証が通る
 * （生成 → 解決ラウンドトリップ）。
 *
 * @param opts 署名アルゴリズム・秘密鍵・時刻クレーム等。
 * @returns did:jwt 文字列。
 * @throws privateKey 不正の場合（VericertsError、code `1003`）、署名演算失敗の場合（code `1020`）。
 */
export function createDidJwt(opts: CreateDidJwtOptions): string {
  const generator = ALG_GENERATORS[opts.alg];
  if (generator === undefined) {
    // 型外の alg（JS から不正値が渡された場合）は `1030 UNSUPPORTED_ALGORITHM` にする（resolve 側は 2001）。
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  const publicKeyJwk = generator.publicKeyJwk(opts.privateKey);
  // 任意プロパティは自身のプロパティに限って読む。この payload はそのまま
  // 署名されるため、継承値を拾うと、その項目を**省略した**正当な生成でも汚染値が
  // **署名済み did:jwt トークン**に載る。特に `subjectDid` は `iss` / `sub` / `id` の 3 つを
  // 同時に差し替え、トークンが指す主体そのものを攻撃者の DID に化けさせる。
  const iat = ownProperty<number>(opts, 'iat') ?? Math.floor(Date.now() / 1000);
  const nbf = ownProperty<number>(opts, 'nbf') ?? iat;
  const expiresInSeconds =
    ownProperty<number>(opts, 'expiresInSeconds') ?? DEFAULT_EXPIRES_IN_SECONDS;
  // 非有限・負値・文字列は署名済み did:jwt に `null` や過去の `exp` で載り、検証側が必ず弾く。
  if (!isEpochSeconds(iat) || !isEpochSeconds(nbf) || !isLifetimeSeconds(iat, expiresInSeconds)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const exp = iat + expiresInSeconds;
  const subjectDid = ownProperty<string>(opts, 'subjectDid') ?? DID_JWT_PREFIX;

  const header = { alg: opts.alg, typ: 'JWT' };
  const payload: Record<string, unknown> = {
    iss: subjectDid,
    sub: subjectDid,
    id: subjectDid,
    iat,
    nbf,
    exp,
    verificationMethod: [
      {
        id: '#key-1',
        type: 'JsonWebKey',
        publicKeyJwk,
      },
    ],
    authentication: ['#key-1'],
    assertionMethod: ['#key-1'],
  };

  return assembleDidJwt(header, payload, (signingInput) =>
    generator.sign(signingInput, opts.privateKey),
  );
}
