/**
 * KMS / HSM / 外部署名サービス向けの Remote Signer アダプタ（`createRemoteSigner`）。
 *
 * 秘密鍵 material を SDK へ渡さずに JWT-VC / SD-JWT VC を発行するための seam。呼び出し側は
 * 「署名対象バイト列を受け取り署名バイト列を返す関数」だけを提供すればよく、SDK は署名鍵を
 * 一切保持しない。AWS KMS / GCP KMS / Azure Key Vault のように署名 API の入出力表現が異なる
 * サービスを吸収するため、以下の 2 軸を設定で切り替えられる:
 *
 * | 設定              | 既定             | 用途                                                     |
 * | ----------------- | ---------------- | -------------------------------------------------------- |
 * | `messageFormat`   | `signing-input`  | `digest` にすると SHA-256 済み 32B を渡す（KMS の `DIGEST`）|
 * | `signatureFormat` | `raw`（64B r\\|\\|s）| `der` にすると DER 署名を 64B raw へ変換する（KMS / PKCS#11）|
 *
 * 生成した signer は `AsyncCredentialSigner` として `issueCredentialAsync` /
 * `createSdJwtAsync` にそのまま渡せる。
 *
 * 外部サービスが返した ECDSA 署名の `s` は必ず low-S（`s <= n/2`）へ正規化してから返す。KMS / HSM は
 * high-S 署名を正当に返し得る。SDK の JWS 検証経路は ES256 の high-S を受理するが、ES256K は
 * low-S のみを受理し、署名バイト列を識別子に使う経路（DPoP / did:jwt）も low-S を要求するため、
 * 発行側は常に low-S へ揃える。
 *
 * `EdDSA`（Ed25519）は PureEdDSA のため上記 2 軸の非既定値を受け付けない。事前ハッシュした digest に
 * 署名すると SDK の検証経路（signing-input そのものを検証）と一致せず、また Ed25519 署名は 64B の
 * `R || S` 固定で DER 表現を持たない。したがって `messageFormat: 'digest'` /
 * `signatureFormat: 'der'` は構築時に `UNSUPPORTED_ALGORITHM`（1030）で弾く。`S` は Ed25519 の
 * 仕様上すでに正準（`S < L`）であり、ECDSA の low-S 正規化は適用しない。
 *
 * セキュリティ上の注意:
 * - 外部署名関数が投げた例外は `SIGN_FAILED`（1020）へ正規化し、`cause` も `context` も付けない。
 *   外部サービス由来の例外メッセージには鍵 ID・鍵 material・署名対象（signing-input）が
 *   埋め込まれ得るため、SDK の例外へ一切伝播させない。
 * - 署名バイト列・署名対象・digest を例外メッセージや `context` に含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import {
  derToP1363,
  type EcdsaCurve,
  normalizeLowS,
  P1363_LENGTH,
} from '../ecdsa/signature-format.js';
import type { AsyncCredentialSigner, CredentialAlg } from './signer-types.js';

/** 外部署名サービスが返す署名の表現。`raw` = 64B `r || s`、`der` = ASN.1 DER。 */
export type RemoteSignatureFormat = 'raw' | 'der';

/** 外部署名サービスへ渡す署名対象の表現。`signing-input` = 生バイト列、`digest` = SHA-256 済み 32B。 */
export type RemoteMessageFormat = 'signing-input' | 'digest';

/** ECDSA ベースの JWS 署名アルゴリズム（`EdDSA` を除いた `CredentialAlg`）。 */
type EcdsaCredentialAlg = Exclude<CredentialAlg, 'EdDSA'>;

/**
 * alg → 署名変換に用いる ECDSA 曲線。
 *
 * `EdDSA` は ECDSA ではないため本表に持たない（曲線非依存の PureEdDSA 経路を通す）。
 *
 * `ALG_SPECS`（`identity/jwt/jwk-key.ts`）と同じ理由でプロトタイプを持たないオブジェクトとして
 * 構築する。通常のオブジェクトリテラルだと `alg: "constructor"` / `"toString"` 等が
 * `Object.prototype` にヒットし、`curve === undefined` の未対応 alg ガードをすり抜けて
 * `createRemoteSigner` が 1030 を投げずに signer を返してしまう。
 */
const ALG_CURVES: Record<EcdsaCredentialAlg, EcdsaCurve> = Object.assign(
  Object.create(null) as Record<EcdsaCredentialAlg, EcdsaCurve>,
  {
    ES256: 'p256',
    ES256K: 'secp256k1',
  } satisfies Record<EcdsaCredentialAlg, EcdsaCurve>,
);

/** `createRemoteSigner` の設定。 */
export interface RemoteSignerConfig {
  /** JWS 署名アルゴリズム（`ES256` = P-256 / `ES256K` = secp256k1 / `EdDSA` = Ed25519）。 */
  readonly alg: CredentialAlg;
  /** 外部鍵に対応する EC 公開鍵 JWK（`EdDSA` では OKP / Ed25519 JWK。検証側へ受け渡すため公開）。 */
  readonly publicKeyJwk: PublicKeyJwk;
  /** JWS ヘッダへ載せる鍵 ID（`kid`）。未指定なら header に `kid` を出力しない。 */
  readonly kid?: string;
  /**
   * 既定 `'signing-input'`。`'digest'` の場合 adapter が SHA-256 して 32B digest を渡す
   * （AWS KMS `MessageType=DIGEST` 等）。`alg: 'EdDSA'` では `'digest'` を指定できない。
   */
  readonly messageFormat?: RemoteMessageFormat;
  /**
   * 既定 `'raw'`（64B `r || s`。`EdDSA` では `R || S`）。`'der'` の場合 adapter が `derToP1363` で
   * 変換する（AWS KMS / PKCS#11 等）。`alg: 'EdDSA'` では `'der'` を指定できない。
   */
  readonly signatureFormat?: RemoteSignatureFormat;
  /**
   * 外部署名サービス呼び出し。秘密鍵 material は SDK に渡さない。
   * @param message `messageFormat` に従った署名対象バイト列。
   * @returns `signatureFormat` に従った署名バイト列（同期・非同期いずれも可）。
   */
  sign(message: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

/**
 * 外部署名関数から `AsyncCredentialSigner` を生成する（KMS / HSM adapter）。
 *
 * 返る signer の `sign` は signing-input を受け取り、`messageFormat` に応じて必要なら SHA-256 を
 * 取ってから `config.sign` を呼び、`signatureFormat` に応じて DER を 64B raw へ変換し、長さが
 * 64 バイトであることを検証したうえで（ECDSA のみ）`s` を low-S へ正規化して返す。外部関数の失敗・
 * 戻り値不正・署名長不正・正規化失敗はすべて `SIGN_FAILED`（1020）へ正規化し、秘密情報を含み得る
 * `cause` / `context` は付けない。
 *
 * `alg: 'EdDSA'` では PureEdDSA のため signing-input をそのまま外部署名関数へ渡し、64B `R || S` を
 * そのまま返す（low-S 正規化なし）。
 *
 * @param config alg / publicKeyJwk / kid / 表現形式 / 外部署名関数。
 * @returns `issueCredentialAsync` / `createSdJwtAsync` に渡せる `AsyncCredentialSigner`。
 * @throws `alg` が `ES256` / `ES256K` / `EdDSA` 以外の場合、または `alg: 'EdDSA'` に
 *         `messageFormat: 'digest'` / `signatureFormat: 'der'` を指定した場合
 *         （VericertsError、code `1030`）。
 */
export function createRemoteSigner(
  config: RemoteSignerConfig,
): AsyncCredentialSigner<CredentialAlg> {
  // 省略時の既定値へ落とすオプションは、自身のプロパティのときだけ読む。`config.messageFormat`
  // と直接書くとプロトタイプ鎖を辿るため、`Object.prototype` が汚染されていると「省略した」
  // つもりの呼び出しが `digest` / `der` として扱われ、署名対象が黙って変わる。
  const messageFormat =
    ownProperty<RemoteMessageFormat>(config, 'messageFormat') ?? 'signing-input';
  const signatureFormat = ownProperty<RemoteSignatureFormat>(config, 'signatureFormat') ?? 'raw';
  // alg は型の上では閉じた union だが、JS からの呼び出しや外部 adapter 経由では任意の値が来る。
  // 文字列以外を許すと `ALG_CURVES[alg]` の添字アクセスで `toString()` へ暗黙変換されてガードを
  // 通過し、そのオブジェクトが JWS ヘッダ生成時に `JSON.stringify`（`toJSON`）で**別の値**へ
  // 化け得る（例: 照合は ES256、ヘッダは EdDSA）。読み取りのたびに値が変わる余地を断つため、
  // まず文字列であることを要求し、以降は確定した `alg` だけを使う。
  const alg = ownProperty<CredentialAlg>(config, 'alg');
  if (typeof alg !== 'string') {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  // EdDSA は ECDSA 用の 2 軸（事前ハッシュ・DER）を持たない。digest に署名すると検証経路
  // （signing-input そのものを検証）と一致せず、Ed25519 署名に DER 表現も存在しないため、
  // 誤設定を発行時ではなく構築時点で弾く。
  const isEdDSA = alg === 'EdDSA';
  if (isEdDSA && (messageFormat !== 'signing-input' || signatureFormat !== 'raw')) {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  const curve = isEdDSA ? undefined : ALG_CURVES[alg as EcdsaCredentialAlg];
  // 未対応アルゴリズム（将来の alg 追加時の取りこぼしを含む）を構築時点で弾く。
  if (!isEdDSA && curve === undefined) {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }

  const sign = async (signingInput: Uint8Array): Promise<Uint8Array> => {
    const message = messageFormat === 'digest' ? sha256(signingInput) : signingInput;
    let result: unknown;
    try {
      result = await config.sign(message);
    } catch {
      // 外部サービス由来の例外メッセージに鍵 ID・署名対象が含まれ得るため cause は渡さない。
      throw new VericertsError(ErrorCodes.SIGN_FAILED);
    }
    if (!(result instanceof Uint8Array)) {
      throw new VericertsError(ErrorCodes.SIGN_FAILED);
    }
    // DER の場合のみ raw へ変換する（derToP1363 はパース失敗を 1020 に正規化済み）。
    const raw =
      signatureFormat === 'der' && curve !== undefined ? derToP1363(result, curve) : result;
    if (raw.length !== P1363_LENGTH) {
      // 署名バイト列は例外に含めない。
      throw new VericertsError(ErrorCodes.SIGN_FAILED);
    }
    // Ed25519 の S は仕様上すでに正準（S < L）のため ECDSA の low-S 正規化は適用しない。
    if (curve === undefined) {
      return raw;
    }
    // KMS / HSM は high-S 署名を正当に返し得るため、JWS へ載せる前に low-S へ揃える。
    return normalizeLowS(raw, curve);
  };

  // kid 未設定時はプロパティ自体を生やさない（`kid: undefined` を JWS ヘッダ判定へ持ち込まない）。
  // 分割代入（`const { kid } = config`）はプロトタイプ鎖を辿るため、`kid` を省略した正当な
  // 呼び出しでも `Object.prototype.kid` の汚染値を拾い、それを signer の**自身のプロパティ**として
  // 載せてしまう。すると `buildJwsHeader` の `Object.hasOwn` ガードが素通りし、攻撃者が選んだ
  // 鍵 ID が JWS ヘッダに載る。`ownProperty` で自身のプロパティに限って読むことでこれを断つ。
  const kid = ownProperty<string>(config, 'kid');
  // publicKeyJwk は型の上では必須のため、自身のプロパティが無いのは呼び出し側の契約違反。
  // 汚染値を公開鍵として引き渡さないよう、継承値は拾わず undefined のまま通す。
  const publicKeyJwk = ownProperty<PublicKeyJwk>(config, 'publicKeyJwk') as PublicKeyJwk;
  return kid !== undefined ? { alg, publicKeyJwk, kid, sign } : { alg, publicKeyJwk, sign };
}
