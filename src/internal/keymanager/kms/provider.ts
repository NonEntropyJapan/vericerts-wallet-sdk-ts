/**
 * KMS / HSM トランスポート層の DI seam（`KmsProvider`）と JWS 署名 seam への橋渡し
 * （`createKmsSigner`）。
 *
 * PKCS#11 v3.0 や KMIP 1.4 以上などへの接続は、呼び出し側が `KmsProvider` を通じて提供する。
 *
 * ## `createRemoteSigner` との関係（署名抽象を二重に作らない）
 *
 * 本モジュールは **JWS 署名 seam を新設しない**。署名の入出力表現の吸収（事前ハッシュ・DER →
 * raw 変換・署名長検証・low-S 正規化）はすべて `createRemoteSigner`が担い、
 * `createKmsSigner` はその設定を組み立てて委譲するだけの薄い橋である。
 *
 * ```text
 * KmsProvider          … トランスポート層（PKCS#11 / KMIP / クラウド KMS への接続と鍵メタデータ解決）
 *      ↓ createKmsSigner
 * createRemoteSigner   … JWS 署名 seam（表現変換・正準化）   ← 唯一の署名抽象
 *      ↓
 * AsyncCredentialSigner … issueCredentialAsync / createSdJwtAsync が受け取る形
 * ```
 *
 * `createRemoteSigner` は呼び出し側が `alg` / `publicKeyJwk` / 表現形式を**すでに知っている**
 * 前提の API である。`KmsProvider` が上に足すのはその一点、すなわち **鍵メタデータをバックエンド
 * から解決する `getKey`** であり、これが PKCS#11 の `C_GetAttributeValue` / KMIP の `Get Attributes`
 * に対応する。署名操作そのものは `sign` としてトランスポート呼び出しに徹する。
 *
 * ## SDK が実装しない範囲（利用側の責務）
 *
 * SDK は `KmsProvider` **インターフェースと配線のみ**を提供し、PKCS#11 / KMIP の
 * **実プロトコル実装は持たない**。`NonceStoreAdapter`（`auth/nonce/types.ts`）と同じ
 * DI seam 方針である。理由:
 *
 * - PKCS#11 v3.0 はネイティブ共有ライブラリ（`.so` / `.dll`）の FFI ロードを要する。SDK は
 *   ブラウザ拡張と Node / Bun / Deno の双方を対象とするため、ネイティブ依存を持てない。
 * - KMIP 1.4+ は生 TCP + TLS ソケットと TTLV コーデックを要し、同じくブラウザで動作しない。
 * - 認証情報（PKCS#11 の PIN / KMIP のクライアント証明書）の保持は利用側の運用責務であり、
 *   SDK がステートフルな接続プールを抱えるべきではない。
 *
 * AWS CloudHSM / Google Cloud HSM / Azure Dedicated HSM / YubiHSM 2 はいずれも PKCS#11 を
 * 提供するため、利用側は 1 つの PKCS#11 adapter を `KmsProvider` として実装すればこれら 4 つと
 * PKCS#11 v3.0 を賄えるが、KMIP 1.4+ は別プロトコル（TTLV over TLS）のため別途 KMIP adapter の
 * 実装が必要である。
 *
 * セキュリティ上の注意:
 * - 秘密鍵 material は `KmsProvider` の境界を越えない。SDK が受け取るのは公開鍵 JWK と署名
 *   バイト列だけである。
 * - `getKey` / `sign` が投げた例外は SDK の例外へ `cause` も `context` も伝播させない。
 *   バックエンド由来の例外メッセージには鍵ハンドル・PIN・署名対象が埋め込まれ得る。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import {
  createRemoteSigner,
  type RemoteMessageFormat,
  type RemoteSignatureFormat,
} from '../jws/remote-signer.js';
import type { AsyncCredentialSigner, CredentialAlg } from '../jws/signer-types.js';

/**
 * KMS / HSM が保持する 1 本の署名鍵のメタデータ（`KmsProvider.getKey` の戻り値）。
 *
 * PKCS#11 なら `C_GetAttributeValue`（`CKA_KEY_TYPE` / `CKA_EC_POINT` / `CKA_ID`）、
 * KMIP なら `Get Attributes` + `Get`（公開鍵）で解決される値に対応する。
 */
export interface KmsKeyDescriptor {
  /** 鍵に対応する JWS 署名アルゴリズム（`ES256` / `ES256K` / `EdDSA`）。 */
  readonly alg: CredentialAlg;
  /** 署名鍵に対応する公開鍵 JWK（EC または OKP）。検証側へ受け渡すため公開。 */
  readonly publicKeyJwk: PublicKeyJwk;
  /**
   * JWS ヘッダへ載せる鍵 ID（`kid`）。未指定ならヘッダに `kid` を出力しない。
   *
   * `getKey` に渡した `keyId` を自動で `kid` へ流用することはしない。バックエンド内部の
   * 鍵ハンドルを公開 credential へ露出するかは利用側の判断だからである。
   */
  readonly kid?: string;
  /**
   * バックエンドへ渡す署名対象の表現。既定 `'signing-input'`。
   *
   * 事前ハッシュを要求するバックエンド（AWS KMS `MessageType=DIGEST` 等）では `'digest'`。
   */
  readonly messageFormat?: RemoteMessageFormat;
  /**
   * バックエンドが返す署名の表現。既定 `'raw'`。
   *
   * PKCS#11 の `CKM_ECDSA` は 64 バイト raw を返すが、KMIP や一部クラウド KMS は ASN.1 DER を
   * 返すため、その場合は `'der'` を指定する。
   */
  readonly signatureFormat?: RemoteSignatureFormat;
}

/**
 * KMS / HSM バックエンドへの最小依存（DI seam）。
 *
 * SDK はこのインターフェースだけに依存し、PKCS#11 モジュールのロードや KMIP セッション管理は
 * 実装側（adapter）が担う。`NonceStoreAdapter` と同じく構造型として最小限のメソッドのみを要求する。
 *
 * **実装上の要件:**
 * - `sign` は秘密鍵を SDK へ返してはならない。返すのは署名バイト列のみである。
 * - `getKey` が返す `publicKeyJwk` は `sign` が実際に使う鍵と一致していなければならない。
 *   不一致は発行後の検証失敗（`3010`）として現れ、SDK 側では検知できない。
 * - セッション確立・再接続・PIN 入力・接続プールはすべて adapter の責務である。
 */
export interface KmsProvider {
  /**
   * 鍵ハンドルからメタデータを解決する。
   *
   * @param keyId バックエンド内の鍵識別子（PKCS#11 の `CKA_ID` / `CKA_LABEL`、
   *              KMIP の Unique Identifier、クラウド KMS の鍵 ARN 等）。
   * @returns 鍵のメタデータ。
   */
  getKey(keyId: string): Promise<KmsKeyDescriptor>;
  /**
   * 鍵ハンドルを指定して署名する。
   *
   * @param keyId `getKey` と同じ鍵識別子。
   * @param message `KmsKeyDescriptor.messageFormat` に従った署名対象バイト列。
   * @returns `KmsKeyDescriptor.signatureFormat` に従った署名バイト列。
   */
  sign(keyId: string, message: Uint8Array): Promise<Uint8Array>;
}

/** `messageFormat` に許される値（型と乖離しないよう `satisfies` で束縛する）。 */
const MESSAGE_FORMATS = [
  'signing-input',
  'digest',
] as const satisfies readonly RemoteMessageFormat[];

/** `signatureFormat` に許される値（同上）。 */
const SIGNATURE_FORMATS = ['raw', 'der'] as const satisfies readonly RemoteSignatureFormat[];

/**
 * 省略可能な列挙値を検査する（`undefined` は既定値へのフォールバックとして許容）。
 *
 * 対応表オブジェクトではなく配列 + `includes` で照合する。オブジェクトリテラルの参照は
 * プロトタイプ経由（`'toString'` 等）で真になり、ガードが不発になるためである。
 */
function isOptionalEnum(value: unknown, allowed: readonly string[]): boolean {
  return value === undefined || (typeof value === 'string' && allowed.includes(value));
}

/**
 * 公開鍵 JWK を検証済みの平坦なオブジェクトとして写し取る（非配列オブジェクトかつ非空 `kty`）。
 *
 * `typeof value === 'object'` だけでは配列・`Uint8Array`・`{}` が素通りしてしまうため、
 * JWK であれば必ず存在する `kty`（RFC 7517 §4.1）の有無まで見る。
 *
 * 検証の**前に**自身の列挙可能プロパティを新しいオブジェクトへ写す。元の値が getter を持つ場合、
 * 検証時と利用時で別の値を返し得る（TOCTOU）ためで、写し取った後は取得済みの値だけを見る。
 */
function snapshotPublicKeyJwk(value: unknown): PublicKeyJwk | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return undefined;
  }
  // getter を再評価させないため、検証前に値を確定させる。プロトタイプを持たない器へ写すことで、
  // `Object.prototype` が汚染されていても継承プロパティを拾わない。
  const jwk = Object.assign(
    Object.create(null) as Record<string, unknown>,
    value as Record<string, unknown>,
  );
  const { kty } = jwk;
  return isNonEmptyString(kty) ? (jwk as PublicKeyJwk) : undefined;
}

/**
 * `getKey` の戻り値を検証し、**検証した値そのもの**を鍵メタデータとして写し取る。
 *
 * `KmsProvider` は外部（JS 実装も含む）から注入されるため、型注釈だけでは実行時の欠損を防げない。
 * 検証不能な JWS を発行してしまう経路を構築時に断つのが目的で、次をすべて要求する:
 *
 * - `value` が配列でないオブジェクトであること。
 * - `publicKeyJwk` が配列でないオブジェクトで、非空文字列の `kty` を持つこと。
 * - `kid` が指定されていれば `string` であること（未指定は許容）。
 * - `messageFormat` / `signatureFormat` が指定されていれば所定の列挙値であること（未指定は許容）。
 *   綴り誤りが黙って既定値へ縮退し、発行時まで表面化しないのを防ぐ。
 *
 * `alg` の妥当性は検査しない（`createRemoteSigner` が `1030` で弾くため委譲する）。
 *
 * **各プロパティは 1 回だけ読み、以降は写し取った値だけを使う。** 検証してから呼び出し側が
 * 元オブジェクトを読み直すと、読むたびに違う値を返す getter を仕込んだ `KmsProvider` が
 * ガードを通過したうえで未検証の値を signer 構成へ流し込めてしまう（TOCTOU）。戻り値を
 * `boolean` ではなく写し取り済みオブジェクトにしているのは、この読み直しを型の上で不可能に
 * するためである。
 */
function snapshotKeyDescriptor(value: unknown): KmsKeyDescriptor | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return undefined;
  }
  // 自身の列挙可能プロパティだけを 1 回で写し取る。getter の再評価を防ぐと同時に、写し先を
  // プロトタイプなしにすることで `Object.prototype` 汚染由来の値（継承した messageFormat 等）が
  // 混入するのも防ぐ（通常のオブジェクトリテラルへ写すと継承プロパティを拾ってしまう）。
  const source = Object.assign(
    Object.create(null) as Record<string, unknown>,
    value as Record<string, unknown>,
  );
  // 以降で参照するのはこの写しだけ。元の value を二度読みしない。
  const { alg, kid, messageFormat, signatureFormat } = source;
  const publicKeyJwk = snapshotPublicKeyJwk(source.publicKeyJwk);

  if (publicKeyJwk === undefined) {
    return undefined;
  }
  if (kid !== undefined && typeof kid !== 'string') {
    return undefined;
  }
  if (
    !isOptionalEnum(messageFormat, MESSAGE_FORMATS) ||
    !isOptionalEnum(signatureFormat, SIGNATURE_FORMATS)
  ) {
    return undefined;
  }
  return {
    alg: alg as CredentialAlg,
    publicKeyJwk,
    kid,
    messageFormat: messageFormat as RemoteMessageFormat | undefined,
    signatureFormat: signatureFormat as RemoteSignatureFormat | undefined,
  };
}

/**
 * `KmsProvider` から `AsyncCredentialSigner` を生成する（KMS / HSM 発行経路の入口）。
 *
 * `provider.getKey(keyId)` で鍵メタデータを解決し、その内容を `createRemoteSigner` の設定へ
 * 写して signer を組み立てる。署名時は `provider.sign(keyId, message)` が呼ばれる。
 * 署名の表現変換・長さ検証・low-S 正規化はすべて `createRemoteSigner` 側で行われるため、
 * 本関数は独自の署名処理を一切持たない。
 *
 * 戻り値は `issueCredentialAsync` / `createSdJwtAsync` / `issuePresentationAsync` /
 * `signStatusListTokenAsync` にそのまま渡せる。
 *
 * @param provider PKCS#11 / KMIP / クラウド KMS への adapter。
 * @param keyId バックエンド内の鍵識別子。
 * @returns 解決済みメタデータで構成された `AsyncCredentialSigner`。
 * @throws `provider.getKey` が失敗した、または戻り値が鍵メタデータの形（配列でないオブジェクトで
 *         あり、非空 `kty` を持つ配列でないオブジェクトの `publicKeyJwk` を持ち、`kid` /
 *         `messageFormat` / `signatureFormat` が指定されていれば所定の型・列挙値であること）を
 *         満たさない場合（VericertsError、code `1004`）。
 * @throws 解決された `alg` が `ES256` / `ES256K` / `EdDSA` 以外、または `alg: 'EdDSA'` に
 *         `messageFormat: 'digest'` / `signatureFormat: 'der'` が組み合わされた場合
 *         （VericertsError、code `1030`）。
 */
export async function createKmsSigner(
  provider: KmsProvider,
  keyId: string,
): Promise<AsyncCredentialSigner> {
  let descriptor: KmsKeyDescriptor | undefined;
  try {
    const resolved = await provider.getKey(keyId);
    // 検証と同時に値を写し取る。以降 resolved は二度と読まない（getter による TOCTOU の遮断）。
    // 写し取りは try の内側で行う。descriptor の getter が throw する実装（遅延解決する
    // PKCS#11 adapter 等）でも、その例外メッセージに鍵ハンドル・PIN が載り得るためである。
    descriptor = snapshotKeyDescriptor(resolved);
  } catch {
    // バックエンド由来の例外メッセージに鍵ハンドル・PIN が含まれ得るため cause は渡さない。
    throw new VericertsError(ErrorCodes.KEY_NOT_FOUND);
  }
  if (descriptor === undefined) {
    // 解決できた値の中身は例外に含めない。
    throw new VericertsError(ErrorCodes.KEY_NOT_FOUND);
  }

  // 署名処理は createRemoteSigner に委譲する（本モジュールは署名抽象を持たない）。
  return createRemoteSigner({
    alg: descriptor.alg,
    publicKeyJwk: descriptor.publicKeyJwk,
    kid: descriptor.kid,
    messageFormat: descriptor.messageFormat,
    signatureFormat: descriptor.signatureFormat,
    sign: (message) => provider.sign(keyId, message),
  });
}
