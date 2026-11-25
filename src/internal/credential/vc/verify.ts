/**
 * JWT-VC（JWS）として表現された W3C VC を検証する最小プリミティブ。
 *
 * 検証手順:
 * 1. コンパクト JWS をデコードする（形式不正は `SIG_INVALID` 3010）。
 * 2. `alg=none` を拒否する（`ALG_NONE` 3011）。`ES256` / `ES256K` / `EdDSA` 以外も拒否する。
 * 3. 暗号アジリティレジストリで alg のステータスを判定する。`prohibited` は署名検証前に
 *    拒否（`VERIFY_ALGO_PROHIBITED` 3019）。`deprecated` / `sunset` は成功時に `algorithmDeprecated: true`。
 * 4. 署名を検証する（`SIG_INVALID` 3010）。検証鍵は呼び出し側が DI する（発行者 DID 解決は責務外）。
 * 5. `iat` / `exp` / `nbf` の時刻評価を `clockSkewSeconds`（既定 120s）込みで行う。スキュー超過の
 *    未来 `iat` は `CLOCK_SKEW_EXCEEDED` 4014、期限切れは `VC_EXPIRED` 3024、有効化前は
 *    `VC_NOT_YET_VALID` 3025、型不正は `VC_SCHEMA_INVALID` 3002 として拒否する。
 * 6. envelope（JWT クレーム）↔ body（内包 VC）の自己整合を検証する。`iss` / `sub` / `nbf` / `exp` /
 *    `jti` が VC 本体と食い違う場合は構造不正（`VC_SCHEMA_INVALID` 3002）として拒否する
 *    （confused deputy 対策）。VC 本体は JWT-VC 1.1 系の `vc` claim（`issuanceDate` /
 *    `expirationDate`）か、VC 2.0 系の payload 自体（`validFrom` / `validUntil`。walt.id 等）
 * のどちらでもよい（`jwt-vc-body.ts`）。
 *
 * 失効リスト（Bitstring / Token Status List）の実評価は最小スコープ外で、型のみ（`vc.ts`）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に公開鍵・VC 本文・JWT を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { assertSigningKeyNotRevoked, type IssuerTrustOption } from '../issuer-key-revocation.js';
import { assertTimeClaims, resolveClockSkewSeconds } from '../time-claims.js';
import { resolveCredentialAlgorithmDeprecation } from './algorithm-policy.js';
import type { CredentialSignerAlg, DecodedJws } from './jws.js';
import { assertAlg, decodeCompactJwsOrThrow, verifyWithKey } from './jws.js';
import { jwtVcBodyMembersOf } from './jwt-vc-members.js';
import { isoToNumericDate } from './numeric-date.js';

/**
 * 署名検証の鍵注入方法。
 *
 * 発行者 DID の解決は credential の責務外のため、検証鍵は呼び出し側が DI する:
 * - `publicKeyJwk`: 発行者の EC / OKP 公開鍵 JWK。`alg` に応じた検証関数で検証する。
 * - `verify`: 署名検証を丸ごと差し替える任意の検証関数（HSM / WebCrypto 等の脱出ハッチ）。
 *
 * いずれか一方を指定する。
 */
export type CredentialVerifierKey =
  | { readonly publicKeyJwk: PublicKeyJwk; readonly verify?: undefined }
  | {
      /**
       * 署名検証コールバック。
       *
       * - `ES256` / `ES256K`（ECDSA）: 事前ハッシュ済みの `digest`（signing-input の SHA-256）を使う。
       * - `EdDSA`（Ed25519）: 事前ハッシュを行わないため、必ず第 3 引数の `signingInput` を使う。
       *   digest で検証しようとしても署名は一致しない。
       *
       * 第 3 引数は任意パラメータ扱いのため、従来の 2 引数コールバックはそのまま渡せる
       * （TS の構造的部分型）。ECDSA 専用のコールバックが EdDSA の JWS を渡された場合は単に
       * `false` を返し、呼び出し側が `SIG_INVALID` に正規化する（フェイルクローズ。検証の
       * バイパスにはならない）。
       */
      readonly verify: (
        digest: Uint8Array,
        signature: Uint8Array,
        signingInput: Uint8Array,
      ) => boolean;
      readonly publicKeyJwk?: undefined;
    }
  | {
      /**
       * `alg: "ES256K-R"`（IANA 登録外。did:pkh / did:ethr の controller 鍵限定の標準外の例外）専用のアドレス鍵。
       * 署名（EIP-191）から公開鍵を復元してこのアドレス（小文字 `0x` + 40 hex）と照合する。ほかの alg では使えない。
       */
      readonly ethereumAddress: string;
      readonly publicKeyJwk?: undefined;
      readonly verify?: undefined;
    };

/** `verifyCredential` の入力オプション。 */
export interface VerifyCredentialOptions {
  /** 署名検証鍵（発行者公開鍵 JWK or 検証関数）。 */
  readonly key: CredentialVerifierKey;
  /** 現在時刻（エポック秒）。既定は現在時刻。テストの決定性のため注入可能とする。 */
  readonly nowSeconds?: number;
  /**
   * `iat` / `exp` / `nbf` 評価で許容するクロックスキュー秒数。既定 = 上限キャップ
   * `CLOCK_SKEW_PROFILE.vc`（120s）。0 以上 120 以下の整数のみ指定でき、
   * それ以外（キャップ超過・負値・非整数・非数値）は `CLOCK_SKEW_OPTION_INVALID`（4015）で拒否する。
   * `0` を指定すると `exp` / `nbf` の判定は本オプション導入前と同一になる（`iat` の評価は本
   * プロファイルで新設したものであり、`0` でも評価される）。
   */
  readonly clockSkewSeconds?: number;
  /**
   * 発行者について構築済みの Federation Trust Chain（FC-11）。
   *
   * 指定すると、署名検証を通した VC に対して鍵無効化宣言（`revoked_keys`）の突合が**自動的に**
   * 適用され、該当する VC は `FEDERATION_KEY_REVOKED`（5012）で拒否される。呼び出し側が
   * `assertCredentialKeyNotRevoked` を別途呼ぶ必要は無い（呼び忘れによるバイパスを構造的に塞ぐ）。
   *
   * Federation 由来の信頼を使わない検証経路（did:web 単独など）では省略する。省略時は判定しない。
   */
  readonly issuerTrust?: IssuerTrustOption;
}

/** 検証成功時に返す JWT-VC の構成要素。 */
export interface VerifiedCredential {
  /** デコード済み JWS ヘッダ。 */
  readonly header: Record<string, unknown>;
  /** デコード済み JWS ペイロード（`iss` / `sub` / `nbf` / `exp` / `vc` 等）。 */
  readonly payload: Record<string, unknown>;
  /**
   * 署名アルゴリズムが暗号アジリティレジストリ（`crypto-registry.ts`）で `deprecated` /
   * `sunset` 段階の場合 `true`。`recommended` /
   * `acceptable` なら `false`。UI 側の注意表示や再発行トリガー判断に使う。
   */
  readonly algorithmDeprecated: boolean;
}

/**
 * デコード済み JWS の署名を、DI された検証鍵で検証する。
 *
 * @param alg 検証済み alg。
 * @param decoded デコード済み JWS。
 * @param key 検証鍵（公開鍵 JWK or 検証関数）。
 * @throws 署名不一致の場合（VericertsError、code `3010`）。alg と JWK の kty / crv が食い違う場合も
 *         署名検証不成立として同じ `3010` に正規化する（`verifyWithJwkOrFalse`）。
 */
function assertSignature(
  alg: CredentialSignerAlg,
  decoded: DecodedJws,
  key: CredentialVerifierKey,
): void {
  // `key` はクラスインスタンスにもなり得る（`verify()` を prototype に持つ KMS 実装が正当）ため
  // own 限定では読めない。`verifyWithKey` は `Object.prototype` 由来の汚染値だけを除外し
  // `verify` は厳密に `true` を返したときのみ成功とする（JWT-VP と共通）。
  if (!verifyWithKey(alg, decoded, key)) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
}

/**
 * JWT envelope（JWT クレーム）↔ body（内包 VC）の自己整合を検証する。
 *
 * envelope のクレームが VC 本体（`vc` claim、または VC 2.0 系の payload 自体）と一致することを検証する。
 * 対象は VC 本体に対応物を持つ `iss` / `sub` / `jti` / `nbf` / `exp` で、`iat`（発行時刻。VC 本体に
 * 対応するフィールドが無い）
 * は意図的に対象外とする。食い違うトークン（例: `iss !== vc.issuer`）を受理すると、検証鍵が
 * 異なる発行者の VC を承認してしまう（confused deputy）。すべての不整合は構造不正
 * （`VC_SCHEMA_INVALID` 3002）として拒否する。
 *
 * 本検証は「同一トークン内の自己整合」であり時刻の妥当性判定ではないため、`clockSkewSeconds` は
 * 一切適用せず `nbf` / `exp` を厳密一致で比較する。
 *
 * @param payload デコード済み JWS payload。
 * @throws envelope と body が食い違う / `vc` が構造不正の場合（VericertsError、code `3002`）。
 */
function assertEnvelopeBinding(payload: Record<string, unknown>): void {
  // payload はデコード済み JSON（外部入力）。`payload.vc` をプロトタイプ鎖で読むと、`vc` を
  // **持たない** JWT に汚染された VC 本体が生えて envelope↔body 突合を素通りする。
  // 構造検証で読んだ own 値を**そのまま**受け取る（`vc.issuer` 等で読み直すと、own アクセサ付きの
  // VC を渡された場合に 2 度目が別の値を返し、検査した値と突合に使う値が食い違う TOCTOU になる）。
  // VP 側の `assertVerifiablePresentationMembers` → `vp-claims.ts` と同じ single-read に揃える。
  // 本体の所在と日付メンバ名は表現で決まる（`jwt-vc-members.ts` / `jwt-vc-body.ts`）。
  const { vc: bodyVc, issuer, credentialSubject, startDate, endDate } = jwtVcBodyMembersOf(payload);

  // envelope 側のクレームは**すべて** own 限定で読む。`iss` だけを own 限定にしても、
  // `sub` / `jti` / `nbf` / `exp` を鎖読みしていると、それらを**持たない** JWT に
  // `Object.prototype` 汚染で値が生え、「無いこと」を要求する側の分岐（`payload.sub !==
  // undefined` 等）が汚染値で反転して突合が壊れる。
  const iss = ownProperty<unknown>(payload, 'iss');
  const sub = ownProperty<unknown>(payload, 'sub');
  const jti = ownProperty<unknown>(payload, 'jti');
  const nbf = ownProperty<unknown>(payload, 'nbf');
  const exp = ownProperty<unknown>(payload, 'exp');

  // `id` は構造検証の対象外（構造検証が読まない任意メンバ）なので
  // ここで**一度だけ** own 限定に読む。鎖読みすると汚染値が「指定あり」に化け、対応する `jti` の
  // 有無判定が反転する。終了日時は検査済みの値をそのまま使う（読み直さない）。
  const vcId = ownProperty<string>(bodyVc, 'id');

  // iss = vc.issuer（発行時は常時設定）。
  if (iss !== issuer) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }

  // sub = vc.credentialSubject.id（string のときのみ設定。それ以外は sub なし）。
  const subjectId = ownProperty<unknown>(credentialSubject, 'id');
  if (typeof subjectId === 'string') {
    if (sub !== subjectId) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
  } else if (sub !== undefined) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }

  // jti = vc.id（ある時のみ設定。なければ jti なし）。
  if (vcId !== undefined) {
    if (jti !== vcId) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
  } else if (jti !== undefined) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }

  // nbf = isoToNumericDate(開始日時)（常時設定。日付不正は isoToNumericDate が 3002）。
  if (nbf !== isoToNumericDate(startDate)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }

  // exp = isoToNumericDate(終了日時)（ある時のみ設定。なければ exp なし）。
  if (endDate !== undefined) {
    if (exp !== isoToNumericDate(endDate)) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
  } else if (exp !== undefined) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
}

/**
 * JWT-VC（コンパクト JWS）を検証する。
 *
 * `issueCredential` で発行した JWT-VC を検証し、デコード済みヘッダ・ペイロードを返す
 * （発行 → 検証ラウンドトリップ）。発行者公開鍵 or 検証関数は `opts.key` で DI する。
 *
 * @param jwt 検証対象のコンパクト JWT-VC 文字列。
 * @param opts 検証鍵・現在時刻・クロックスキュー。
 * @returns デコード済みヘッダ・ペイロード・アルゴリズム非推奨警告フラグ。
 * @throws `clockSkewSeconds` 不正（code `4015`）/ 形式不正（code `3010`）/ `alg=none`（code `3011`）/
 *         `prohibited` アルゴリズム（code `3019`）/ 署名不一致（code `3010`）/ `issuerTrust` 指定時の
 *         鍵無効化該当（code `5012`）・不成立チェーン（code `5010`）/ 未来 `iat` のスキュー超過
 *         （code `4014`）/ 期限切れ（code `3024`）/ 有効化前（code `3025`）/ envelope↔body 不整合・
 *         `vc` 構造不正・時刻型不正（code `3002`）の場合（VericertsError）。
 */
export function verifyCredential(jwt: string, opts: VerifyCredentialOptions): VerifiedCredential {
  // オプション検証は署名検証（暗号処理）より前に済ませる（fail fast）。
  // 任意オプションは自身のプロパティに限って読む。継承値を拾うと、`nowSeconds` を
  // 省略した正当な検証で **`Object.prototype.nowSeconds` の過去時刻が「現在時刻」として使われ、
  // exp 超過の失効済み JWT-VC が受理される**。`clockSkewSeconds` も未指定なのに汚染値が
  // 許容スキューとして適用されると、時刻検証の窓が呼び出し側の意図より広がる。
  const skewSeconds = resolveClockSkewSeconds('vc', ownProperty<number>(opts, 'clockSkewSeconds'));
  const nowSeconds = ownProperty<number>(opts, 'nowSeconds');
  // 構造不正は 2001（DID 解決失敗）ではなく VC 検証 API の失敗面（3010）へ正規化する。
  const decoded = decodeCompactJwsOrThrow(jwt, ErrorCodes.SIG_INVALID);
  const alg = assertAlg(decoded.header, { allowEs256kR: true });
  const algorithmDeprecated = resolveCredentialAlgorithmDeprecation(alg);
  // `key` は JWT-VC の**署名検証鍵**。型上必須だが、型の無い JS から渡し忘れるとプロトタイプ鎖の
  // 汚染値が「渡された鍵」に化け、**攻撃者の鍵で署名が検証される**（偽造 JWT-VC の受理）。
  // `sdjwt/verify.ts` の `issuerKey` と同じクラスの欠陥。own 限定で読み、鍵でなければ 3010 へ倒す。
  // 併せて、後段の FC-11 突合キーと**同じ読み方**を共有する（読み方が食い違うと、片方だけ
  // 汚染値になる／`nonObjectPrototypeProperty(undefined, ...)` が生の TypeError を送出する）。
  const key = ownProperty<CredentialVerifierKey>(opts, 'key');
  if (key === null || typeof key !== 'object') {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  assertSignature(alg, decoded, key);
  // FC-11: 署名が確定した直後に鍵無効化宣言を突合する（未指定なら no-op）。突合キーは
  // 上位が署名した Subordinate Statement の JWKS を**検証鍵の鍵素材**で引いて決める（ヘッダや
  // JWK の `kid` ラベルは署名者＝攻撃者が決められるため使わない）。発行時刻は JWT-VC 標準の
  // `nbf` を第一候補にし、束縛されていない `iat` の後付けだけで基準時刻を動かせないようにする。
  // 突合キーは `assertSignature` と**同じ読み方**で取得しなければならない。
  // `opts.key.publicKeyJwk` をプロトタイプ鎖で読むと、own な `publicKeyJwk` を持たない
  // verify 専用の KMS 鍵（`nonObjectPrototypeProperty` が存在する当のケース）で汚染値が
  // 突合キーに化け、**FC-11 の鍵無効化検査がバイパス**される（失効鍵で署名された VC が通る）。
  const revocationKey = nonObjectPrototypeProperty<PublicKeyJwk>(key, 'publicKeyJwk');
  assertSigningKeyNotRevoked(
    decoded.payload,
    ownProperty<IssuerTrustOption>(opts, 'issuerTrust'),
    'nbf',
    revocationKey,
  );
  assertTimeClaims(decoded.payload, nowSeconds ?? Math.floor(Date.now() / 1000), skewSeconds);
  assertEnvelopeBinding(decoded.payload);
  return { header: decoded.header, payload: decoded.payload, algorithmDeprecated };
}
