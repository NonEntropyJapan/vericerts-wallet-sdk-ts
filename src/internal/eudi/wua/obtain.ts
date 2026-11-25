/**
 * Wallet Provider Backend から、デバイス鍵に結び付いた WUA を取得する。
 *
 * HTTPS で `/wua/challenge` に公開鍵を送り、受け取った challenge と nonce を署名する。
 * `/wua/issue` に assertion と任意の device posture を送り、返された `wallet_attestation` の署名、
 * 有効期限、種別、WSCD の公開鍵との一致を確認する。検証鍵には呼び出し側が信頼した `providerJwk` を使う。
 *
 * SDK は端末の attestation を取得しない。呼び出し側が渡す `devicePosture` はそのまま Provider に転送する。
 * 取得結果はメモリ上に返し、IndexedDB には保存しない。
 *
 * 通信・応答形式の失敗は `10101 WUA_FETCH_FAILED`。検証での失敗は `10102`、期限切れは `10103` を返す。
 * リダイレクト後の最終 URL にも HTTPS を要求する。
 * - 例外の `message` / `context` / `cause` に URL・応答本文・JWT・鍵素材を一切載せない。
 *   `context` は固定文字列の `reason` だけを持つ。
 */

import { signCompactJws } from '../../credential/vc/compact-jws.js';
import { buildJwsHeader, type CredentialSigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FetchLike } from '../../fetch-di.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import {
  fetchFailed,
  requestWuaChallenge,
  requestWuaIssuance,
  type WuaChallenge,
} from './obtain-http.js';
import type { WalletUnitAttestation } from './types.js';
import {
  parseWalletUnitAttestation,
  verifyWalletUnitAttestation,
  verifyWscdBinding,
} from './wua.js';

/** デバイスバインド Proof の JWS ヘッダ `typ`（本 SDK が固定）。 */
const WUA_DEVICE_BINDING_TYP = 'wua-device-binding+jwt' as const;

/**
 * `obtainWalletUnitAttestation` の入力オプション。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface ObtainWalletAttestationOptions {
  /**
   * 信頼済み Wallet Provider の署名鍵（EC 公開鍵 JWK）。
   *
   * 信頼判定（ETSI TSL / Federation / ARF Catalogue）は呼び出し側の責務で、応答が同梱する鍵は
   * 採用しない（モジュール JSDoc「信頼済み Wallet Provider 鍵は明示入力である」）。
   */
  readonly providerJwk: PublicKeyJwk;
  /**
   * デバイスバインド Proof の署名鍵（WSCD 由来鍵の署名抽象）。
   *
   * 公開鍵は `/wua/challenge` の `devicePubKey` としても送る。WebAuthn assertion の取得は
   * SDK が呼べるプラットフォーム API ではないため呼び出し側の責務である。
   */
  readonly signer: CredentialSigner;
  /** 検証時刻（NumericDate、秒）。取得した WUA の期限判定に使う。 */
  readonly nowSeconds: number;
  /**
   * WSCD（Passkey）由来の公開鍵 JWK。
   *
   * 指定時は取得した WUA の `cnf.jwk` がこの鍵にバインドされていることを検証する
   * （不一致は `10102`）。省略時はバインド検証を行わない。
   */
  readonly wscdPublicKeyJwk?: PublicKeyJwk;
  /**
   * `/wua/issue` へ転送する device posture。
   *
   * Play Integrity / App Attest は SDK が呼べるプラットフォーム API ではないため、呼び出し側が
   * 組み立てた**不透明な値**として受け取り、SDK は解釈も検証もしない。省略時は
   * `device_posture` キー自体を送らない。
   */
  readonly devicePosture?: unknown;
  /** HTTP 差し替えシーム（テスト注入・証明書ピンニング）。省略時はグローバル `fetch`。 */
  readonly fetchImpl?: FetchLike;
}

/** 検証不能（10102）を固定理由で組み立てる。鍵素材は載せない。 */
function verificationFailed(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED, { context: { reason } });
}

/**
 * `options.signer` を DI として解決し、公開鍵と併せて返す。
 *
 * `signer` は署名メソッドを持つ DI 依存なので、`fetchImpl` と同じく own 限定ではなく
 * `Object.prototype` 由来だけを弾いて読む（own 限定にすると `class Signer { sign() {…} }` の
 * ようなプロトタイプメソッド実装が無言で拒否される。`own-property.ts`「どちらのヘルパーを
 * 使うか」）。`sign` / `publicKeyJwk` を取り出せない値は `as` で下流へ流さず閉じる。
 *
 * @param options `signer` の読み取り元。
 * @returns 署名抽象と、`devicePubKey` として送る公開鍵 JWK。
 * @throws `signer` を解決できない場合（code `10101`。取得の前提が揃っていないため取得失敗側）。
 */
function resolveDeviceSigner(options: object): {
  readonly signer: CredentialSigner;
  readonly publicKeyJwk: object;
} {
  const signer = nonObjectPrototypeProperty<unknown>(options, 'signer');
  if (typeof signer !== 'object' || signer === null) {
    throw fetchFailed('signer_not_configured');
  }
  const sign = nonObjectPrototypeProperty<unknown>(signer, 'sign');
  const publicKeyJwk = nonObjectPrototypeProperty<unknown>(signer, 'publicKeyJwk');
  if (typeof sign !== 'function' || typeof publicKeyJwk !== 'object' || publicKeyJwk === null) {
    throw fetchFailed('signer_not_configured');
  }
  return { signer: signer as CredentialSigner, publicKeyJwk };
}

/**
 * デバイスバインド Proof（コンパクト JWS）を組み立てる。
 *
 * payload は `/wua/challenge` が返した `challenge` / `nonce` の 2 クレームで、Wallet Provider は
 * 自分が発行した challenge への署名であることをもってデバイスバインドを確かめる。WebAuthn
 * assertion の同梱は呼び出し側の責務（モジュール JSDoc 参照）。
 *
 * @param challenge `/wua/challenge` の応答。
 * @param signer WSCD 由来鍵の署名抽象。
 * @returns デバイスバインド Proof（コンパクト JWS）。
 * @throws 署名演算が失敗した場合（VericertsError、code `1020`）。
 */
function buildDeviceBindingProof(challenge: WuaChallenge, signer: CredentialSigner): string {
  return signCompactJws(
    buildJwsHeader(signer, WUA_DEVICE_BINDING_TYP),
    { challenge: challenge.challenge, nonce: challenge.nonce },
    signer,
  );
}

/**
 * Wallet Provider Backend から WUA を取得し、検証して返す。
 *
 * `POST <providerEndpoint>/wua/challenge` → デバイスバインド Proof 生成 →
 * `POST <providerEndpoint>/wua/issue`（いずれもタイムアウト 10 秒）で WUA JWT を取得し、
 * `parseWalletUnitAttestation` → `verifyWalletUnitAttestation`（→ `wscdPublicKeyJwk` 指定時は
 * `verifyWscdBinding`）を通した WUA だけを返す。**検証を通らない WUA は返さない**ため、
 * 呼び出し側は戻り値をそのまま現行 WUA として保持してよい。**保持先の永続化は行わない**
 * （モジュール JSDoc「未解決の仕様矛盾」参照）。
 *
 * オプションは分割代入せず own 限定で読む（`options` は呼び出し側が組み立てる値でパース境界を
 * 通らないため、鎖読みだと `providerJwk` を**指定していない**呼び出しが `Object.prototype` の
 * 汚染値を検証鍵に採る）。`providerJwk` を読み取れない場合は検証省略ではなく `10102` で閉じる。
 *
 * @param providerEndpoint Wallet Provider Backend のベース URL（HTTPS のみ）。
 * @param options 信頼済み Wallet Provider 鍵・署名鍵・検証時刻・WSCD 公開鍵・device posture・
 *                `fetch` 差し替えシーム。
 * @returns 署名・`vct`・期限（と指定時は WSCD バインド）を検証済みの WUA。
 * @throws 非 HTTPS・`signer` 未設定・ネットワーク失敗・タイムアウト・非 2xx・平文への
 *         リダイレクト・非 JSON・challenge / nonce / JWT フィールド欠落の場合
 *         （VericertsError、code `10101`、再試行可）。
 *         `providerJwk` / `nowSeconds` / `wscdPublicKeyJwk` を読み取れない場合と、署名・`vct`・
 *         WSCD バインド不正の場合（`10102`）。
 *         取得した WUA が `nowSeconds` 時点で期限切れの場合（`10103`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function obtainWalletUnitAttestation(
  providerEndpoint: string,
  options: ObtainWalletAttestationOptions,
): Promise<WalletUnitAttestation> {
  // 通信の前に入口検査を済ませる（非 HTTPS のエンドポイントへは 1 バイトも送らない）。
  if (!isPublicHttpsUrl(providerEndpoint)) {
    throw fetchFailed('non_https_endpoint');
  }
  const providerJwk = ownProperty<unknown>(options, 'providerJwk');
  if (typeof providerJwk !== 'object' || providerJwk === null) {
    throw verificationFailed('provider_key_not_configured');
  }
  const nowSeconds = ownProperty<unknown>(options, 'nowSeconds');
  if (typeof nowSeconds !== 'number' || !Number.isFinite(nowSeconds)) {
    throw verificationFailed('invalid_verification_time');
  }
  // 指定されているのに JWK として読めない値は「バインド検証を省略」ではなく失敗に倒す。
  const wscdPublicKeyJwk = ownProperty<unknown>(options, 'wscdPublicKeyJwk');
  if (
    wscdPublicKeyJwk !== undefined &&
    (typeof wscdPublicKeyJwk !== 'object' ||
      wscdPublicKeyJwk === null ||
      Array.isArray(wscdPublicKeyJwk))
  ) {
    throw verificationFailed('invalid_wscd_key');
  }
  const { signer, publicKeyJwk } = resolveDeviceSigner(options);

  const challenge = await requestWuaChallenge(providerEndpoint, publicKeyJwk, options);
  const jwt = await requestWuaIssuance(
    providerEndpoint,
    buildDeviceBindingProof(challenge, signer),
    ownProperty<unknown>(options, 'devicePosture'),
    options,
  );

  // 構造解析（10102）→ 署名・vct・期限の検証（10102 / 10103）。いずれも包み直さず伝播させる。
  const wua = parseWalletUnitAttestation(jwt);
  verifyWalletUnitAttestation(wua, providerJwk as PublicKeyJwk, nowSeconds);
  if (wscdPublicKeyJwk !== undefined) {
    // 取得した WUA が WSCD 由来鍵（cnf=K7.pub）にバインドされていること。
    verifyWscdBinding(wua, wscdPublicKeyJwk as PublicKeyJwk);
  }
  return wua;
}
