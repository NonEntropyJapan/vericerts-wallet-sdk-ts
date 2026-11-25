/**
 * Wallet ファサードの WUA 取得と現行 WUA の読み出し規則。
 *
 * `EudiFacade`（`facade.ts`）が持つ WUA 取得系メソッドのうち、**状態を持たない部分**だけを本
 * モジュールへ切り出す。現行 WUA そのもの（`currentWua`）はファサードのインスタンス状態として
 * 残し、ここには「取得の前提が揃っているか」「どう取得するか」「保持分を有効な WUA として返して
 * よいか」の 3 つと、その根拠だけを置く。切り出しの理由は 2 つある。
 *
 * 1. どれも根拠の説明が長く（fail-closed の理由・SDK と呼び出し側の責務分担・期限切れを返さない
 *    理由）、ファサードの委譲メソッド列の中に置くと「依存を束ねて薄く保つ」という `facade.ts` の
 *    性格が崩れる。
 * 2. どれもファサードの依存（ペルソナ・鍵管理・Catalogue）を必要とせず、単体で検査できる。
 *
 * 現行 WUA はファサードのメモリにのみ保持するため、セッションをまたいで再利用するには再取得が必要になる。
 */

import type { CredentialSigner } from '../../internal/credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import type { WalletUnitAttestation } from '../../internal/eudi/wua/index.js';
import {
  isWalletAttestationExpired,
  obtainWalletUnitAttestation,
  refreshWalletAttestation,
} from '../../internal/eudi/wua/index.js';
import type { FetchLike } from '../../internal/fetch-di.js';
import type { PublicKeyJwk } from '../../internal/identity/did.js';
import {
  nonObjectPrototypeProperty,
  ownProperty,
} from '../../internal/prototype-safety/own-property.js';

/** 現在時刻（NumericDate、秒）。WUA の有効期限判定と PoP 生成の時刻基準。 */
export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** `createWallet` 時に固定される、WUA 取得に関わる `WalletOptions` の部分集合。 */
export interface WuaObtainConfig {
  /** 信頼済み Wallet Provider 署名鍵（`WalletOptions.walletProviderJwk`）。 */
  readonly walletProviderJwk?: PublicKeyJwk;
  /** WSCD 由来の公開鍵 JWK（`WalletOptions.wscdPublicKeyJwk`）。設定時のみバインドを検証する。 */
  readonly wscdPublicKeyJwk?: PublicKeyJwk;
  /** HTTP 差し替えシーム（`WalletOptions.eudiFetchImpl`）。 */
  readonly fetchImpl?: FetchLike;
}

/**
 * `createWallet({ walletProviderJwk })` で与えられた信頼済み Wallet Provider 鍵を要求する。
 *
 * 信頼済み鍵が無い状態で取得すると「検証していない WUA を現行 WUA として保持する」ことになる。
 * 応答同梱の鍵で代用もしない（取得元が渡してきた鍵でその取得元の署名を検証しても何も検証した
 * ことにならない）ので、検証省略ではなく失敗に倒す（fail-closed）。
 *
 * @param walletProviderJwk `WalletOptions.walletProviderJwk`（未設定なら `undefined`）。
 * @returns 信頼済み Wallet Provider 署名鍵。
 * @throws 未設定の場合（VericertsError、code `10102`、`reason = 'provider_key_not_configured'`）。
 */
function requireProviderJwk(walletProviderJwk: PublicKeyJwk | undefined): PublicKeyJwk {
  if (walletProviderJwk === undefined) {
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED, {
      context: { reason: 'provider_key_not_configured' },
    });
  }
  return walletProviderJwk;
}

/**
 * Wallet Provider Backend から WUA を取得し、検証済みのものだけを返す。
 *
 * 取得プリミティブ `obtainWalletUnitAttestation`（`internal/eudi/wua/obtain.ts`）へ、ファサードが
 * 握っている 3 つ（信頼済み Provider 鍵・WSCD 公開鍵・`fetch` シーム）と、呼び出しごとに解決した
 * 署名鍵・現在時刻を渡すだけの薄い層である。
 *
 * **`devicePosture` は渡さない。** Play Integrity / App Attest はネイティブ実行環境の attestation
 * API であり、その評価結果は**取得のたびに**得なければ意味を持たない（古い評価結果を使い回すと
 * 「以前は健全だった端末」を現在の健全性として主張できてしまう）。ファサードが握れるのは
 * `createWallet` 時に固定された `WalletOptions` だけなので、ここから渡せる値は必ず静的になる。
 * device posture を添えたい呼び出し側は、取得プリミティブを直接呼んでその時点の値を渡すこと。
 *
 * @param providerEndpoint Wallet Provider Backend のベース URL（HTTPS のみ）。
 * @param signer challenge へ署名するアクティブペルソナの署名鍵。
 * @param config `createWallet` 由来の設定。
 * @returns 署名・`vct`・期限（設定時は WSCD バインドも）を検証済みの WUA。
 * @throws `walletProviderJwk` 未設定・検証失敗（code `10102`）、取得失敗（`10101`）、
 *         期限切れ（`10103`）の場合。
 */
export async function obtainVerifiedWua(
  providerEndpoint: string,
  signer: CredentialSigner,
  config: WuaObtainConfig,
): Promise<WalletUnitAttestation> {
  const wscdPublicKeyJwk = ownProperty<PublicKeyJwk>(config, 'wscdPublicKeyJwk');
  return obtainWalletUnitAttestation(providerEndpoint, {
    providerJwk: requireProviderJwk(ownProperty<PublicKeyJwk>(config, 'walletProviderJwk')),
    signer,
    nowSeconds: Math.floor(Date.now() / 1000),
    fetchImpl: nonObjectPrototypeProperty<FetchLike>(config, 'fetchImpl'),
    // 未設定時はキー自体を生やさない（`undefined` を載せると継承値との区別が消える）。
    ...(wscdPublicKeyJwk === undefined ? {} : { wscdPublicKeyJwk }),
  });
}

/**
 * 保持している WUA のうち、`getWalletAttestation()` が返してよいものだけを返す。
 *
 * 期限切れを返すと呼び出し側が「有効な WUA を持っている」と誤認して提示・添付に回す。保持自体は
 * 消さない（`refreshWalletAttestation` が旧 WUA を WSCD バインドの照合基準に要求するため）。
 *
 * @param wua 保持している現行 WUA（未取得なら `null`）。
 * @param nowSeconds 現在時刻（NumericDate、秒）。
 * @returns 期限内の WUA。未取得・期限切れなら `null`。
 */
export function activeWua(
  wua: WalletUnitAttestation | null,
  nowSeconds: number,
): WalletUnitAttestation | null {
  return wua === null || isWalletAttestationExpired(wua, nowSeconds) ? null : wua;
}

/**
 * 現行 WUA を保持要件だけで返す（期限切れは許容。`refreshCurrentWua` が使う）。リフレッシュは
 * 期限切れ WUA を差し替える経路そのものなので、旧 WUA は `cnf.jwk` の照合基準として使えれば足りる。
 *
 * @throws 現行 WUA を保持していない場合（VericertsError、code `10101`、再試行可）。
 */
export function requireWua(wua: WalletUnitAttestation | null): WalletUnitAttestation {
  if (wua === null) {
    throw new VericertsError(ErrorCodes.WUA_FETCH_FAILED, {
      context: { reason: 'wallet_attestation_unavailable' },
    });
  }
  return wua;
}

/**
 * 現行 WUA を、期限内であることまで確認して返す（`buildWuaProofOfPossession` / `attestationBuilder`
 * が使う）。期限切れの現行 WUA では PoP を生成しない（`getWalletAttestation()` が期限切れを
 * `null` にするのと同じ不変条件）。
 *
 * @throws 現行 WUA を保持していない場合（`10101`、再試行可）、保持分が期限切れの場合
 *         （`10103`、再試行可）。
 */
export function requireActiveWua(
  wua: WalletUnitAttestation | null,
  nowSeconds: number,
): WalletUnitAttestation {
  const active = activeWua(requireWua(wua), nowSeconds);
  if (active === null) {
    throw new VericertsError(ErrorCodes.WUA_LIFETIME_EXPIRED, {
      context: { reason: 'wallet_attestation_expired' },
    });
  }
  return active;
}

/**
 * 期限切れ（または期限が近い）WUA を、Wallet Provider が再発行した新 WUA JWT へ差し替える
 * 新 WUA JWT の取得（Wallet Provider
 * Backend への再取得リクエスト）は本 SDK の責務外のため呼び出し側が用意する。`walletProviderJwk`
 * 未設定の判定はここで行う（`obtainVerifiedWua` と同じ理由: 検証していない WUA を現行 WUA として
 * 保持することになるため）。実体は `internal/eudi/wua/wua.ts` の `refreshWalletAttestation`。
 *
 * @throws `walletProviderJwk` 未設定・新 WUA の署名 / `vct` / WSCD バインド不正の場合（`10102`）、
 *         新 WUA が期限切れの場合（`10103`）。
 */
export function refreshCurrentWua(
  previous: WalletUnitAttestation,
  refreshedJwt: string,
  walletProviderJwk: PublicKeyJwk | undefined,
  nowSeconds: number,
): WalletUnitAttestation {
  return refreshWalletAttestation(
    previous,
    refreshedJwt,
    requireProviderJwk(walletProviderJwk),
    nowSeconds,
  );
}
