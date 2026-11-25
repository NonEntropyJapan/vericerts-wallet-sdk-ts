/**
 * EUDI の受領 / 提示フローへ渡す依存（DI オブジェクト）の組み立て規則。
 *
 * `EudiFacade` の関心は「WUA の保持」と「PID / (Q)EAA の受領・提示」であり、下流フローへ渡す
 * 依存をどう組むかはそれとは独立した関心事なので本モジュールへ分ける。とくに **`fetchImpl` は
 * 値が `undefined` でも必ず own プロパティとして載せる**という規則（載せずに省略すると下流の DI
 * 解決がリテラルのプロトタイプ鎖を辿って `Object.prototype.fetchImpl` を掴む）は受領・提示の
 * 両経路で共通であり、片方だけに書くと退行が生まれる。
 */

import type { ReceiveDeps } from '../../internal/auth/eudi/issuance/index.js';
import type { PresentDeps } from '../../internal/auth/eudi/presentation/index.js';
import type { CredentialSigner } from '../../internal/credential/vc/signer.js';
import type { ClientAttestation, WalletUnitAttestation } from '../../internal/eudi/wua/index.js';
import {
  buildClientAttestation,
  buildWuaProofOfPossession,
} from '../../internal/eudi/wua/index.js';
import type { FetchLike } from '../../internal/fetch-di.js';
import type { KeyManager } from '../../internal/keymanager/keymanager.js';
import type { Metrics } from '../../internal/observability/metrics.js';
import type { PersonaManager } from '../../internal/persona/persona.js';
import {
  nonObjectPrototypeProperty,
  ownProperty,
} from '../../internal/prototype-safety/own-property.js';
import type { QtspServiceCertificate } from '../../internal/trust/etsi-tsl/index.js';
import { type ActiveSignerOptions, resolveActiveHolder } from '../setup.js';
import { jarTrustOf } from './rp-trust.js';
import { nowSeconds, requireActiveWua } from './wua-holder.js';

/** 依存の組み立てに必要な、`EudiFacade` が生成時に受け取る不変の材料。 */
export interface EudiDepsContext {
  readonly personas: PersonaManager;
  readonly keymanager: KeyManager;
  readonly metrics: Metrics;
  readonly fetchImpl?: FetchLike;
  readonly rpTrustAnchors?: readonly QtspServiceCertificate[];
  /** 取り込んだ DID のペルソナで署名するための Resolver・外部秘密鍵の提供元。 */
  readonly signing?: ActiveSignerOptions;
}

/**
 * 現行 WUA から `client_assertion` の組み立て関数を作る。
 *
 * WUA 未保持の判定は**ここで即座に**行い、通信を 1 回も起こさずに `10101`（再試行可）へ倒す
 * （期限切れも同様に即座へ倒す。`requireActiveWua` の不変条件）。一方 WUA-PoP の生成は返した
 * 関数の中で遅延させる。`aud` は「実際に Token Request を送る Token Endpoint」でなければならず
 * その値が確定するのは受領フロー内部だからである（`internal/auth/eudi/issuance/types.ts` の
 * `buildClientAttestation`）。
 *
 * リプレイを防ぐため、受領フローは AS の Nonce Endpoint から取得した `c_nonce` を
 * 第 2 引数で渡す。Issuer が Nonce Endpoint を告知していなければ、受領フローは `8010` で失敗し、
 * PoP を送信しない。
 *
 * @param signer WUA `cnf.jwk` に対応する署名鍵。
 * @param currentWua `EudiFacade` が保持する現行 WUA（未取得なら `null`）。
 * @returns Token Endpoint と AS 発行 `c_nonce` を受け取り `client_assertion` を返す関数。
 * @throws 現行 WUA を保持していない場合（VericertsError、code `10101`、再試行可）、
 *         保持分が期限切れの場合（code `10103`、再試行可）。
 */
function attestationBuilder(
  signer: CredentialSigner,
  currentWua: WalletUnitAttestation | null,
): (aud: string, nonce: string) => ClientAttestation {
  const wua = requireActiveWua(currentWua, nowSeconds());
  return (aud: string, nonce: string): ClientAttestation =>
    buildClientAttestation(
      wua,
      buildWuaProofOfPossession(wua, { aud, nonce }, signer, nowSeconds()),
    );
}

/**
 * 受領フローの依存を組み立てる。
 *
 * @param ctx 生成時に確定している依存材料。
 * @param currentWua 現行 WUA（`withAttestation` が `true` のときだけ参照する）。
 * @param withAttestation Token Request に WUA を添付するか。
 * @throws アクティブペルソナ未設定（code `2005`）、WUA 未保持での添付要求（`10101`）の場合。
 */
export async function buildReceiveDeps(
  ctx: EudiDepsContext,
  currentWua: WalletUnitAttestation | null,
  withAttestation: boolean,
): Promise<ReceiveDeps> {
  const { signer, did, keyId } = await resolveActiveHolder(
    ctx.personas,
    ctx.keymanager,
    ownProperty<ActiveSignerOptions>(ctx, 'signing'),
  );
  return {
    signer,
    holderDid: did,
    keyId,
    fetchImpl: nonObjectPrototypeProperty<EudiDepsContext['fetchImpl']>(ctx, 'fetchImpl'),
    metrics: ctx.metrics,
    // 添付しない場合はキー自体を生やさない（`undefined` を載せると継承値との区別が消える）。
    ...(withAttestation ? { buildClientAttestation: attestationBuilder(signer, currentWua) } : {}),
  };
}

/**
 * 提示フローの依存を組み立てる。`SubmitFetchLike` は `FetchLike` より init が 1 フィールド
 * 広いだけなので後者をそのまま渡せる（`jarTrust` の根拠は `rp-trust.ts`）。
 *
 * @throws アクティブペルソナ未設定の場合（VericertsError、code `2005`）。
 */
export async function buildPresentDeps(ctx: EudiDepsContext): Promise<PresentDeps> {
  const { signer } = await resolveActiveHolder(
    ctx.personas,
    ctx.keymanager,
    ownProperty<ActiveSignerOptions>(ctx, 'signing'),
  );
  return {
    signer,
    fetchImpl: nonObjectPrototypeProperty<EudiDepsContext['fetchImpl']>(ctx, 'fetchImpl'),
    jarTrust: jarTrustOf(ownProperty<EudiDepsContext['rpTrustAnchors']>(ctx, 'rpTrustAnchors')),
  };
}
