/**
 * Wallet ファサードの EUDI PID / (Q)EAA API と Wallet Unit Attestation API の委譲実装。
 *
 * `WalletImpl`（`wallet.ts`）が肥大化しないよう、受領・提示の委譲処理を本クラスへ切り出す
 * （`GdprFacade` / `DelegationFacade` と同じ方針）。`WalletImpl` は本クラスのインスタンスを 1 つ
 * 保持し、各公開メソッドを 1 行で素通し委譲する。インターフェース定義は `api.ts`（`EudiApi`）。
 *
 * 手続きそのもの（OID4VCI 通信・JWT Proof・選択的開示・VP Token 送信）は内部プリミティブ
 * （`internal/eudi/issuance` / `internal/eudi/presentation`）が担い、本クラスは次の処理を担当する。
 *
 * 1. **署名鍵と Holder 識別子の解決。** 呼び出しごとに `resolveActiveHolder`（`wallet/setup.ts`。
 *    `receiveCredentialWith` と共有）でアクティブペルソナの HD 鍵を導出する
 *    （ペルソナ未設定は `2005` がそのまま伝播）。ペルソナ DID は did:key なので、JWT Proof /
 *    KB-JWT の `kid` は DID Document の verificationMethod id（`did:key:z…#z…`）と同じ規則で
 *    導出する（`internal/identity/method-key.ts` の `buildDidDocument`）。
 * 2. **セッションスコープの受領済み Credential 保持。**
 * 3. **Wallet Attestation の取得・保持・添付。**
 * 4. **受領した SD-JWT VC の Issuer 署名の既定検証**（`verified-receive.ts` / `receive-verify.ts`）。
 *    `wallet.receiveCredential` と同じ検証規則をすべての受領経路に適用する。挙動変更・後方非互換。
 *
 * ## 保持はメモリのみ（永続化は本イテレーションのスコープ外）
 *
 * 直近の PID と受領済み (Q)EAA 群は**インスタンス上のメモリにのみ**保持し、`Storage` へは書かない
 * （`MnemonicVault` がアンロック中の平文をメモリだけに持つのと同じ形）。理由は、同じ EUDI の
 * セッション状態である現行 WUA の取得 API `getWalletAttestation()` が **同期**
 * である一方 `Storage` は非同期であり、片方だけ永続化すると「WUA はメモリ・Credential は storage」
 * という一貫しない状態が生まれるためである。EUDI セッション状態は一括してメモリに揃え、永続化は
 * 保持先を決めたうえで別スコープで導入する。したがってプロセス / タブをまたいだ保持はされない。
 */

import type { ReceiveDeps } from '../../internal/auth/eudi/issuance/index.js';
import type { PresentDeps, PresentOptions } from '../../internal/auth/eudi/presentation/index.js';
import {
  presentEAACredential,
  presentPIDCredential,
} from '../../internal/auth/eudi/presentation/index.js';
import type { VerifiablePresentation } from '../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import type {
  AttestationCatalogueSource,
  EAACredential,
  EAAReceiveOptions,
  PIDAttributeName,
  PIDCredential,
  PIDReceiveOptions,
} from '../../internal/eudi/pid/index.js';
import type { WalletUnitAttestation, WuaPopOptions } from '../../internal/eudi/wua/index.js';
import { buildWuaProofOfPossession } from '../../internal/eudi/wua/index.js';
import type { FetchLike } from '../../internal/fetch-di.js';
import type { PublicKeyJwk } from '../../internal/identity/did.js';
import type { KeyManager } from '../../internal/keymanager/keymanager.js';
import type { Metrics } from '../../internal/observability/metrics.js';
import type { PersonaManager } from '../../internal/persona/persona.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import type { QtspServiceCertificate } from '../../internal/trust/etsi-tsl/index.js';
import type { ReceivedIssuerTrust } from '../issuer-trust/index.js';
import { type ActiveHolder, type ActiveSignerOptions, resolveActiveHolder } from '../setup.js';
import { buildPresentDeps, buildReceiveDeps, type EudiDepsContext } from './deps.js';
import {
  withOid4vpResponseMetrics,
  withPidIssuanceMetrics,
  withWuaRefreshMetrics,
} from './observability.js';
import { receiveVerifiedEAA, receiveVerifiedPID } from './verified-receive.js';
import {
  activeWua,
  nowSeconds,
  obtainVerifiedWua,
  refreshCurrentWua,
  requireActiveWua,
  requireWua,
} from './wua-holder.js';

/** EUDI API の委譲先。依存を束ねて `WalletImpl` を薄く保つ。 */
export class EudiFacade {
  /** 直近に受領した PID。`presentPID` が `opts.credential` 省略時に提示する（メモリのみ）。 */
  private storedPid: PIDCredential | null = null;

  /** 受領済み (Q)EAA。`presentEAA` が `vctFilter` で絞り込む提示候補（メモリのみ）。 */
  private readonly storedEaas: EAACredential[] = [];

  /**
   * 現行 Wallet Unit Attestation（メモリのみ、セッションスコープ）。
   *
   * `obtainWalletAttestation` が検証済みの WUA だけを書き込み、`getWalletAttestation` が読み、
   * `walletAttestation: true` の受領が `deps.ts` の `buildReceiveDeps` 経由で使う。未取得のうちは `null`
   * （= `walletAttestation: true` は `10101` に倒れる）。
   */
  private currentWua: WalletUnitAttestation | null = null;

  /** 受領 / 提示フローへ渡す依存の組み立て材料（`deps.ts`）。 */
  private readonly depsContext: EudiDepsContext;

  /**
   * タグの並びは実引数順と揃える（ずれると IDE / typedoc が別の引数の説明として表示する）。
   *
   * @param personas ペルソナ管理委譲先（アクティブペルソナの解決）。
   * @param keymanager 鍵管理委譲先（HD 鍵導出と `CredentialSigner` の取得）。
   * @param catalogue (Q)EAA Catalogue の参照源（未登録 vct は `10003`）。
   * @param metrics ラベルのカーディナリティを制限したメトリクスの記録先。既定ではメモリに記録する。
   * @param issuerTrust Issuer 署名の既定検証の信頼材料（DID Resolver・`x5c` 用 Issuer 側 Trust Anchor・JWT VC Issuer Metadata 経路の opt-in と取得シーム）。
   * @param fetchImpl HTTP 差し替えシーム（OID4VCI 3 経路・OID4VP の `request_uri`（JAR）取得・OID4VP 送信・WUA 取得に伝播する）。
   * @param walletProviderJwk 信頼済み Wallet Provider 署名鍵（未設定なら WUA 取得は `10102`）。
   * @param wscdPublicKeyJwk WSCD 由来の公開鍵 JWK（設定時のみ WUA `cnf.jwk` のバインドを検証）。
   * @param rpTrustAnchors RP Access Certificate の Trust Anchor（未設定なら参照形式の提示要求は `8030`。`rp-trust.ts`）。
   * @param signing 取り込んだ DID のペルソナで署名するための Resolver・外部秘密鍵の提供元。
   */
  constructor(
    private readonly personas: PersonaManager,
    private readonly keymanager: KeyManager,
    private readonly catalogue: AttestationCatalogueSource,
    private readonly metrics: Metrics,
    private readonly issuerTrust: ReceivedIssuerTrust,
    private readonly fetchImpl?: FetchLike,
    private readonly walletProviderJwk?: PublicKeyJwk,
    private readonly wscdPublicKeyJwk?: PublicKeyJwk,
    rpTrustAnchors?: readonly QtspServiceCertificate[],
    private readonly signing?: ActiveSignerOptions,
  ) {
    this.depsContext = { personas, keymanager, metrics, fetchImpl, rpTrustAnchors, signing };
  }

  /**
   * Wallet Provider Backend から WUA を取得して保持する。
   *
   * 取得は 2 段階のフロー（`/wua/challenge` → `/wua/issue`）で、challenge への
   * 署名鍵にはアクティブペルソナの `CredentialSigner` を渡す。**`devicePosture` は送らない** —
   * 取得のたびにネイティブ実行環境の attestation API から得るべき値であり、`createWallet` 時に
   * 固定される `WalletOptions` に置くと「いつ評価したか判らない静的な値」を毎回送ることになって
   * 意味を失うためである（詳細と回避策は `wua-holder.ts` の `obtainVerifiedWua`）。検証を通った
   * WUA だけが返るので、保持は戻り値をそのまま代入してよい。
   *
   * @param providerEndpoint Wallet Provider Backend のベース URL（HTTPS のみ）。
   * @throws `walletProviderJwk` 未設定・署名や WSCD バインド不正（`10102`）、取得失敗（`10101`）、
   *         期限切れ（`10103`）、アクティブペルソナ未設定（`2005`）の場合。
   */
  async obtainWalletAttestation(providerEndpoint: string): Promise<WalletUnitAttestation> {
    const { signer } = await this.resolveHolder();
    return withWuaRefreshMetrics(this.metrics, async () => {
      const wua = await obtainVerifiedWua(providerEndpoint, signer, {
        walletProviderJwk: this.walletProviderJwk,
        wscdPublicKeyJwk: this.wscdPublicKeyJwk,
        fetchImpl: this.fetchImpl,
      });
      this.currentWua = wua;
      return wua;
    });
  }

  /** 現行 WUA を返す（同期。未取得・期限切れは `null`）。 */
  getWalletAttestation(): WalletUnitAttestation | null {
    return activeWua(this.currentWua, nowSeconds());
  }

  /**
   * 現行 WUA にバインドされた署名鍵で WUA-PoP JWT を生成する。
   * `internal/eudi/wua/proof.ts` の
   * `buildWuaProofOfPossession` へ対象 WUA・署名鍵・現在時刻を渡すだけの薄いラッパーで、
   * 呼び出し側は `opts`（`aud` / `nonce`）だけを渡す。
   *
   * @throws 現行 WUA 未保持（VericertsError、code `10101`）、期限切れ（`10103`）、
   *         アクティブペルソナ未設定（`2005`）、signer 鍵が `cnf.jwk` と不一致（`10102`）の場合。
   * @experimental v1.0 での安定化を予定している。それまでは挙動やシグネチャが変わることがある。
   */
  async buildWuaProofOfPossession(opts: WuaPopOptions): Promise<string> {
    const wua = requireActiveWua(this.currentWua, nowSeconds());
    const { signer } = await this.resolveHolder();
    return buildWuaProofOfPossession(wua, opts, signer, nowSeconds());
  }

  /**
   * 期限切れ（または期限が近い）現行 WUA を、Wallet Provider が再発行した新 WUA JWT へ
   * 差し替える。新 WUA JWT の取得
   * （Wallet Provider Backend への再取得リクエスト）は本 SDK の責務外のため呼び出し側が用意し、
   * 本メソッドは `internal/eudi/wua/wua.ts` の `refreshWalletAttestation` へ旧 WUA・信頼済み
   * Wallet Provider 鍵・現在時刻を渡して検証し、通れば保持を差し替えるだけの薄いラッパーである。
   *
   * @throws 現行 WUA 未保持（VericertsError、code `10101`）、`walletProviderJwk` 未設定・
   *         新 WUA の署名 / `vct` / WSCD バインド不正の場合（`10102`）、新 WUA が期限切れの場合
   *         （`10103`）。
   * @experimental v1.0 での安定化を予定している。それまでは挙動やシグネチャが変わることがある。
   */
  refreshWalletAttestation(refreshedJwt: string): WalletUnitAttestation {
    const refreshed = refreshCurrentWua(
      requireWua(this.currentWua),
      refreshedJwt,
      this.walletProviderJwk,
      nowSeconds(),
    );
    this.currentWua = refreshed;
    return refreshed;
  }

  /** PID を受領し、Issuer 署名を検証してから保持する。 */
  async receivePID(offerURI: string, opts?: PIDReceiveOptions): Promise<PIDCredential> {
    // 任意オプションは own 限定で読む（鎖読みだと `walletAttestation` を**省略した**正当な
    // 呼び出しが `Object.prototype.walletAttestation` を拾い、意図せず WUA を添付する）。
    const withAttestation = ownProperty<unknown>(opts ?? {}, 'walletAttestation') === true;
    return withPidIssuanceMetrics(this.metrics, async () => {
      // 保持する前に検証する（保持後だと偽の PID が presentPID の提示候補として残る）。
      const pid = await receiveVerifiedPID(
        offerURI,
        await this.receiveDeps(withAttestation),
        this.issuerTrust,
        opts,
      );
      this.storedPid = pid;
      return pid;
    });
  }

  /** PID を選択的開示して提示する。 */
  async presentPID(
    requestURI: string,
    disclosedClaims: PIDAttributeName[],
    opts?: PresentOptions,
  ): Promise<VerifiablePresentation> {
    // `credential` を鎖で読むと、汚染された `Object.prototype.credential` が保持済み PID を
    // 上書きし、**攻撃者が用意した SD-JWT が Verifier へ提示される**（`present.ts` と同じ根拠）。
    const credential = ownProperty<PIDCredential>(opts ?? {}, 'credential') ?? this.storedPid;
    if (credential === null) {
      // 提示対象が特定できない状態で推測しない。理由は固定識別子のみ。
      throw new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED, {
        context: { reason: 'no_stored_credential' },
      });
    }
    return withOid4vpResponseMetrics(this.metrics, async () =>
      presentPIDCredential(requestURI, disclosedClaims, credential, await this.presentDeps()),
    );
  }

  /** (Q)EAA を受領し、Issuer 署名を検証してから保持する。 */
  async receiveEAA(offerURI: string, opts?: EAAReceiveOptions): Promise<EAACredential> {
    const eaa = await receiveVerifiedEAA(
      offerURI,
      this.catalogue,
      await this.receiveDeps(false),
      this.issuerTrust,
      opts,
    );
    this.storedEaas.push(eaa);
    return eaa;
  }

  /** 保持している (Q)EAA を `vct` で選んで提示する。 */
  async presentEAA(requestURI: string, vctFilter: string): Promise<VerifiablePresentation> {
    return withOid4vpResponseMetrics(this.metrics, async () =>
      presentEAACredential(requestURI, vctFilter, this.storedEaas, await this.presentDeps()),
    );
  }

  /**
   * メモリ保持中の PID・(Q)EAA・WUA をすべて破棄する。
   *
   * seed を別ウォレットへ差し替えた後に旧ウォレットの Credential が提示対象・WUA として残ると、
   * `cnf` は旧 seed の鍵なのに KB-JWT は新 seed の鍵で署名され、検証側で原因不明の不一致になる。
   * `RecoveryFacade` の旧 seed 状態掃除から呼ぶ内部用で、`EudiApi` には載せない。
   */
  discardHeldCredentials(): void {
    this.storedPid = null;
    this.storedEaas.length = 0;
    this.currentWua = null;
  }

  /**
   * アクティブペルソナの署名鍵と Holder 識別子を解決する。
   *
   * 実体は `resolveActiveHolder`（`wallet/setup.ts`）で、`receiveCredentialWith`
   * （`wallet/credential/ops.ts`）と共有する（重複実装を避ける）。
   *
   * @returns 署名鍵・Holder DID・検証鍵 ID。
   * @throws アクティブペルソナ未設定の場合（VericertsError、code `2005`）。
   */
  private async resolveHolder(): Promise<ActiveHolder> {
    return resolveActiveHolder(this.personas, this.keymanager, this.signing);
  }

  /**
   * 受領フローの依存を組み立てる（組み立て規則は `deps.ts`）。
   *
   * @param withAttestation Token Request に WUA を添付するか。
   * @throws アクティブペルソナ未設定（code `2005`）、WUA 未保持での添付要求（`10101`）の場合。
   */
  private receiveDeps(withAttestation: boolean): Promise<ReceiveDeps> {
    return buildReceiveDeps(this.depsContext, this.currentWua, withAttestation);
  }

  /**
   * 提示フローの依存を組み立てる（組み立て規則は `deps.ts`）。
   *
   * @throws アクティブペルソナ未設定の場合（VericertsError、code `2005`）。
   */
  private presentDeps(): Promise<PresentDeps> {
    return buildPresentDeps(this.depsContext);
  }
}
