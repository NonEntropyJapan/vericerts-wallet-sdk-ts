/**
 * `WalletImpl`（`wallet.ts`）の公開 API のうち、`GdprFacade` / `EudiFacade` へ**引数を素通しする
 * だけ**の委譲をまとめた基底クラス。
 *
 * `WalletImpl` は `Wallet` interface の唯一の実装であり、鍵・DID・VC の組み立て（委譲先が複数に
 * またがる結線）と、単一ファサードへの素通しという 2 種類の記述が同居して肥大化していた。後者は
 * ロジックを一切持たず「どのファサードの同名メソッドを呼ぶか」しか決めていないため、本クラスへ分離
 * して `wallet.ts` 側を結線に集中させる。
 *
 * ここに実装を足すときは実体を必ずファサード側（`gdpr/facade.ts` / `eudi/facade.ts`）に置き、本
 * クラスは素通しに保つこと。分岐や加工が要るものは素通しではないので `wallet.ts` 側へ書く。
 */

import type { PresentOptions } from '../internal/auth/eudi/presentation/index.js';
import type { VerifiablePresentation } from '../internal/credential/index.js';
import type {
  EAACredential,
  EAAReceiveOptions,
  PIDAttributeName,
  PIDCredential,
  PIDReceiveOptions,
} from '../internal/eudi/pid/index.js';
import type { WalletUnitAttestation } from '../internal/eudi/wua/index.js';
import type {
  ConsentScope,
  CredentialRecord,
  DashboardLogVerifierKey,
  LogFilter,
} from '../internal/gdpr/index.js';
import type { EudiFacade } from './eudi/facade.js';
import type { GdprFacade } from './gdpr/index.js';
import type { Wallet } from './types.js';

/** `GdprFacade` / `EudiFacade` への素通し委譲だけを持つ `WalletImpl` の基底クラス。 */
export abstract class WalletFacadeDelegates {
  protected constructor(
    protected readonly gdpr: GdprFacade,
    protected readonly eudi: EudiFacade,
  ) {}

  // VC レコード / GDPR APIは GdprFacade へ素通し委譲する。
  readonly matchCredentialsByPresentationDefinition: Wallet['matchCredentialsByPresentationDefinition'] =
    (pd) => this.gdpr.matchCredentialsByPresentationDefinition(pd);
  readonly matchCredentials: Wallet['matchCredentials'] = (requestURI, opts) =>
    this.gdpr.matchCredentials(requestURI, opts);
  readonly createPresentation: Wallet['createPresentation'] = (requestURI, vcIDs, opts) =>
    this.gdpr.createPresentation(requestURI, vcIDs, opts);
  readonly storeCredential: Wallet['storeCredential'] = (vc) => this.gdpr.storeCredential(vc);
  getCredentialRecord(vcId: string): Promise<CredentialRecord | null> {
    return this.gdpr.getCredentialRecord(vcId);
  }
  recordPresentation(vcId: string, rpIdentifier: string, purpose?: string): Promise<void> {
    return this.gdpr.recordPresentation(vcId, rpIdentifier, purpose);
  }
  markCredentialDisputed(vcId: string, reason: string): Promise<void> {
    return this.gdpr.markCredentialDisputed(vcId, reason);
  }
  setCredentialProcessingRestriction(vcId: string, restricted: boolean): Promise<void> {
    return this.gdpr.setCredentialProcessingRestriction(vcId, restricted);
  }
  revokeConsent(scope: ConsentScope): Promise<void> {
    return this.gdpr.revokeConsent(scope);
  }
  deleteCredential(vcId: string): Promise<void> {
    return this.gdpr.deleteCredential(vcId);
  }
  purgeDashboardLog(filter?: LogFilter): Promise<number> {
    return this.gdpr.purgeDashboardLog(filter);
  }
  exportDashboardLog(filter?: LogFilter): Promise<Blob> {
    return this.gdpr.exportDashboardLog(filter);
  }
  importDashboardLog(ndjson: Blob | string, verifierKey: DashboardLogVerifierKey): Promise<number> {
    return this.gdpr.importDashboardLog(ndjson, verifierKey);
  }

  // EUDI API（PID / (Q)EAA・WUA）は EudiFacade へ素通し委譲する。
  receivePID(offerURI: string, opts?: PIDReceiveOptions): Promise<PIDCredential> {
    return this.eudi.receivePID(offerURI, opts);
  }
  presentPID(
    requestURI: string,
    disclosedClaims: PIDAttributeName[],
    opts?: PresentOptions,
  ): Promise<VerifiablePresentation> {
    return this.eudi.presentPID(requestURI, disclosedClaims, opts);
  }
  receiveEAA(offerURI: string, opts?: EAAReceiveOptions): Promise<EAACredential> {
    return this.eudi.receiveEAA(offerURI, opts);
  }
  presentEAA(requestURI: string, vctFilter: string): Promise<VerifiablePresentation> {
    return this.eudi.presentEAA(requestURI, vctFilter);
  }
  obtainWalletAttestation(providerEndpoint: string): Promise<WalletUnitAttestation> {
    return this.eudi.obtainWalletAttestation(providerEndpoint);
  }
  getWalletAttestation(): WalletUnitAttestation | null {
    return this.eudi.getWalletAttestation();
  }
  readonly buildWuaProofOfPossession: Wallet['buildWuaProofOfPossession'] = (opts) =>
    this.eudi.buildWuaProofOfPossession(opts);
  readonly refreshWalletAttestation: Wallet['refreshWalletAttestation'] = (refreshedJwt) =>
    this.eudi.refreshWalletAttestation(refreshedJwt);
}
