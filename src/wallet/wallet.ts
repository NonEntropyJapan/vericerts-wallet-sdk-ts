/** 鍵管理・DID・ストレージを統合する Wallet の実装。鍵の状態は `KeyManager` が保持し、DID Document は `Storage` に永続化する。例外やログに seed、秘密鍵、パスワード、平文を含めない。 */

import type { IssueCredentialOptions, VerifiableCredential } from '../internal/credential/index.js';
import type {
  AbiEncoder,
  Erc1056EventSource,
  UnsignedTransaction,
} from '../internal/delegation/index.js';
import type { FetchLike } from '../internal/fetch-di.js';
import type { DIDDocument } from '../internal/identity/did.js';
import type { MethodKey } from '../internal/identity/method-key.js';
import type { Resolver } from '../internal/identity/resolver.js';
import type { KeyManager } from '../internal/keymanager/keymanager.js';
import type { MnemonicLanguage, WordCount } from '../internal/keymanager/mnemonic.js';
import type { PersonaManager } from '../internal/persona/persona.js';
import type {
  CreatePersonaOptions,
  ListPersonasOptions,
  PersonaMetadata,
} from '../internal/persona/types.js';
import type { Storage } from '../storage/storage.js';
import {
  issueCredentialWith,
  issuePresentationWith,
  issueSdJwtWith,
  verifyCredentialResultWith,
  verifyCredentialWith,
  verifyPresentationEnvelopeStrictWith,
  verifyPresentationResultWith,
  verifySdJwtWith,
} from './credential/index.js';
import { WalletFacadeDelegates } from './delegates.js';
import { DidFacade } from './did/index.js';
import type {
  CreateDIDOptions,
  DIDConfiguration,
  DIDConfigurationVerificationResult,
  UpdateDIDOptions,
} from './did/options.js';
import type { EudiFacade } from './eudi/index.js';
import type { GdprFacade } from './gdpr/index.js';
import type { ImportMnemonicOptions, Logger, Metrics, Tracer } from './options.js';
import type { ActiveSignerOptions } from './setup.js';
import type { Wallet, WalletKeyPair } from './types.js';

/** `Wallet` の内部実装。生成は `factory.ts` の `createWallet` 経由のみを想定する（公開 API では直接 new させない）。`factory.ts` から参照するため export する。 */
export class WalletImpl extends WalletFacadeDelegates implements Wallet {
  /** VC の保存・提示候補の照合・GDPR は同じストアを共有する。`factory.ts` で構成した各ファサードとログ・メトリクス・トレースの出力先を受け取る。 */
  constructor(
    storage: Storage,
    private readonly keymanager: KeyManager,
    private readonly resolver: Resolver,
    method: MethodKey,
    private readonly personas: PersonaManager,
    eventSource: Erc1056EventSource,
    abiEncoder: AbiEncoder,
    didConfigurationFetchImpl: FetchLike | undefined,
    eudi: EudiFacade,
    private readonly logger: Logger,
    private readonly metrics: Metrics,
    private readonly tracer: Tracer,
    readonly createStatusListResolver: Wallet['createStatusListResolver'],
    readonly receiveCredential: Wallet['receiveCredential'],
    private readonly aaAndRecovery: Pick<
      Wallet,
      | 'emergencyRevokeValidator'
      | 'importMnemonic'
      | 'importRecoveredWallet'
      | 'recoverFromShamirShares'
    >,
    gdpr: GdprFacade,
    signing?: ActiveSignerOptions,
  ) {
    super(gdpr, eudi);
    this.did = new DidFacade(
      storage,
      keymanager,
      resolver,
      method,
      eventSource,
      abiEncoder,
      personas,
      didConfigurationFetchImpl,
      this.logger.child({ component: 'sdk.did' }),
      this.metrics,
      this.tracer,
      signing,
    );
  }
  private readonly did: DidFacade;
  generateMnemonic(wordCount: WordCount, language?: MnemonicLanguage): string {
    return this.keymanager.generateMnemonic(wordCount, language);
  }
  async importMnemonic(
    mnemonic: string,
    passphrase?: string,
    language?: MnemonicLanguage,
    options?: ImportMnemonicOptions,
  ): Promise<void> {
    return this.aaAndRecovery.importMnemonic(mnemonic, passphrase, language, options);
  }
  unlockMnemonic(password: string): Promise<void> {
    return this.keymanager.unlock(password);
  }
  readonly lockMnemonic: Wallet['lockMnemonic'] = () => this.keymanager.lockMnemonic();
  readonly isMnemonicUnlocked: Wallet['isMnemonicUnlocked'] = () =>
    this.keymanager.isMnemonicUnlocked();
  exportMnemonic(): Promise<string> {
    return this.keymanager.exportMnemonic();
  }
  async deriveKey(path: string): Promise<WalletKeyPair> {
    // 秘密鍵は KeyManager に保持し、署名には返却する鍵 ID を使う。
    const { id, algorithm, publicKey, address, derivationPath } =
      await this.keymanager.deriveKey(path);
    return { id, algorithm, publicKey, address, derivationPath };
  }
  async sign(keyID: string, data: Uint8Array): Promise<Uint8Array> {
    return this.keymanager.getSigner(keyID).sign(data);
  }
  async encrypt(plaintext: Uint8Array, password: string): Promise<Uint8Array> {
    return this.keymanager.encrypt(plaintext, password);
  }
  async decrypt(ciphertext: Uint8Array, password: string): Promise<Uint8Array> {
    return this.keymanager.decrypt(ciphertext, password);
  }
  readonly createShamirShares: Wallet['createShamirShares'] = (threshold, total) =>
    this.keymanager.createShamirShares(threshold, total);
  readonly recoverFromShamirShares: Wallet['recoverFromShamirShares'] = (shares, options) =>
    this.aaAndRecovery.recoverFromShamirShares(shares, options);
  readonly emergencyRevokeValidator: Wallet['emergencyRevokeValidator'] = (reason, opts) =>
    this.aaAndRecovery.emergencyRevokeValidator(reason, opts);
  readonly importRecoveredWallet: Wallet['importRecoveredWallet'] = (mnemonic, opts) =>
    this.aaAndRecovery.importRecoveredWallet(mnemonic, opts);
  // DID 管理・DID Configuration・controller 操作を DidFacade に委譲する。
  createDID(method: string, opts?: CreateDIDOptions): Promise<DIDDocument> {
    return this.did.createDID(method, opts);
  }
  resolveDID(did: string): Promise<DIDDocument> {
    return this.did.resolveDID(did);
  }
  updateDID(did: string, opts: UpdateDIDOptions): Promise<DIDDocument> {
    return this.did.updateDID(did, opts);
  }
  getDID(did: string): Promise<DIDDocument | null> {
    return this.did.getDID(did);
  }
  listDIDs(): Promise<string[]> {
    return this.did.listDIDs();
  }
  readonly registerDIDMethod: Wallet['registerDIDMethod'] = (method) =>
    this.did.registerDIDMethod(method);
  generateDIDConfiguration(did: string, origin: string): Promise<DIDConfiguration> {
    return this.did.generateDIDConfiguration(did, origin);
  }
  verifyDIDConfiguration(
    origin: string,
    did?: string,
  ): Promise<DIDConfigurationVerificationResult> {
    return this.did.verifyDIDConfiguration(origin, did);
  }
  detectController(did: string): Promise<string> {
    return this.did.detectController(did);
  }
  buildSetControllerTx(
    did: string,
    controllerDid: string,
    registryAddress?: string,
  ): UnsignedTransaction {
    return this.did.buildSetControllerTx(did, controllerDid, registryAddress);
  }
  buildRemoveControllerTx(did: string, registryAddress?: string): UnsignedTransaction {
    return this.did.buildRemoveControllerTx(did, registryAddress);
  }
  createPersona(opts?: CreatePersonaOptions): Promise<PersonaMetadata> {
    return this.personas.createPersona(opts);
  }
  setActivePersona(id: string): Promise<PersonaMetadata> {
    return this.personas.setActivePersona(id);
  }
  getActivePersona(): Promise<PersonaMetadata | null> {
    return this.personas.getActivePersona();
  }
  listPersonas(opts?: ListPersonasOptions): Promise<PersonaMetadata[]> {
    return this.personas.listPersonas(opts);
  }
  issueCredential(
    vc: VerifiableCredential,
    keyID: string,
    opts?: IssueCredentialOptions,
  ): Promise<string> {
    return issueCredentialWith(this.keymanager, vc, keyID, opts);
  }
  readonly verifyCredentialStrict: Wallet['verifyCredentialStrict'] = (jwt, opts) =>
    verifyCredentialWith(this.resolver, jwt, this.logger, this.metrics, this.tracer, opts);
  readonly verifyCredential: Wallet['verifyCredential'] = (jwt, opts) =>
    verifyCredentialResultWith(this.resolver, jwt, this.logger, this.metrics, this.tracer, opts);
  readonly issuePresentation: Wallet['issuePresentation'] = (vp, keyID, opts) =>
    issuePresentationWith(this.keymanager, vp, keyID, opts);
  readonly verifyPresentationEnvelopeStrict: Wallet['verifyPresentationEnvelopeStrict'] = (
    jwt,
    opts,
  ) => verifyPresentationEnvelopeStrictWith(this.resolver, jwt, this.metrics, opts);
  readonly verifyPresentation: Wallet['verifyPresentation'] = (jwt, opts) =>
    verifyPresentationResultWith(this.resolver, jwt, this.metrics, opts);
  readonly issueSdJwt: Wallet['issueSdJwt'] = (keyID, opts) =>
    issueSdJwtWith(this.keymanager, keyID, opts);
  readonly verifySdJwt: Wallet['verifySdJwt'] = (sdJwt, opts) =>
    verifySdJwtWith(this.resolver, sdJwt, this.metrics, opts);
  zeroize(): void {
    // DID Document は公開情報のため storage は消さず、秘密のみ消去する。
    this.keymanager.zeroize();
  }
}
