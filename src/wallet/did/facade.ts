/**
 * Wallet ファサードの DID 管理と controller 操作の実装。
 *
 * `WalletImpl`（`wallet.ts`）が肥大化しないよう、DID の生成・解決・一覧・メソッド登録、Well Known
 * DID Configuration の生成・検証、ERC-1056 controller 操作（検出・Tx 構築）を本クラスへ
 * 切り出す（`GdprFacade` と同じ方針）。`WalletImpl` は本クラスのインスタンスを
 * 1 つ保持し、各公開メソッドを 1 行で素通し委譲する。インターフェース定義は `api.ts`（`DidApi`）。
 *
 * DID Document の生成・解決・永続化は既存モジュール（`MethodKey` / `Resolver` / `Storage`）へ
 * 素通し委譲し、controller 操作（検出・Tx 構築）は delegation プリミティブへ委譲する。
 * Well Known DID Configuration も自前実装は持たず、VC 発行・検証（`credential`）と well-known
 * 文書の取得（`fetchWellKnownJson`）を組み合わせ、DLC 固有の条件判定だけを本クラスで行う。
 */

import { fetchWellKnownJson } from '../../internal/auth/well-known-json/index.js';
import { issueCredential, VC_TYPE, VC_V2_CONTEXT } from '../../internal/credential/index.js';
import {
  type AbiEncoder,
  buildRemoveControllerTx,
  buildSetControllerTx,
  detectController,
  type Erc1056EventSource,
  parseEthrDid,
  type UnsignedTransaction,
} from '../../internal/delegation/index.js';
import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import type { FetchLike } from '../../internal/fetch-di.js';
import { isPublicHttpsUrl } from '../../internal/http/public-https-url.js';
import {
  createBoundedResolver,
  type DidResolverLike,
} from '../../internal/identity/bounded-resolver.js';
import type { DIDDocument, DIDMethod } from '../../internal/identity/did.js';
import type { MethodKey } from '../../internal/identity/method-key.js';
import type { Resolver } from '../../internal/identity/resolver.js';
import type { KeyManager } from '../../internal/keymanager/keymanager.js';
import type { Logger } from '../../internal/observability/logger.js';
import type { Metrics } from '../../internal/observability/metrics.js';
import type { Tracer } from '../../internal/observability/tracer.js';
import type { PersonaManager } from '../../internal/persona/persona.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import type { Storage } from '../../storage/storage.js';
import { decodeDocument, encodeDocument } from '../codec.js';
import { verifyCredentialWith } from '../credential/index.js';
import {
  type ActiveSignerOptions,
  buildControllerTxDeps,
  resolveCreateDidKey,
  resolveSignerForDid,
} from '../setup.js';
import { checkDomainLinkageClaims } from './linked-did-claims.js';
import { MAX_LINKED_DIDS } from './linked-dids-limit.js';
import type {
  CreateDIDOptions,
  DIDConfiguration,
  DIDConfigurationVerificationResult,
  LinkedDIDResult,
  UpdateDIDOptions,
} from './options.js';
import { resolveDidWith } from './resolve.js';
import { updateDidWith } from './update.js';

/** storage 上で DID Document を保存するキーの prefix。 */
const DID_KEY_PREFIX = 'did/';

/** DIF Well Known DID Configuration の JSON-LD コンテキスト（文書と DLC の両方で使う）。 */
const DID_CONFIGURATION_CONTEXT = 'https://identity.foundation/.well-known/did-configuration/v1';

/** Well Known DID Configuration 文書のパス。 */
const DID_CONFIGURATION_PATH = '/.well-known/did-configuration.json';

/** Domain Linkage Credential の VC type（`VerifiableCredential` に続く 2 番目の型）。 */
const DOMAIN_LINKAGE_CREDENTIAL_TYPE = 'DomainLinkageCredential';

export { MAX_LINKED_DIDS };

/** DID の管理・解決と ERC-1056 controller 操作を実装する。 */
export class DidFacade {
  constructor(
    private readonly storage: Storage,
    private readonly keymanager: KeyManager,
    private readonly resolver: Resolver,
    private readonly method: MethodKey,
    private readonly eventSource: Erc1056EventSource,
    private readonly abiEncoder: AbiEncoder,
    private readonly personas: PersonaManager,
    private readonly didConfigurationFetchImpl: FetchLike | undefined,
    /** `component: 'sdk.did'` を束縛済みのロガー（`WalletImpl` が組み立てる）。 */
    private readonly logger: Logger,
    /** ラベルのカーディナリティ制限を適用済みのメトリクス。ラベルは呼び出しごとに渡す。 */
    private readonly metrics: Metrics,
    /** 分散トレースの出力先（未注入時は no-op）。 */
    private readonly tracer: Tracer,
    /** 取り込んだ DID のペルソナで署名するための Resolver・外部秘密鍵の提供元（`factory.ts` が組み立てる）。 */
    private readonly signing?: ActiveSignerOptions,
  ) {}

  /** DID を生成し、DID Document を storage に永続化する。 */
  async createDID(method: string, opts?: CreateDIDOptions): Promise<DIDDocument> {
    if (method !== 'key') {
      throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
    }
    const key = await resolveCreateDidKey(
      this.keymanager,
      opts ? ownProperty<string>(opts, 'keyID') : undefined,
    );
    const document = await this.method.create(key);
    await this.storage.set(this.didStorageKey(document.id), encodeDocument(document));
    return document;
  }

  /** DID 文字列を DID Document に解決する（登録メソッドへ委譲。計装は `resolve.ts`）。 */
  resolveDID(did: string): Promise<DIDDocument> {
    return resolveDidWith(this.resolver, did, this.logger, this.metrics, this.tracer);
  }

  /** 差分適用と GDPR Art.9 属性の検査を経て、更新の公開を DID メソッドに委譲する。 */
  updateDID(did: string, opts: UpdateDIDOptions): Promise<DIDDocument> {
    return updateDidWith(this.resolver, this.storage, (id) => this.didStorageKey(id), did, opts);
  }

  /** storage に保存済みの DID Document を取得する。 */
  async getDID(did: string): Promise<DIDDocument | null> {
    const stored = await this.storage.get(this.didStorageKey(did));
    if (stored === null) {
      return null;
    }
    return decodeDocument(stored);
  }

  /** storage に保存済みの全 DID 文字列を返す。 */
  async listDIDs(): Promise<string[]> {
    const keys = await this.storage.list(DID_KEY_PREFIX);
    return keys.map((key) => key.slice(DID_KEY_PREFIX.length));
  }

  /** カスタム DID メソッドプラグインを登録する。 */
  registerDIDMethod(method: DIDMethod): void {
    this.resolver.register(method);
  }

  /** Well Known DID Configuration（Domain Linkage Credential）を生成する。 */
  async generateDIDConfiguration(did: string, origin: string): Promise<DIDConfiguration> {
    // 検証側（verifyDIDConfiguration）は公開 HTTPS のみを許し、DLC の `origin` を渡された origin と
    // 文字列一致で照合する。どのオリジンでも有効にならない DLC を署名しないよう、署名前に正規形の
    // 公開 HTTPS origin（パス・クエリ・userinfo・既定ポート明示なし）だけを受理する。
    if (
      typeof origin !== 'string' ||
      !isPublicHttpsUrl(origin) ||
      new URL(origin).origin !== origin
    ) {
      throw new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID);
    }
    // 署名鍵は「指定 DID のもの」に限定して解決する（不一致・未設定はいずれも 2007）。
    const signer = await resolveSignerForDid(this.personas, this.keymanager, did, this.signing);
    // DLC は self-issued（issuer = credentialSubject.id = did）。これがドメイン紐づけの根拠で、
    // 検証側（verifyDIDConfiguration）も同じ条件を要求する。
    const jwt = issueCredential(
      {
        '@context': [VC_V2_CONTEXT, DID_CONFIGURATION_CONTEXT],
        type: [VC_TYPE, DOMAIN_LINKAGE_CREDENTIAL_TYPE],
        issuer: did,
        credentialSubject: { id: did, origin },
        issuanceDate: new Date().toISOString(),
      },
      signer,
    );
    return { '@context': DID_CONFIGURATION_CONTEXT, linked_dids: [jwt] };
  }

  /**
   * Well Known DID Configuration を検証する。
   *
   * 取得・パース・検証のいずれの失敗も結果で返す。
   */
  async verifyDIDConfiguration(
    origin: string,
    did?: string,
  ): Promise<DIDConfigurationVerificationResult> {
    const fetched = await this.fetchDidConfiguration(origin);
    if (typeof fetched === 'string') {
      return { valid: false, linkedDIDs: [], errors: [fetched] };
    }
    const entries = ownProperty<unknown>(fetched, 'linked_dids');
    // 件数上限超過は 1 件も解決せず拒否する（外部オリジン指定の件数ぶん発行者 DID 解決を撒かない）。
    if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_LINKED_DIDS) {
      return { valid: false, linkedDIDs: [], errors: ['invalid_did_configuration'] };
    }
    // 発行者 DID の解決は 1 回の検証（スコープ）で共有する: 同一 DID は 1 回に集約し、相異なる DID 数・DID 長・
    // 検証仕事量（did:webvh の署名検証数など）の総量を縛る。DLC の発行者 DID 解決は署名検証より前に走るため、
    // 署名不正の DLC を並べるだけで外部オリジンが検証側の CPU・外向き要求を増幅できる。
    const resolver = createBoundedResolver(this.resolver);
    const linkedDIDs: LinkedDIDResult[] = [];
    for (const entry of entries) {
      // 逐次検証する。各 DLC の検証は発行者 DID の解決（ネットワーク）を伴うため、文書に並ぶ
      // 件数ぶんの同時リクエストを外部ドメインの申告どおりに撒かない。
      linkedDIDs.push(
        typeof entry === 'string'
          ? await this.verifyLinkedDid(resolver, entry, origin)
          : { did: '', valid: false, error: 'invalid_linked_did_entry' },
      );
    }
    if (did === undefined) {
      // DID 無指定は「この文書の DLC がすべて有効か」を問う。
      return { valid: linkedDIDs.every((result) => result.valid), linkedDIDs };
    }
    // 指定した DID が有効な DLC で origin に紐づいていれば、別の DID の DLC の失敗は結果に影響しない。
    if (linkedDIDs.some((result) => result.valid && result.did === did)) {
      return { valid: true, linkedDIDs };
    }
    return { valid: false, linkedDIDs, errors: ['did_not_linked'] };
  }

  /** did:ethr の現在の controller（所有者）をオンチェーンイベントから検出する。 */
  async detectController(did: string): Promise<string> {
    // async にすることで parseEthrDid の同期 throw（形式不正 2001）も rejected Promise に正規化する。
    return detectController(parseEthrDid(did), this.eventSource);
  }

  /** controller を設定する未署名トランザクションを構築する。 */
  buildSetControllerTx(
    did: string,
    controllerDid: string,
    registryAddress?: string,
  ): UnsignedTransaction {
    const deps = buildControllerTxDeps(this.abiEncoder, registryAddress);
    return buildSetControllerTx(did, controllerDid, deps);
  }

  /** controller を削除する未署名トランザクションを構築する。 */
  buildRemoveControllerTx(did: string, registryAddress?: string): UnsignedTransaction {
    return buildRemoveControllerTx(did, buildControllerTxDeps(this.abiEncoder, registryAddress));
  }

  /**
   * `<origin>/.well-known/did-configuration.json` を取得する。
   *
   * トランスポート（HTTPS 限定・タイムアウト・リダイレクト後の再検査・プロトタイプ無しパース）は
   * `fetchWellKnownJson` に委譲する。取得元 URL は検証対象ドメインが与えるもので OID4VCI の
   * Metadata 取得と同じ攻撃面（SSRF / 平文降格）を持つため、入口検査を書き写さない。
   *
   * @param origin 検証対象ドメインオリジン。
   * @returns 取得できた文書、または失敗理由の識別子（文字列）。
   */
  private async fetchDidConfiguration(origin: string): Promise<object | string> {
    let reason = 'fetch_failed';
    try {
      return await fetchWellKnownJson(
        origin,
        DID_CONFIGURATION_PATH,
        this.didConfigurationFetchImpl,
        (failureReason) => {
          reason = failureReason;
          // 直後の catch で取得失敗を示す reason を返す。
          return new VericertsError(ErrorCodes.DID_NOT_FOUND);
        },
      );
    } catch {
      return reason;
    }
  }

  /**
   * Domain Linkage Credential（JWT-VC）1 件を検証する。
   *
   * 署名・発行者 DID の解決・時刻クレームは `verifyCredentialWith` が担う。そのうえで DLC 固有の
   * 条件（self-issued であること、`credentialSubject.origin` が検証対象と一致すること）を確かめる。
   * `verifyCredentialWith` は `iss` = `vc.issuer` と `sub` = `vc.credentialSubject.id` の突合まで
   * 済ませているため、self-issued 判定は envelope 側の `iss` / `sub` の比較で足りる。
   *
   * @param resolver 発行者 DID の解決に使う、1 回の検証で共有する上限付き resolver。
   * @param jwt 検証対象の Domain Linkage Credential。
   * @param origin 検証対象ドメインオリジン。
   * @returns 検証結果（失敗理由は固定の識別子のみで、JWT 本文は載せない）。
   */
  private async verifyLinkedDid(
    resolver: DidResolverLike,
    jwt: string,
    origin: string,
  ): Promise<LinkedDIDResult> {
    let payload: Record<string, unknown>;
    try {
      // DLC も JWT-VC なので、`verifyCredentialWith` 側が `component: 'sdk.vc'` /
      // `operation: 'vc.verify'` を束ね直す。ここでは出力先だけ渡す。
      ({ payload } = await verifyCredentialWith(
        resolver,
        jwt,
        this.logger,
        this.metrics,
        this.tracer,
      ));
    } catch {
      // 署名不正・期限切れ・発行者 DID 解決失敗・構造不正。検証を通っていない payload は事実として
      // 扱えないため DID は空にする。
      return { did: '', valid: false, error: 'verification_failed' };
    }
    return checkDomainLinkageClaims(payload, origin);
  }

  /** DID 文字列から storage キーを組み立てる。 */
  private didStorageKey(did: string): string {
    return `${DID_KEY_PREFIX}${did}`;
  }
}
