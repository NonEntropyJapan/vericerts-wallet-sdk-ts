/**
 * `createWallet` ファクトリ。
 *
 * `WalletImpl`（`wallet.ts`）の生成と、その依存（KeyManager / Resolver / PersonaManager /
 * controller 検出・Tx 構築の eventSource・abiEncoder）の組み立てを担う。ファサード本体（`wallet.ts`）から
 * 生成ロジックを分離し、双方を薄く保つ。
 */

import { createErc1056AbiEncoder, createEthersEventSource } from '../internal/delegation/index.js';
import type { AttestationCatalogueSource } from '../internal/eudi/pid/index.js';
import { createRecordCatalogueSource } from '../internal/eudi/pid/index.js';
import { CredentialStore, DashboardLog } from '../internal/gdpr/index.js';
import { bindInjectedFetch } from '../internal/http/bind-fetch.js';
import type { PublicKeyJwk } from '../internal/identity/did.js';
import { createDidKey } from '../internal/identity/method-key.js';
import type { KdfParams } from '../internal/keymanager/kdf.js';
import { MetricsInstrumentedKeyManager } from '../internal/keymanager/keymanager-metrics.js';
import { createLogger, errorLogAttributes } from '../internal/observability/logger.js';
import { createMetrics } from '../internal/observability/metrics-budget.js';
import { safeEmit } from '../internal/observability/safe-emit.js';
import { createTracer } from '../internal/observability/tracer.js';
import type { OnWarning } from '../internal/observability/warning.js';
import { PersonaManager } from '../internal/persona/persona.js';
import {
  nonObjectPrototypeProperty,
  ownProperty,
} from '../internal/prototype-safety/own-property.js';
import type { QtspServiceCertificate } from '../internal/trust/etsi-tsl/index.js';
import type { Storage } from '../storage/storage.js';
import { AaFacade } from './aa/facade.js';
import { receiveCredentialWith } from './credential/index.js';
import { buildDidResolver, readRpcUrls } from './did/did-resolver.js';
import { EudiFacade } from './eudi/index.js';
import { GdprFacade } from './gdpr/index.js';
import { buildReceivedIssuerTrust, type ReceivedIssuerTrust } from './issuer-trust/index.js';
import type { Logger, Metrics, Tracer, WalletOptions } from './options.js';
import { RecoveryFacade } from './recovery/facade.js';
import {
  type ActiveSignerOptions,
  createPersonaSigningResolver,
  type ExternalKeyProvider,
} from './setup.js';
import { StatusFacade } from './status/index.js';
import type { Wallet } from './types.js';
import { WalletImpl } from './wallet.js';
import { WalletRecordStore } from './wallet-record.js';

/**
 * Wallet ファサードを生成する。内部で `KeyManager` / `Resolver` を生成し、標準の DID
 * メソッドを Resolver に登録する。
 *
 * @param opts 生成オプション（`storage` は必須）。
 * @returns 初期化済みの Wallet。
 */
export async function createWallet(opts: WalletOptions): Promise<Wallet> {
  // 構造化ログ。未注入なら no-op に落ち、注入時は PII マスキングを
  // 挟んだラッパになる。ロガーはプロトタイプメソッドで実装されるのが正当な DI 依存なので
  // own 限定にはしない（`Object.prototype` 由来だけを弾く）。keymanager（下）が生成時に
  // メトリクスを必要とするため、ここで先に組み立てる。
  const logger = createLogger(nonObjectPrototypeProperty<Logger>(opts, 'logger'));
  // メトリクス。未注入なら in-memory 既定に落ち、いずれの場合も
  // ラベルカーディナリティ予算を挟んだラッパになる。予算違反の warn は上の `logger` へ出す。
  // ロガーと同じくプロトタイプメソッドで実装されるのが正当な DI 依存なので own 限定にはしない。
  const metrics = createMetrics(nonObjectPrototypeProperty<Metrics>(opts, 'metrics'), logger);
  // storage を渡してニーモニックの暗号化永続化（exportMnemonic の前提）を可能にする。
  // `encrypt`（`vericerts_storage_encrypt_duration_seconds`）だけ計装した
  // サブクラスを使う。計装をここに寄せることで `wallet.ts`（薄いファサード）は素通し委譲のまま保てる。
  //
  // `storage` / `kdf` は `opts.x` の鎖読みでリテラルへ詰め直さない（KeyManager 側の own 限定読みが
  // 継承値を「呼び出し側の指定」と区別できなくなる）。`storage` はメソッドを prototype に持つ
  // クラス実装が正当なので `Object.prototype` 由来だけを弾き、純データの `kdf` は own 限定で読む。
  // 未指定のキーは生やさず、指定されたものだけを渡す。
  const storage = nonObjectPrototypeProperty<Storage>(opts, 'storage') as Storage;
  const kdf = ownProperty<KdfParams>(opts, 'kdf');
  const keymanager = new MetricsInstrumentedKeyManager(
    { ...(kdf === undefined ? {} : { kdf }), storage },
    metrics,
  );
  // did:key を含む標準の DID メソッドを備えた Resolver を構築する（did-resolver.ts に委譲）。
  const { resolver, method } = buildDidResolver(opts);
  // 取り込んだ DID のペルソナで署名するときの共通設定（DID の再照合に使う Resolver と外部秘密鍵の提供元）。
  // 提供元は `opts` のメソッドとして実装されるのが正当な DI なので own 限定にはせず（`Object.prototype` 由来だけ弾く）、
  // 呼び出し時のレシーバを `opts` に束ねる。
  const externalKeyProvider = nonObjectPrototypeProperty<ExternalKeyProvider>(
    opts,
    'externalKeyProvider',
  );
  const signing: ActiveSignerOptions = {
    resolver: createPersonaSigningResolver(resolver),
    ...(externalKeyProvider === undefined
      ? {}
      : { externalKeyProvider: (did: string) => externalKeyProvider.call(opts, did) }),
  };
  // ペルソナ管理は keymanager（HD 派生）と did:key 生成（createDidKey）を共有する。
  const personas = new PersonaManager(keymanager, storage, createDidKey);
  // ウォレットルートエンティティの永続化層。ペルソナ切替（切替イベント）で
  // ルートの updatedAt を更新し、「最終更新日時」を実際の状態変化に追従させる（初回切替時に id /
  // createdAt の採番と永続化も行われる）。touch の拒否（メタデータ破損等）は切替処理の成否に影響させず、
  // unhandled rejection にもならないよう logger へ流す。
  //
  // ルートメタデータの読み取り（WalletRecordStore.get）は内部用で、Wallet の公開 API には含めない。
  const walletRecordStore = new WalletRecordStore(storage, personas);
  personas.onPersonaSwitch(() => {
    walletRecordStore.touch().catch((error: unknown) => {
      safeEmit(() =>
        logger.warn('wallet.record.touch', {
          component: 'sdk.wallet',
          ...errorLogAttributes(error),
        }),
      );
    });
  });
  // delegation（controller 検出・Tx 構築）の依存。eventSource は did:ethr と同じ
  // rpcUrls を共有し、abiEncoder は ERC-1056 書き込み ABI の既定実装を用いる。
  const eventSource = createEthersEventSource(readRpcUrls(opts));
  const abiEncoder = createErc1056AbiEncoder();
  // GDPR Compliance APIの基盤。Dashboard ログ（JWS 署名 + Merkle chain）と
  // VC レコードストアを組み立て、markCredentialDisputed 等の GDPR 操作に供する。
  // 末尾アンカーの書込失敗など、気づきたい失敗は `onWarning`（未指定なら何も通知しない）へ流す。
  // prototype メソッドの DI も受理し、元 options の receiver と非同期の戻り値を保つ。
  const onWarning = nonObjectPrototypeProperty<OnWarning>(opts, 'onWarning');
  const dashboardLog = new DashboardLog(
    storage,
    undefined,
    onWarning === undefined ? undefined : (warning) => onWarning.call(opts, warning),
  );
  const credentials = new CredentialStore(storage, dashboardLog);
  const gdpr = new GdprFacade(credentials, personas, keymanager, signing);
  // AA 緊急 Validator 失効。Dashboard ログは上と同じインスタンスを共有する。
  // ログ記録失敗は他コンポーネントと同じ構造化ロガー経由に揃える（`console.error` へ生の例外を
  // 流すと PII マスキング・no-op 既定を迂回するため。`component: 'sdk.aa'` は schemas/log-entry.json の列挙値）。
  const aa = new AaFacade(
    keymanager,
    personas,
    dashboardLog,
    logger.child({ component: 'sdk.aa' }),
    signing,
  );
  // Token Status List 解決器生成。Fail-open 判定の監査ログ記録先は
  // 既定でこの Wallet の dashboardLog（上）へアクティブペルソナ鍵付きで結線される（StatusFacade 参照）。
  const status = new StatusFacade(dashboardLog, personas, keymanager, signing);
  const createStatusListResolver: Wallet['createStatusListResolver'] = (opts) =>
    status.createStatusListResolver(opts);
  // EUDIの (Q)EAA Catalogue。未設定は「空の Catalogue」= すべて未登録
  // （receiveEAA は 10003）に倒す。純データのため own 限定で読む（鎖読みだと Catalogue を
  // **指定していない**呼び出しが `Object.prototype.eudiCatalogue` の汚染値を参照源にしてしまい、
  // 攻撃者が選んだ vct を「登録済み」にできる）。
  const eudiCatalogue =
    ownProperty<AttestationCatalogueSource>(opts, 'eudiCatalogue') ??
    createRecordCatalogueSource({});
  // fetch シームは prototype メソッドとして実装されるのが正当な DI なので own 限定にはしない
  // （`own-property.ts`「どちらのヘルパーを使うか」）。**同時にレシーバをここで束ねる**
  // （`internal/fetch-di.ts` 規則 2）。シームは関数値のまま下流へ配られ、受け取る
  // `fetchJsonWithinLimits` が束ね直せるのは合成リテラルだけなので、ここで束ねないと
  // `class Deps { eudiFetchImpl() { return this.agent.fetch(…) } }` 形の注入が `this` を失う
  // （失敗は catch されて `3010` issuer_key_unresolved の幻の障害になる）。グローバル `fetch`
  // そのものを明示注入した場合は束ねない（`bindInjectedFetch`）。
  const eudiFetchImpl = bindInjectedFetch(opts, 'eudiFetchImpl');
  // `verifyDIDConfiguration` の取得シームも同じ理由・同じ規則で読む。
  const didConfigurationFetchImpl = bindInjectedFetch(opts, 'didConfigurationFetchImpl');
  // 信頼済み Wallet Provider 署名鍵。純データ（JWK）なので own 限定で読む（鎖読みだと鍵を
  // **指定していない**呼び出しが `Object.prototype.walletProviderJwk` の汚染値を検証鍵に採り、
  // 攻撃者が署名した WUA が「検証済み」として保持される）。未設定なら `obtainWalletAttestation`
  // は検証を省略せず `10102` で閉じる（`wallet/eudi/facade.ts`）。
  const walletProviderJwk = ownProperty<PublicKeyJwk>(opts, 'walletProviderJwk');
  // WSCD バインド検証の照合基準。同じく純データなので own 限定で読む（鎖読みだと
  // 鍵を**指定していない**呼び出しが `Object.prototype.wscdPublicKeyJwk` の汚染値を基準に採り、
  // 攻撃者が選んだ鍵にバインドされた WUA が「WSCD バインド済み」として通る）。
  const wscdPublicKeyJwk = ownProperty<PublicKeyJwk>(opts, 'wscdPublicKeyJwk');
  // JAR JWS 署名検証の信頼の起点。純データ（証明書 DER の配列）なので
  // own 限定で読む（鎖読みだと Trust Anchor を**指定していない**呼び出しが
  // `Object.prototype.rpTrustAnchors` の汚染値を起点に採り、**攻撃者 CA が発行した RP 証明書で
  // 署名された任意の提示要求が「検証済み」として提示 UI へ通る**）。未設定なら参照形式の提示要求は
  // 検証を省略せず `8030` で閉じる（`internal/auth/jar/jar-signature.ts`）。
  const rpTrustAnchors = ownProperty<readonly QtspServiceCertificate[]>(opts, 'rpTrustAnchors');
  // 受領した SD-JWT VC の Issuer 鍵解決（`x5c` / JWT VC Issuer Metadata / DID）
  // に使う信頼材料。読み取りの規律と対になる書き込みの規律（`undefined` でも own プロパティとして
  // 載せる）があるため、組み立ては読み取り側と同じモジュールに置いている
  // （`issuer-trust/resolve.ts` の {@link buildReceivedIssuerTrust}）。
  const issuerTrust: ReceivedIssuerTrust = buildReceivedIssuerTrust(opts, resolver, eudiFetchImpl);
  // 分散トレース。未注入なら no-op。Tracer もプロトタイプメソッドで
  // 実装されるのが正当な DI 依存なので、ロガーと同じく own 限定にはしない。
  const tracer = createTracer(nonObjectPrototypeProperty<Tracer>(opts, 'tracer'));
  const eudi = new EudiFacade(
    personas,
    keymanager,
    eudiCatalogue,
    metrics,
    // 受領した PID / (Q)EAA の Issuer 署名を既定検証するための信頼材料を渡す（
    // `wallet.receiveCredential` が同じ `issuerTrust` を使うのと同じ経路・同じ規則）。
    issuerTrust,
    eudiFetchImpl,
    walletProviderJwk,
    wscdPublicKeyJwk,
    rpTrustAnchors,
    signing,
  );
  // ウォレット完全復旧。WUA 再発行は上の eudi を再利用し、
  // 発行前のペルソナ確保に personas を使う（新端末復旧ではペルソナが 1 件も無い）。
  const recovery = new RecoveryFacade(keymanager, walletRecordStore, eudi, personas, storage);
  // `receiveCredential`は `createStatusListResolver` と同じく生成側で束ねて渡す
  // （`WalletImpl` の行数上限対応。アクティブペルソナ解決と `issuerTrust` をここで結線する）。
  const receiveCredential: Wallet['receiveCredential'] = (offerURI, opts) =>
    receiveCredentialWith(personas, keymanager, issuerTrust, offerURI, opts, signing);
  // WalletImpl の行数上限対応で aa / recovery を 1 パラメータへ束ねる（`Wallet` の該当メソッドのみ公開）。
  const aaAndRecovery: Pick<
    Wallet,
    | 'emergencyRevokeValidator'
    | 'importMnemonic'
    | 'importRecoveredWallet'
    | 'recoverFromShamirShares'
  > = {
    emergencyRevokeValidator: (reason, opts) => aa.emergencyRevokeValidator(reason, opts),
    importMnemonic: (mnemonic, passphrase, language, options) =>
      recovery.importMnemonic(mnemonic, passphrase, language, options),
    importRecoveredWallet: (mnemonic, opts) => recovery.importRecoveredWallet(mnemonic, opts),
    recoverFromShamirShares: (shares, opts) => recovery.recoverFromShamirShares(shares, opts),
  };
  return new WalletImpl(
    storage,
    keymanager,
    resolver,
    method,
    personas,
    eventSource,
    abiEncoder,
    didConfigurationFetchImpl,
    eudi,
    logger,
    metrics,
    tracer,
    createStatusListResolver,
    receiveCredential,
    aaAndRecovery,
    gdpr,
    signing,
  );
}
