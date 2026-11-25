/**
 * Wallet ファサードの公開オプション型。
 *
 * `Wallet` interface 本体は `types.ts`。本ファイルは生成・メソッド呼び出しのオプション型
 * （`Logger` / `WalletOptions` / `ImportMnemonicOptions`）を集約する。DID 系メソッドの型は `did/options.ts`。
 */

import type { FetchLike } from '../internal/auth/oid4vci/oid4vci.js';
import type { AttestationCatalogueSource } from '../internal/eudi/pid/index.js';
import type { PublicKeyJwk } from '../internal/identity/did.js';
import type { KdfParams } from '../internal/keymanager/kdf.js';
import type { Logger } from '../internal/observability/logger.js';
import type { Metrics } from '../internal/observability/metrics.js';
import type { Tracer } from '../internal/observability/tracer.js';
import type { OnWarning } from '../internal/observability/warning.js';
import type { QtspServiceCertificate } from '../internal/trust/etsi-tsl/index.js';
import type { Storage } from '../storage/storage.js';
import type { DidNodeUrls } from './did/did-node-urls.js';
import type { ExternalKeyProvider } from './setup.js';

/**
 * 相関 ID の公開型。
 *
 * 実体は `internal/observability/correlation.ts` にあり、ここは公開 API としての再エクスポート。
 * 呼び出し側（Extension の Background SW 等）は上流で発行した `traceparent` / `X-Request-Id` を
 * この形で SDK へ引き渡す。
 */
export type {
  CorrelationContext,
  CreateCorrelationContextInput,
} from '../internal/observability/correlation.js';

/**
 * 構造化ログの公開型。
 *
 * 実体は `internal/observability/logger.ts` にあり、ここは公開 API としての再エクスポート。
 * 呼び出し側はこの形の実装（`pino` / `winston` / `console` のアダプタ等）を
 * `WalletOptions.logger` に渡す。
 */
export type { LogAttributes, Logger, LogValue } from '../internal/observability/logger.js';
/**
 * メトリクスの公開型。
 *
 * 実体は `internal/observability/metrics.ts` にあり、ここは公開 API としての再エクスポート。
 * 呼び出し側はこの形の実装（Prometheus / OpenTelemetry Meter のアダプタ等）を
 * `WalletOptions.metrics` に渡す。
 */
export type {
  Counter,
  Gauge,
  Histogram,
  Labels,
  Metrics,
} from '../internal/observability/metrics.js';
/**
 * 分散トレースの公開型。
 *
 * 実体は `internal/observability/tracer.ts` にあり、ここは公開 API としての再エクスポート。
 * 呼び出し側はこの形の実装（OpenTelemetry Tracer のアダプタ等）を `WalletOptions.tracer` に渡す。
 */
export type {
  Attributes,
  AttributeValue,
  Span,
  SpanOptions,
  Tracer,
} from '../internal/observability/tracer.js';
export type { OnWarning, SdkWarning } from '../internal/observability/warning.js';

/** Wallet 生成オプション。 */
export interface WalletOptions {
  /** 永続化バックエンド（必須）。DID Document の保存に用いる。 */
  readonly storage: Storage;
  /** `KeyManager` の KDF パラメータの上書き（省略時は既定 `DEFAULT_KDF` = argon2id m=19456,t=2）。 */
  readonly kdf?: KdfParams;
  /** JSON-RPC エンドポイント（asset / aa 用に予約）。 */
  readonly rpcUrl?: string;
  /**
   * did:ethr 解決用のチェーン ID → RPC URL マップ。
   *
   * `resolveDID` で did:ethr を解決する際、当該 chainId の RPC URL を用いて
   * ERC-1056 イベントをスキャンする。未設定（マップに無い）チェーンの did:ethr は
   * `DID_NOT_FOUND`（code `2003`）になる。
   */
  readonly rpcUrls?: Readonly<Record<number, string>>;
  /** did:ipid の DID Document を取得する IPFS Gateway URL。既定値は `https://ipfs.io`。 */
  readonly ipfsGatewayUrl?: string;
  /** did:ipid の公開（create / update）に用いる IPFS HTTP API URL。既定値は `http://localhost:5001`。 */
  readonly ipfsApiUrl?: string;
  /** did:ebsi / did:ion / did:cheqd の解決先 URL。`https:` のみ指定でき、未指定のメソッドを解決すると `2002` になる。 */
  readonly didNodeUrls?: DidNodeUrls;
  /**
   * 取り込んだ DID のペルソナ（`keySource: 'external'`）の秘密鍵 JWK を DID 指定で返すコールバック。署名のたびに
   * アクティブペルソナの DID で呼び、SDK は鍵を保存せず署名の間だけ使う。省略・`undefined`・例外は
   * `DID_SIGNING_KEY_UNAVAILABLE`（code `2007`、fail-closed）。署名のたびに DID をキャッシュなしで解決し直して保持鍵と
   * 照合し、不一致（鍵のローテーション・削除）は `DID_KEY_MISMATCH`（code `2017`）。
   */
  readonly externalKeyProvider?: ExternalKeyProvider;
  /**
   * (Q)EAA Catalogue（vct → `AttestationCatalogueEntry`）の参照源。
   *
   * `receiveEAA` は受領した VC の `vct` をここで解決し、**未登録なら受け入れない**。
   * 省略時は空の Catalogue（`createRecordCatalogueSource({})`）を用いるため、あらゆる `vct` が
   * 未登録扱いになり `receiveEAA` は `EAA_CATALOGUE_NOT_FOUND`（code `10003`）で失敗する。
   * 既定を「全許可」にしないのは、Catalogue 未設定という設定漏れが「未知の型の (Q)EAA を無検査で
   * 受け入れる」状態に化けるのを避けるためである（fail-closed）。
   */
  readonly eudiCatalogue?: AttestationCatalogueSource;
  /**
   * EUDI の受領・提示経路（OID4VCI の Metadata / Token / Credential と OID4VP の VP Token 送信）で
   * 使う `fetch` の差し替えシーム。省略時はグローバル `fetch`。
   *
   * 内部プリミティブの `ReceiveDeps.fetchImpl` / `PresentDeps.fetchImpl` と同じ役割で、
   * テスト注入（グローバル `fetch` を差し替えない）と、証明書ピンニング付き `fetch` の注入を
   * 想定する。`SubmitFetchLike`（OID4VP 送信）は `FetchLike` より init が 1 フィールド広いだけ
   * なので、本 1 つで両経路をまかなえる。
   */
  readonly eudiFetchImpl?: FetchLike;
  /**
   * `verifyDIDConfiguration` が `.well-known/did-configuration.json` を取得するときに使う `fetch`
   * の実装。省略時はグローバル `fetch`。
   *
   * `eudiFetchImpl` と同じ役割（テスト注入・証明書ピンニング付き `fetch` の注入）だが、取得先が
   * 「検証対象ドメイン」であり EUDI の発行者・Verifier とは信頼の前提が別なので、1 つのシームに
   * 束ねず別オプションとする。
   */
  readonly didConfigurationFetchImpl?: FetchLike;
  /**
   * **信頼済み** Wallet Provider の署名鍵（EC 公開鍵 JWK）。
   *
   * `obtainWalletAttestation` が取得した WUA の署名検証に使う。この鍵の信頼判定（ETSI TSL /
   * OpenID Federation / ARF Wallet Provider Registry で当該 Wallet Provider の鍵だと確かめること）
   * は**呼び出し側の責務**である。
   *
   * SDK が応答同梱の鍵を代わりに使うことはない。取得元が渡してきた鍵でその取得元の署名を
   * 検証しても何も検証したことにならず、中間者が差し替えた WUA がそのまま「検証済み」になる
   * ためである。したがって**省略時は取得を検証省略で通さず** `WUA_VERIFICATION_FAILED`
   * （code `10102`、`context.reason = 'provider_key_not_configured'`）で失敗する（fail-closed）。
   */
  readonly walletProviderJwk?: PublicKeyJwk;
  /**
   * WSCD（Passkey / TEE）由来の公開鍵 JWK。
   *
   * 設定すると `obtainWalletAttestation` は取得した WUA の `cnf.jwk` がこの鍵にバインドされて
   * いることも検証し、不一致なら `WUA_VERIFICATION_FAILED`（code `10102`）で失敗する（不一致の
   * WUA は現行 WUA として保持されない）。省略時はバインド検証を行わない — 検証の基準となる
   * WSCD 鍵は SDK が自力で取得できず（WebAuthn の鍵はプラットフォームが保持する）、基準が無い
   * まま「一致した」と判定することはできないためである。
   */
  readonly wscdPublicKeyJwk?: PublicKeyJwk;
  /**
   * **信頼済み** RP Access Certificate の Trust Anchor（ETSI TSL / LOTL 由来の QTSP サービス
   * 証明書）。
   *
   * `presentPID` / `presentEAA` が `request_uri` 参照形式（JAR）の提示要求を解決するときの
   * **JAR JWS 署名検証の信頼の起点**である（HAIP §5.1 は JAR の `request_uri` 経由取得を
   * 必須とする）。`loadTrustedList` → `extractQtspCertificates` で得た集合をそのまま渡す。
   *
   * **渡す前に `loadTrustedList` の `signatureAnchored` を検査すること**（`signing-anchor/index.ts`）。
   * `false` は「Trusted List 文書の署名者がどの Trust Anchor にも連結していない」＝この集合の出どころが
   * 取得元 URL への TLS だけに依存している、の意である。`QtspServiceCertificate` は由来を持たないため
   * **SDK 側から `signatureAnchored: false` 由来の入力を識別する手段は無い**。
   *
   * SDK が LOTL / TSL を代わりに取得することはない。取得タイミングとキャッシュ方針
   * （`TrustedListFetcher` の DI シーム）はアプリの責務であり、SDK が起動時に固定すると
   * 「いつ取得した信頼リストか判らない」状態で署名検証を行うことになるためである。したがって
   * **省略時は検証省略で通さず**、参照形式の提示要求を `OID4VP_REQUEST_PARSE_FAILED`
   * （code `8030`、`context.reason = 'jar_trust_anchors_unconfigured'`）で拒否する
   * （fail-closed。`walletProviderJwk` 未設定時に WUA 取得が `10102` で閉じるのと同じ方針）。
   * 直接形式の提示要求には署名対象が無いため本オプションは不要である。
   */
  readonly rpTrustAnchors?: readonly QtspServiceCertificate[];
  /**
   * **信頼済み** PID / (Q)EAA Issuer の Trust Anchor（ETSI TSL / LOTL 由来の QTSP サービス証明書）。
   * 受領した SD-JWT VC の `x5c` 証明書チェーンを検証し、証明書の SAN と `iss` を照合する。
   * この経路には発行者用の Trust Anchor が必要で、省略時は `3010` を返す。`rpTrustAnchors` は提示要求の検証に使う。
   * `loadTrustedList` の `signatureAnchored` 検査が要る点は `rpTrustAnchors` と同じ。
   */
  readonly issuerTrustAnchors?: readonly QtspServiceCertificate[];
  /**
   * 受領した SD-JWT VC の Issuer 鍵を **JWT VC Issuer Metadata**
   * （`/.well-known/jwt-vc-issuer`、draft-ietf-oauth-sd-jwt-vc §5）からも解決するか。**既定は `false`**。
   *
   * 名前に文書名（`jwtVcIssuer`）を含めるのは、SDK が別の場所で「Issuer Metadata」と呼ぶ
   * OID4VCI の `/.well-known/openid-credential-issuer`（発行フローのエンドポイント探索に使う。
   * `3004` の取得失敗はそちら）と取り違えないためである。本オプションが指すのは**鍵解決に使う
   * `/.well-known/jwt-vc-issuer`** だけで、OID4VCI の Issuer Metadata 取得には影響しない。
   *
   * この経路は **Issuer 自身のホスト（WebPKI / TLS）だけを信頼の起点とする**ため、ETSI TSL
   * Trust Anchor を起点とする `x5c` 経路（`issuerTrustAnchors`）とは信頼の強さが違う。既定で
   * 有効にすると **HTTPS の `iss` を名乗るあらゆるホストが自分の鍵を自分で証明できる**ことになり、
   * 現在 `3010`（`issuer_key_unresolved`）で閉じている面がすべて開く。したがって opt-in とし、
   * **未指定なら HTTP リクエストを 1 度も行わない**（従来の挙動が変わらない）。
   *
   * 有効化しても `x5c` が常に優先で、本経路に入るのは `x5c` を持たず `iss` が HTTPS URL の VC
   * だけである。`iss` と metadata の `issuer` の不一致・非 HTTPS の `iss` はいずれも `3010` で
   * fail-closed。取得結果は SDK 側でキャッシュしない（取得タイミングは `eudiFetchImpl` に注入する
   * `fetch` の責務。`loadTrustedList` を呼び出し側に委ねるのと同じ方針）。
   *
   * metadata の取得シームは**両受領経路とも `eudiFetchImpl`** である。信頼材料
   * （`issuerTrustAnchors` / 本オプション）が Wallet スコープである以上、その解決に使う `fetch` も
   * Wallet スコープで与える — `receiveCredential(offerURI, { fetchImpl })` の呼び出しごとの
   * シームは OID4VCI の発行者通信のためのもので、信頼の起点の解決には用いない。
   */
  readonly jwtVcIssuerMetadataResolution?: boolean;
  /** AA Bundler エンドポイント（予約済み）。 */
  readonly bundlerUrl?: string;
  /**
   * 構造化ログの出力先。省略時は SDK からログを出力しない。
   *
   * 秘密情報を渡してはならない。SDK は渡された属性に PII マスキング
   * （`*mnemonic*` 等はキーごと削除、`credentialSubject` 等は `[REDACTED]`、`email` 等は
   * ハッシュ化）を**設定変更不可で**適用してから本ロガーを呼ぶ。
   */
  readonly logger?: Logger;
  /**
   * 握りつぶした失敗のうち**気づきたいもの**を 1 件ずつ受け取る関数。省略時は何も起きない（従来どおり）。
   *
   * 対象は、結論は変えないが記録が欠ける失敗（Dashboard ログの末尾アンカーの書込失敗など）に限る。
   * ストリームの解放や未処理 rejection の回避のように、わざと捨てている後始末の失敗は呼ばない。
   * 渡す `attributes` は失敗の名前・メッセージ・コードで、PII マスキングを適用した値。
   * 例外オブジェクトそのものは渡さない。関数が投げても（Promise を返して拒否しても）SDK の処理には影響しない。
   */
  readonly onWarning?: OnWarning;
  /**
   * メトリクスの出力先。省略時はメモリ内で集計し、外部へは送信しない。
   *
   * SDK はラベル値と組合せ数の制限（`method` 等の許容外値は `other` へ、
   * `result` 等の許容外値は観測ごと拒否、1 メトリクスあたり組合せ 100 で切り捨て）を
   * **設定変更不可で**適用してから本 Metrics を呼ぶ。予算違反は例外にせず warn ログで知らせる。
   */
  readonly metrics?: Metrics;
  /**
   * 分散トレースの出力先。省略時は Span を出力しない。
   *
   * Span 名は `<component>.<operation>`。SDK は
   * 渡された属性へマスキングを掛けないため（載せる値は SDK 内部の計装側が選ぶ）、本オプションの
   * 実装が Exporter へ送る内容にも秘密情報・生の DID / URL を含めてはならない。
   */
  readonly tracer?: Tracer;
}

/**
 * `importMnemonic` のオプション。
 */
export interface ImportMnemonicOptions {
  /** 指定時はニーモニックを暗号化・永続化しアンロック状態にする（`exportMnemonic` の前提）。 */
  readonly persistPassword?: string;
}
