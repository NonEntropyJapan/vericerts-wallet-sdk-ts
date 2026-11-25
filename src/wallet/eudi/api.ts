/**
 * Wallet で PID・(Q)EAA を受領・提示し、Wallet Unit Attestation（WUA）を取得・利用するためのインターフェース。
 *
 * `Wallet` 本体（`types.ts`）が肥大化しないよう、EUDI の受領・提示メソッドを本インターフェースへ
 * 切り出し、`Wallet` が `extends` する（`../gdpr/api.ts` の `GdprApi` と同パターン）。実装は
 * `wallet.ts` の `WalletImpl` が `EudiFacade`（`facade.ts`）へ委譲する。
 *
 * 受領・提示の手続きは内部プリミティブ（`internal/eudi/issuance` /
 * `internal/eudi/presentation`）が担う。本インターフェースはそれらに「アクティブペルソナ由来の
 * 署名鍵」と「セッション内の受領済み Credential」を与える薄い層である。
 */

import type { PresentOptions } from '../../internal/auth/eudi/presentation/index.js';
import type { VerifiablePresentation } from '../../internal/credential/index.js';
import type {
  EAACredential,
  EAAReceiveOptions,
  PIDAttributeName,
  PIDCredential,
  PIDReceiveOptions,
} from '../../internal/eudi/pid/index.js';
import type { WalletUnitAttestation, WuaPopOptions } from '../../internal/eudi/wua/index.js';

/**
 * PID と (Q)EAA の受領・提示、および Wallet Unit Attestation の取得・利用を扱う。
 *
 * 成熟度は各メソッドの JSDoc に記載する。実験的なメソッドも `Wallet` から直接呼び出せる。
 * これらのメソッド自体は、呼び出し時に成熟度を知らせるランタイム警告を出さない。
 */
export interface EudiApi {
  /**
   * OID4VCI Pre-Authorized Code Flow で PID を受領する。
   *
   * 受領した PID はセッション内に保持し、以降の `presentPID` が `opts.credential` 省略時の
   * 提示対象として使う（保持は**メモリのみ**。`EudiFacade` の JSDoc 参照）。
   *
   * **受領した PID の Issuer 署名は既定で検証する**（挙動変更・後方非互換）。
   * `wallet.receiveCredential` と同じ順序で Issuer 鍵の解決経路を選ぶ。
   *
   * 1. Issuer-signed JWT ヘッダの `x5c` → `createWallet({ issuerTrustAnchors })` の ETSI TSL
   *    Trust Anchor まで検証し、`iss` が leaf 証明書の SubjectAltName と一致することも確かめる。
   * 2. `x5c` が無く `createWallet({ jwtVcIssuerMetadataResolution: true })` を指定していて `iss` が
   *    HTTPS URL → JWT VC Issuer Metadata（`/.well-known/jwt-vc-issuer`）。**既定は off** で、
   *    未指定なら取得に行かない。
   * 3. それ以外 → `iss` を `Wallet` が持つ DID Resolver で解決する。
   *
   * どの経路でも鍵を得られなければ `3010`（`reason: 'issuer_key_unresolved'`）、鍵は
   * 得られたが署名が合わなければ `3010`（`reason: 'received_credential_signature_invalid'`）、署名不一致以外
   * の失敗（`3002` / `3024` 等）は元のコードのまま返して fail-closed。
   * `opts.verifyReceived` を渡した場合はそれが既定検証を**置換**する（上記 3 経路
   * では表せない鍵解決を持ち込む運用のための出口。検証を省くなら no-op を渡す）。
   *
   * @param offerURI `openid-credential-offer://` 形式の Credential Offer URI。
   * @param opts `walletAttestation: true` で Token Request に WUA を添付する。
   *        `verifyReceived` で既定の署名検証を置換する。
   * @returns 受領・署名検証・ARF PID Rulebook 検証済みの PID Credential。
   * @throws アクティブペルソナ未設定（VericertsError、code `2005`）、grant 不正（`3003`）、
   *         Issuer Metadata 取得失敗（`3004`）、Issuer 署名不一致（`3010`。期限切れ `3024` 等は元のコード）、
   *         Token Request 失敗（`8010`）、
   *         Credential Request 失敗（`8020`）、必須属性欠落（`10002`）、スキーマ / `vct` 違反
   *         （`10001`）、WUA 未保持のまま `walletAttestation: true`（`10101`）の場合。
   *
   * @experimental v1.0 での安定化を予定している。それまでは挙動やシグネチャが変わることがある。
   */
  receivePID(offerURI: string, opts?: PIDReceiveOptions): Promise<PIDCredential>;
  /**
   * OID4VP `direct_post` で PID を選択的開示して提示する。
   *
   * 提示対象は `opts.credential`、省略時は直近に `receivePID` で受領した PID。どちらも無い場合は
   * 推測で提示せず fail-closed に落とす。
   *
   * @param requestURI OID4VP Authorization Request URI。
   * @param disclosedClaims 開示する PID 属性名（同意取得済みの範囲）。
   * @param opts 提示する PID Credential を明示する場合に指定する。
   * @returns 送信した vp_token を保持する `VerifiablePresentation`（提示記録）。
   * @throws アクティブペルソナ未設定（VericertsError、code `2005`）、要求解析失敗（`8030`）、
   *         提示対象 PID 不在・送信失敗（`8035`）の場合。
   *
   * @experimental v1.0 での安定化を予定している。それまでは挙動やシグネチャが変わることがある。
   */
  presentPID(
    requestURI: string,
    disclosedClaims: PIDAttributeName[],
    opts?: PresentOptions,
  ): Promise<VerifiablePresentation>;
  /**
   * OID4VCI Pre-Authorized Code Flow で (Q)EAA を受領する。
   *
   * 受領した VC の `vct` を (Q)EAA Catalogue で解決し、未登録なら受け入れない。Catalogue は
   * `createWallet` の `eudiCatalogue` で与える（省略時は空 = すべて未登録扱い）。受領した
   * (Q)EAA はセッション内に追記保持し、`presentEAA` の提示候補になる。
   *
   * `receivePID` と同じく**受領した (Q)EAA の Issuer 署名を既定で検証する**。
   * `opts.verifyReceived` を渡した場合はそれが既定検証を置換する。
   *
   * @param offerURI `openid-credential-offer://` 形式の Credential Offer URI。
   * @param opts `verifyReceived` で既定の署名検証を置換する。
   * @returns 受領・署名検証済みの (Q)EAA Credential。
   * @throws アクティブペルソナ未設定（VericertsError、code `2005`）、grant 不正（`3003`）、
   *         Issuer Metadata 取得失敗（`3004`）、Issuer 署名不一致（`3010`。期限切れ `3024` 等は元のコード）、
   *         Token Request 失敗（`8010`）、
   *         Credential Request 失敗（`8020`）、Catalogue 未登録（`10003`）の場合。
   *
   * @experimental v1.0 での安定化を予定している。それまでは挙動やシグネチャが変わることがある。
   */
  receiveEAA(offerURI: string, opts?: EAAReceiveOptions): Promise<EAACredential>;
  /**
   * OID4VP `direct_post` で (Q)EAA を提示する。
   *
   * セッション内に保持している (Q)EAA から `vctFilter` に一致するものを選び、その top-level
   * クレームをすべて開示する。一致するものが 1 件も無い場合は `8035`（Catalogue 未登録を表す
   * `10003` ではない。`internal/auth/eudi/presentation/present.ts` の判断）。
   *
   * @param requestURI OID4VP Authorization Request URI。
   * @param vctFilter 提示対象の VC Type URI。
   * @returns 送信した vp_token を保持する `VerifiablePresentation`（提示記録）。
   * @throws アクティブペルソナ未設定（VericertsError、code `2005`）、要求解析失敗（`8030`）、
   *         該当 Credential なし・送信失敗（`8035`）の場合。
   *
   * @experimental v1.0 での安定化を予定している。それまでは挙動やシグネチャが変わることがある。
   */
  presentEAA(requestURI: string, vctFilter: string): Promise<VerifiablePresentation>;
  /**
   * Wallet Provider Backend から WUA を取得して現行 WUA として保持する。
   *
   * 取得した WUA は Wallet Provider 署名・`vct`・期限を検証したうえで保持する（保持は**メモリ
   * のみ**）。検証鍵は `createWallet({ walletProviderJwk })` で与える**信頼済み**の鍵で、応答が
   * 同梱する鍵は採用しない。鍵を信頼できるかは呼び出し側が判断する。
   * 未設定のまま呼ぶと検証を省略せず `10102` で失敗する（fail-closed）。
   *
   * @param providerEndpoint WUA 発行エンドポイント（HTTPS のみ）。
   * @returns 検証済みの現行 WUA。
   * @throws 非 HTTPS・通信失敗・タイムアウト・非 2xx・平文へのリダイレクト・非 JSON・JWT
   *         フィールド欠落（VericertsError、code `10101`、再試行可）、Wallet Provider 鍵未設定・
   *         署名 / `vct` 不正（`10102`）、取得した WUA が期限切れ（`10103`）の場合。
   *
   * @experimental v1.0 での安定化を予定している。それまでは挙動やシグネチャが変わることがある。
   */
  obtainWalletAttestation(providerEndpoint: string): Promise<WalletUnitAttestation>;
  /**
   * 現行 WUA を返す（同期）。
   *
   * `obtainWalletAttestation` を一度も成功させていない場合と、保持している WUA が**期限切れ**に
   * なった場合は `null`（期限切れを返すと呼び出し側が提示に回せてしまうため）。保持は
   * `Storage` へ書かない**メモリのみ**（セッションスコープ）で、同期のアクセサからは非同期の
   * `Storage` を読めないためこの API は永続化された WUA を返さない。
   *
   * @returns 有効な現行 WUA。未取得・期限切れなら `null`。
   *
   * @experimental v1.0 での安定化を予定している。それまでは挙動やシグネチャが変わることがある。
   */
  getWalletAttestation(): WalletUnitAttestation | null;
  /**
   * 現行 WUA にバインドされた署名鍵で WUA-PoP JWT を生成する。
   *
   * `client_assertion` を手動で組み立てるときに使う。SDK が現行 WUA、署名鍵、現在時刻を解決し、
   * 呼び出し側は `aud` と `nonce` を指定する。`receivePID` では `walletAttestation: true` を指定すると
   * SDK がクライアントアテステーションを生成して添付する。
   *
   * @param opts `aud` / `nonce` と任意の有効期間・`jti`。
   * @returns WUA-PoP JWT（コンパクト JWS）。
   * @throws 現行 WUA 未保持（VericertsError、code `10101`）、保持分が期限切れ（`10103`）、
   *         アクティブペルソナ未設定（`2005`）、signer 鍵が `cnf.jwk` と不一致（`10102`）の場合。
   *
   * @experimental v1.0 での安定化を予定している。それまでは挙動やシグネチャが変わることがある。
   */
  buildWuaProofOfPossession(opts: WuaPopOptions): Promise<string>;
  /**
   * 期限切れ（または期限が近い）現行 WUA を、Wallet Provider が再発行した新 WUA JWT へ
   * 差し替える。
   *
   * 新 WUA JWT の取得（Wallet Provider Backend への再取得リクエスト）は呼び出し側の責務で、
   * 取得済みの JWT を渡すと検証のうえ現行 WUA として差し替える。実体は
   * `internal/eudi/wua/wua.ts` の `refreshWalletAttestation`（旧 WUA・信頼済み Wallet Provider
   * 鍵・現在時刻は SDK 側が解決する）。
   *
   * @param refreshedJwt Wallet Provider が再発行した新 WUA JWT（コンパクト JWS）。
   * @returns 検証済みの新 WUA（以降 `getWalletAttestation()` が返す現行 WUA）。
   * @throws 現行 WUA 未保持（VericertsError、code `10101`）、`walletProviderJwk` 未設定・
   *         新 WUA の署名 / `vct` / WSCD バインド不正の場合（`10102`）、新 WUA が期限切れの場合
   *         （`10103`）。
   *
   * @experimental v1.0 での安定化を予定している。それまでは挙動やシグネチャが変わることがある。
   */
  refreshWalletAttestation(refreshedJwt: string): WalletUnitAttestation;
}
