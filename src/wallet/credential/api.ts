/**
 * Wallet が提供する VC の受領・検証、VP の作成・検証、SD-JWT VC の発行・検証の型。
 * 成熟度はメソッドごとに示す。タグのないメソッドも experimental として扱う。
 */

import type {
  ReceiveCredentialDeps,
  ReceivedVerifiableCredential,
} from '../../internal/auth/index.js';
import type { NonceContext, NonceStore } from '../../internal/auth/nonce/index.js';
import type {
  CreateSdJwtOptions,
  IssuePresentationOptions,
  VerifiablePresentation,
  VerifiedSdJwt,
  VerifySdJwtOptions,
} from '../../internal/credential/index.js';
import type { CreatePresentationApi } from './create-presentation-api.js';
import type { MatchApi } from './match-api.js';
import type { VerifyApi } from './verify-api.js';

/**
 * VC / VP 検証のオプション型は `verify-api.ts`（`VerifyApi` と同じ場所）にある。
 * 従来どおり `./api.js` からも型付きで参照できるよう再エクスポートする（1 ファイル 300 行の
 * 上限対応で分離しただけで、公開名・意味は変わらない）。
 */
export type {
  VerifyCredentialFacadeOptions,
  VerifyPresentationFacadeOptions,
} from './verify-api.js';

/**
 * `Wallet.receiveCredential` の受領結果。
 *
 * 実体はモジュール関数版と同じ `ReceivedVerifiableCredential`（`internal/auth/oid4vci/facade/types.ts`）。
 * `presentPID` の `PresentOptions` と同じ理由で、`Wallet` メソッドの戻り値型は
 * メインバレルからも型付きで参照できる必要があるため、ここで再エクスポートする。
 */
export type { ReceivedVerifiableCredential };

/**
 * `Wallet.receiveCredential` のオプション。
 *
 * モジュール関数版 `receiveCredential`（`vericerts-wallet-sdk/experimental`。`@deprecated`）が使う
 * `ReceiveCredentialDeps` から、アクティブペルソナで解決できる `signer` / `holderDid` / `keyId` を
 * 除いたもの。`receivePID(offerURI, opts?)` と同様に、これらの値は Wallet が提供する。
 * `authorize` / `clientId` / `redirectUri` は従来どおり `authorization_code` grant の Offer でのみ
 * 必須の任意メンバで、必須性の判定は受領フロー側（grant 判別後）が行う。
 */
export type ReceiveCredentialOptions = Omit<
  ReceiveCredentialDeps,
  'signer' | 'holderDid' | 'keyId'
>;

/**
 * `verifySdJwt` のファサード向けオプション（Issuer 鍵は iss DID 解決で自動補完）。
 *
 * `nonceStore` と `nonceContext` を渡すと、KB-JWT の検証が seen-nonces cache による
 * replay 検知経路（`verifySdJwtWithReplayGuard`）を通る。
 * SDK はステートフルな nonce ストアを内蔵しない方針のため、利用側がストアを注入したときだけ
 * 使用 1 回の保証が有効になる。**両方とも渡さない**ことだけが「replay 検知を使わない」明示的な選択で、
 * **片方だけの指定は拒否する**（`nonceStore` のみ 4012 `NONCE_BINDING_MISMATCH` / `nonceContext` のみ
 * 4010 `REPLAY_DETECTED`。無言で replay 検知なしに落とさない）。
 */
export type VerifySdJwtFacadeOptions = Omit<VerifySdJwtOptions, 'issuerKey'> & {
  /** 消費記録を保持する `NonceStore`。`nonceContext` と必ず対で指定する（片方だけは拒否）。 */
  readonly nonceStore?: NonceStore;
  /** nonce の発行コンテキスト。`aud` の照合対象もここから取る。 */
  readonly nonceContext?: NonceContext;
  /** replay window（秒）の上書き。省略時は `nonceContext.flow` に応じた期間を使う。 */
  readonly replayWindowSeconds?: number;
  /** 初見 nonce を記録する際の保持期間（ms）。 */
  readonly nonceTtlMs?: number;
};

/**
 * JWT-VC / Verifiable Presentation / SD-JWT VC の発行・検証ファサード API。
 *
 * 発行系は keymanager の鍵を非公開のまま署名（`getCredentialSigner`）、検証系は JWT/SD-JWT の
 * 発行者・提示者 DID を解決して検証鍵を組み立てる。いずれも薄い委譲。VC マッチング系は `MatchApi`
 * （`match-api.ts`）、VP 作成（`createPresentation`）は `CreatePresentationApi`
 * （`create-presentation-api.ts`）、VC / VP の検証（2 層構成）は `VerifyApi`
 * （`verify-api.ts`）から合成する（いずれも linterly の 1 ファイル行数上限対応で分離）。
 */
export interface PresentationApi extends MatchApi, CreatePresentationApi, VerifyApi {
  /**
   * OID4VCI で Credential Offer から VC を受領し、解釈済みの結果を返す。
   *
   * 署名鍵・Holder DID・検証鍵 ID はアクティブペルソナから自動解決する（兄弟の `receivePID` と
   * 同じパターン）。`opts.authorize` / `opts.clientId` / `opts.redirectUri` は Offer が
   * `authorization_code` grant を告知する場合にのみ必須で、`pre-authorized_code` 限定の Offer では不要
   * （受領フロー側が grant 判別後に検査する）。
   *
   * 受領した VC の署名は**既定で検証する**（挙動変更・後方非互換）。Issuer 鍵は Wallet の
   * DID Resolver で解決し、解決できなければ `3010`（`issuer_key_unresolved`）、署名が合わなければ
   * `3010`（`received_credential_signature_invalid`）で拒否する。署名不一致以外の失敗（`3002` / `3024` 等）は
   * 元のコードのまま返す。`opts.verifyReceived` を渡した場合は
   * そちらが既定検証を**置換**する（併用しない。`x5c` / Trust Anchor 等の鍵解決を持ち込む経路のため）。
   *
   * @param offerURI OID4VCI Credential Offer URI（`openid-credential-offer:` スキーム）。
   * @param opts 認可 UI 起動関数・client 登録情報・HTTP シーム等（`signer` / `holderDid` / `keyId`
   *             はアクティブペルソナから解決するため含まない）。
   * @returns 解釈した VC の型・発行者・属性などを含む受領結果。`raw` に受領時の VC 文字列を保持する。
   * @throws アクティブペルソナ未設定（VericertsError、code `2005`）、Offer のパース失敗・grant 不明
   *         （`3003`）、Metadata 取得 / 通信失敗（`3004`）、既定検証または `opts.verifyReceived` が
   *         署名不一致で失敗した場合（`3010`。`3002` / `3024` 等の `VericertsError` は元のコード）、依存不正・`authorization_code` grant での認可情報欠落・Token
   *         Request 失敗（`8010`）、Credential Request 失敗・復号失敗・遅延発行（`8020`）の場合。
   *
   * @experimental マイナーバージョンで挙動・シグネチャが変わり得る。
   *   `Wallet` 上で呼び出せる。呼び出し時に experimental 警告は出ない。
   */
  receiveCredential(
    offerURI: string,
    opts?: ReceiveCredentialOptions,
  ): Promise<ReceivedVerifiableCredential>;

  /**
   * VP を JWT-VP（コンパクト JWS）として署名する。署名鍵は keymanager 内に保持したまま使う。
   *
   * @param vp 署名する W3C Verifiable Presentation。
   * @param keyID 署名に使う holder 鍵の ID。
   * @param opts audience / nonce（OID4VP）・有効期間・発行時刻（`iat` の基準時刻）。
   * @returns コンパクト JWT-VP 文字列。
   * @throws keyID 未登録（code `1004`）/ VP 構造不正（code `3002`）の場合。
   */
  issuePresentation(
    vp: VerifiablePresentation,
    keyID: string,
    opts?: IssuePresentationOptions,
  ): Promise<string>;

  /**
   * SD-JWT VC を発行する。Issuer 署名鍵は keymanager 内に保持したまま使う。
   *
   * @param keyID 署名に使う Issuer 鍵の ID。
   * @param opts vct / 開示クレーム / 平文クレーム / cnf / status 等。
   * @returns SD-JWT 文字列（`<issuerJwt>~<d1>~...~`）。
   * @throws keyID 未登録（code `1004`）の場合。
   */
  issueSdJwt(keyID: string, opts: CreateSdJwtOptions): Promise<string>;

  /**
   * SD-JWT VC を検証する。Issuer-signed JWT の `iss` を解決して Issuer 鍵を組み立て、署名・開示
   * digest・KB-JWT を検証する。
   *
   * @param sdJwt 検証対象の SD-JWT。
   * @param opts 期待 vct / KB-JWT の audience・nonce・必須要否・鮮度。`requireKeyBinding: true`
   *             を指定する場合は `audience` / `nonce` も**必須**。
   * @returns 復元クレームと vct / cnf / status。
   * @throws 署名不一致（code `3010`）/ holder binding 不一致（code `3012`。`requireKeyBinding: true`
   *         で `audience` / `nonce` を指定しなかった場合を含む）等。
   */
  verifySdJwt(sdJwt: string, opts?: VerifySdJwtFacadeOptions): Promise<VerifiedSdJwt>;
}
