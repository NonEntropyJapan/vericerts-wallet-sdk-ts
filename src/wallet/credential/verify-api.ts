/**
 * Wallet ファサードの検証 API（VC / VP）のインターフェースとオプション型。
 *
 * 検証結果はメソッドごとに次の形式で返す。
 *
 * - **低レベル primitive（`*Strict`）**: fail-closed。失敗は `VericertsError` として投げ、成功時のみ
 *   「暗号的に検証できた範囲」を返す。`verifyPresentationEnvelopeStrict` が返すのは VP envelope
 *   （署名・時刻・aud/nonce）だけで、**内包 VC の検証結果は含まない**。
 * - **高レベル Verifier API**: 判別共用体の Result 型（`CredentialVerificationResult` /
 *   `PresentationVerificationResult`）を返す。検証の不成立は例外ではなく `valid: false` になり、
 *   理由は構造化された `VerificationIssue[]` として `errors` に載る。
 *
 * 高レベル側でも、**検証の不成立以外**（プログラミングエラー等、`VericertsError` でない例外）は
 * 握り潰さずそのまま伝播する。「想定外の失敗を `valid: false` に丸める」と、原因不明の不具合が
 * 正常な検証失敗に紛れるため。
 *
 * `api.ts` から分離してあるのは 1 ファイル 300 行の上限に収めるためで、`PresentationApi` が
 * 本インターフェースを `extends` する形で従来どおり 1 つの型として公開する。
 */

import type { NonceContext, NonceStore } from '../../internal/auth/nonce/index.js';
import type {
  CredentialVerificationResult,
  IssuerTrustOption,
  PresentationVerificationResult,
  VerifiedCredential,
  VerifiedPresentationEnvelope,
} from '../../internal/credential/index.js';
import type { PresentationWorkBudget } from '../../internal/primitives/presentation-work-budget.js';
import type { TrustedIssuerList } from '../../internal/trusted-issuer/types.js';

/** `verifyCredential` / `verifyCredentialStrict` のファサード向けオプション（検証鍵は issuer DID 解決で自動補完）。 */
export interface VerifyCredentialFacadeOptions {
  /** 現在時刻（エポック秒）。`iat` / `exp` / `nbf` 評価に用いる。既定は現在時刻。 */
  readonly nowSeconds?: number;
  /**
   * 時刻クレーム評価で許容するクロックスキュー秒数。既定値・上限はともに 120 秒。
   * 0 以上 120 以下の整数のみ指定でき、それ以外は 4015 で拒否する。
   */
  readonly clockSkewSeconds?: number;
  /**
   * 発行者について構築済みの Federation Trust Chain。
   *
   * 指定すると鍵無効化宣言（`revoked_keys`）の突合が自動的に適用され、該当する VC は 5012 で
   * 拒否される。Federation 由来の信頼を使わない場合は省略する（省略時は判定しない）。
   * SD-JWT 側は `VerifySdJwtFacadeOptions` が `VerifySdJwtOptions` を継承するため自動的に持つ。
   */
  readonly issuerTrust?: IssuerTrustOption;
}

/**
 * `verifyPresentation` / `verifyPresentationEnvelopeStrict` のファサード向けオプション
 * （検証鍵は holder DID 解決で自動補完）。
 *
 * `nonceStore` と `nonceContext` を渡すと、JWT-VP の検証が seen-nonces cache による
 * replay 検知経路（`verifyPresentationWithReplayGuard`）を通る。
 * SDK はステートフルな nonce ストアを内蔵しない方針のため、利用側がストアを注入したときだけ
 * 使用 1 回の保証が有効になる。**両方とも渡さない**ことだけが「replay 検知を使わない」明示的な選択で、
 * **片方だけの指定は拒否する**（`nonceStore` のみ 4012 `NONCE_BINDING_MISMATCH` / `nonceContext` のみ
 * 4010 `REPLAY_DETECTED`。無言で replay 検知なしに落とさない）。
 *
 * 内包 VC に関わるオプション（`issuerTrust` / `requireHolderBinding`）は
 * **高レベル `verifyPresentation` でのみ効く**。`verifyPresentationEnvelopeStrict` は内包 VC を
 * 検証しないため、渡しても結果に現れない。
 */
export interface VerifyPresentationFacadeOptions {
  /**
   * 期待する Verifier 識別子（OID4VP の `aud`）。既定（束縛）モードでは必須で payload の `aud` と
   * 一致を要求する。`allowUnbound: true` 時は指定された場合のみ照合する。
   */
  readonly expectedAudience?: string;
  /**
   * 期待する nonce（リプレイ対策）。既定（束縛）モードでは必須で payload の `nonce` と一致を要求する。
   * `allowUnbound: true` 時は指定された場合のみ照合する。
   */
  readonly expectedNonce?: string;
  /** 現在時刻（エポック秒）。`iat` / `exp` / `nbf` 評価に用いる。既定は現在時刻。 */
  readonly nowSeconds?: number;
  /**
   * 時刻クレーム評価で許容するクロックスキュー秒数。既定値・上限はともに 30 秒。
   * 0 以上 30 以下の整数のみ指定でき、それ以外は 4015 で拒否する。
   */
  readonly clockSkewSeconds?: number;
  /**
   * Verifier バインド（`aud` / `nonce`）を必須としない unsafe モード。既定 `false`（必須）。
   * OID4VP 文脈外の VP 検証時に明示的にオプトインする。
   */
  readonly allowUnbound?: boolean;
  /** 消費記録を保持する `NonceStore`。`nonceContext` と必ず対で指定する（片方だけは拒否）。 */
  readonly nonceStore?: NonceStore;
  /** nonce の発行コンテキスト。`aud` の照合対象もここから取る。 */
  readonly nonceContext?: NonceContext;
  /** replay window（秒）の上書き。省略時は `nonceContext.flow` に応じた期間を使う。 */
  readonly replayWindowSeconds?: number;
  /** 初見 nonce を記録する際の保持期間（ms）。 */
  readonly nonceTtlMs?: number;
  /**
   * 発行者について構築済みの Federation Trust Chain。
   *
   * VP 署名（Holder の提示鍵）には適用せず、**内包 VC の検証へ中継する**。
   * 指定すると鍵無効化宣言に該当する内包 VC が `credentialResults` 上で
   * 5012 として `valid: false` になる。省略時は判定しない。
   */
  readonly issuerTrust?: IssuerTrustOption;
  /**
   * 内包 VC が提示者（`vp.holder`）のものであることを要求する。
   * 既定 `false`（後方互換）。
   *
   * `true` のとき、JWT-VC は `sub === vp.holder`（`sub` を持たない bearer VC は拒否）、SD-JWT VC は
   * `cnf` + KB-JWT の検証を要求し、満たさない VC は `credentialResults` 上で `3012` として
   * `valid: false` になる。KB-JWT の照合に使う `aud` / `nonce` は、replay 検知経路では
   * `nonceContext` の束縛値と照合済みの実測 `aud` と `expectedNonce` が使われる。
   *
   * **`true` のときは実効 `audience` / `nonce` の両方を要求する（fail-closed）。** どちらかが
   * `undefined` なら内包 SD-JWT VC は KB-JWT の内容によらず `3012` で `valid: false` になる
   * （`undefined` は「照合しない」ではない）。`allowUnbound: true` で `expectedAudience` /
   * `expectedNonce` を省略し、かつ replay 検知経路も通らない呼び出しが該当する。
   *
   * 委任された提示（`sub !== vp.holder`）は `3012` になる。独自の委任材料による
   * 突合（旧 `delegations` オプション）は削除した。
   */
  readonly requireHolderBinding?: boolean;
  /**
   * 内包 VC の発行者との照合に使う Trusted Issuer List。
   *
   * 内包 VC ごとに `issuerDID` を本リストと照合し、`credentialResults[].isTrustedIssuer` に
   * 反映する opt-in の DI。未指定（既定）なら従来どおり照合を行わず `null`（未実行）を返す。
   */
  readonly trustedIssuerList?: TrustedIssuerList;
  /**
   * VP 1 通で共有する仕事量の残予算（`newPresentationWorkBudget()`）。未指定なら呼び出し専用の予算を作る。
   * 内包 VC の署名検証・issuer 信頼評価がこれを消費する。超過は例外（`3002`）で VP 全体を拒否する。
   */
  readonly workBudget?: PresentationWorkBudget;
}

/** JWT-VC / JWT-VP の検証 API（低レベル primitive と高レベル Verifier API の 2 層）。 */
export interface VerifyApi {
  /**
   * JWT-VC を検証する低レベル primitive。**失敗は例外**（fail-closed）。
   *
   * JWT-VC の `iss`（発行者 DID）を取り出して `resolveDID` で解決し、その DID Document から
   * 検証鍵を組み立てて署名・時刻を検証する。旧 `verifyCredential` と**同じ挙動・同じシグネチャ**で、
   * 名前だけ `Strict` を付けて高レベル API と分けた（破壊的変更）。
   *
   * @param jwt 検証対象のコンパクト JWT-VC 文字列。
   * @param opts 現在時刻・クロックスキュー・FC-11 の Trust Chain。
   * @returns デコード済みヘッダ・ペイロード。
   * @throws `clockSkewSeconds` 不正（code `4015`）/ 形式不正（code `2001`）/ `iss` 欠落（code `3002`）/
   *         未対応メソッド（code `2002`）/ 署名不一致（code `3010`）/ 未来 `iat`（code `4014`）/
   *         期限切れ（code `3024`）/ 有効化前（code `3025`）の場合（VericertsError）。
   */
  verifyCredentialStrict(
    jwt: string,
    opts?: VerifyCredentialFacadeOptions,
  ): Promise<VerifiedCredential>;

  /**
   * JWT-VP の **envelope だけ**を検証する低レベル primitive。
   * **失敗は例外**（fail-closed）。
   *
   * `iss`（提示者 DID）を解決して検証鍵を組み立て、署名・時刻（exp/nbf）・aud/nonce を検証する。
   * 既定では Verifier バインド（aud/nonce）必須で、未指定・不一致を拒否する。バインドを持たない VP は
   * `allowUnbound: true` で明示的にオプトアウトする。`nonceStore` と `nonceContext` を両方渡すと
   * seen-nonces cache による replay 検知経路を通る。
   *
   * **内包 VC（`vp.verifiableCredential`）は検証しない。** 返る `presentation` に入っている VC は
   * 未検証であり、そのまま受理してはならない。内包 VC も要るなら高レベル
   * {@link VerifyApi.verifyPresentation} を使うこと（旧 `verifyPresentation` はこちらに相当する）。
   *
   * @param jwt 検証対象の JWT-VP。
   * @param opts 期待 audience / nonce・現在時刻・allowUnbound・`NonceStore` とコンテキスト。
   * @returns header / payload / presentation / holderDID（内包 VC の結果は含まない）。
   * @throws 署名不一致（code `3010`）/ alg=none（code `3011`）/ 期限切れ（code `3024`）・有効化前（code `3025`）/
   *         holder・aud・nonce 不一致・バインド未指定（code `3012`）等。replay 検知経路では
   *         nonce 再利用（code `4010`）/ nonce 期限切れ（code `4011`）/ バインディング不一致（code `4012`）/
   *         `expectedNonce` 未指定・nonce 形式不正（code `4013`）/ replay-window 外（code `4014`）。
   */
  verifyPresentationEnvelopeStrict(
    jwt: string,
    opts?: VerifyPresentationFacadeOptions,
  ): Promise<VerifiedPresentationEnvelope>;

  /**
   * JWT-VC を検証し、判別共用体の結果を返す高レベル Verifier API。
   *
   * 検証の不成立は例外ではなく `{ valid: false, errors }` として返る。`errors` は構造化された
   * `VerificationIssue`（`code` / `message`）の配列で、`code` は `verifyCredentialStrict` が
   * 投げる `VericertsError` の `code` と一致する。
   *
   * @param jwt 検証対象のコンパクト JWT-VC 文字列。
   * @param opts 現在時刻・クロックスキュー・FC-11 の Trust Chain。
   * @returns `valid: true` なら `data` にデコード済みヘッダ・ペイロード、`valid: false` なら `errors`。
   * @throws 検証の不成立では投げない。`VericertsError` でない想定外の例外だけをそのまま伝播する。
   */
  verifyCredential(
    jwt: string,
    opts?: VerifyCredentialFacadeOptions,
  ): Promise<CredentialVerificationResult>;

  /**
   * JWT-VP を envelope + 内包 VC まで検証し、判別共用体の結果を返す高レベル Verifier API。
   *
   * envelope の検証内容は {@link VerifyApi.verifyPresentationEnvelopeStrict} と同じで、加えて
   * 内包 VC（`vp.verifiableCredential`）も検証し、1 件ごとの結果を `credentialResults` に返す。
   * 発行者鍵は VP 署名の検証後に `iss` を解決して自動補完する。
   *
   * **`valid` と `presentationValid`**: `presentationValid` は envelope だけの成否、top-level の
   * `valid` は「envelope が正当**かつ**全内包 VC が有効」である。envelope が正当でも内包 VC が
   * 1 件でも invalid なら `valid: false` / `presentationValid: true` になる（部分成功は診断情報で
   * あり、認可判定は deny に倒す）。
   *
   * @param jwt 検証対象の JWT-VP。
   * @param opts 期待 audience / nonce・現在時刻・allowUnbound・`NonceStore` とコンテキスト・
   *             内包 VC へ中継する `issuerTrust` / `requireHolderBinding`。
   * @returns `valid: true` なら `data`（envelope）と全件有効な `credentialResults`、
   *          `valid: false` なら `presentationValid` / `credentialResults` / `errors`。
   * @throws 検証の不成立では投げない。`VericertsError` でない想定外の例外だけをそのまま伝播する。
   */
  verifyPresentation(
    jwt: string,
    opts?: VerifyPresentationFacadeOptions,
  ): Promise<PresentationVerificationResult>;
}
