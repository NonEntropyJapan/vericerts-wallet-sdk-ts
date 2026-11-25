/**
 * OID4VP VP Token 構成（Wallet 側）。
 *
 * 本モジュールは、`request.ts` でパース済みの `PresentationRequest` と、`matcher.ts` で選定した
 * 提示クレデンシャルから、検証者へ送る VP Token を構成する責務を担う。Authorization Response の
 * 送信（`direct_post` / `direct_post.jwt`）は `oid4vp-submit.ts` の責務。
 *
 * 対応 format:
 * - `jwt_vc_json`: JWT 署名された W3C Verifiable Presentation。`nonce` クレームにリクエストの
 *   `nonce` を、`aud` に `client_id` を含める（Holder Binding）。`issuePresentation`（presentation.ts）に委譲する。
 * - `dc+sd-jwt` / `vc+sd-jwt`: SD-JWT VC の提示部（選択 Disclosure）に Key Binding JWT
 *   （`nonce` / `aud` バインド）を付与する。`selectDisclosures`（sdjwt.ts）+ `addKeyBinding`
 *   （sdjwt-verify.ts）に委譲する。SD-JWT VC の format 識別子は JWS ヘッダの `typ` と同一文字列で、
 *   既定は `dc+sd-jwt`、移行期間中は旧 `vc+sd-jwt` も受理する（`sdjwt/typ.ts` が SSOT）。
 *
 * VP Token は単一クレデンシャルなら文字列、複数なら JSON 配列で表現する。
 *
 * スコープ外（HAIP に関連する別処理）:
 * - PEx v2 Presentation Submission の**構築**（`presentation_submission`）。DCQL 提示を対象とする。
 *   構築済みの Submission を送信に載せる経路は `oid4vp-submit.ts` が提供する。
 * - JAR JWS 署名検証・Trust Anchor 検証。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に privateKey・VC 本文・開示値・JWT・VP Token・nonce 等の秘密を含めない。
 */

import type {
  CredentialAlg,
  CredentialSigner,
  KeyBindingTemplate,
} from '../../credential/index.js';
import {
  addKeyBinding,
  createKeyBindingTemplate,
  type IssuePresentationOptions,
  issuePresentation,
  selectDisclosures,
  VC_V2_CONTEXT,
  type VerifiablePresentation,
  VP_TYPE,
} from '../../credential/index.js';
import { assertBindingValue } from '../../credential/sdjwt/key-binding.js';
import { isAcceptedSdJwtVcTyp, type SdJwtVcTyp } from '../../credential/sdjwt/typ.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { addKeyBindingWithTransactionData } from '../../eudi/transaction-data/hashes.js';
import type { TransactionDataEntry } from '../../eudi/transaction-data/types.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { FORMAT_JWT_VC } from '../matcher.js';
import type { PresentationRequest } from '../request.js';
import {
  hasTransactionData,
  resolveTransactionDataBindings,
  transactionDataBindingFailure,
} from '../transaction-data-binding/binding.js';

/**
 * `jwt_vc_json`（W3C JWT-VP）形式で提示する 1 クレデンシャル分の入力。
 *
 * `holder` を `iss` として JWT-VP を署名し、`verifiableCredential` に提示する VC（JWT-VC 文字列 /
 * JSON-LD VC object）を含める。`nonce` / `aud` はリクエストから設定するため指定不要。
 */
export interface JwtVcPresentationInput {
  /** 提示 format 判別子。 */
  readonly format: typeof FORMAT_JWT_VC;
  /** 提示者 DID（JWT-VP の `iss` / `holder`）。 */
  readonly holder: string;
  /** 提示する VC（JWT-VC コンパクト JWS 文字列 / JSON-LD VC object）の配列。 */
  readonly verifiableCredentials: ReadonlyArray<string | Readonly<Record<string, unknown>>>;
  /** VP の ID（URI）。指定時は JWT-VP の `jti` に対応する。 */
  readonly presentationId?: string;
  /** Holder の署名鍵（`holder` DID の鍵）。 */
  readonly signer: CredentialSigner;
}

/**
 * SD-JWT VC（`dc+sd-jwt` / 移行期間の `vc+sd-jwt`）形式で提示する 1 クレデンシャル分の入力。
 *
 * 元の SD-JWT VC から `disclosedClaims` のクレームのみを開示し、Key Binding JWT（`nonce` / `aud`
 * バインド）を付与する。`signer` は SD-JWT の `cnf.jwk` に対応する Holder 鍵。
 */
export interface SdJwtPresentationInput {
  /** 提示 format 判別子（保持 SD-JWT の `typ` と同一文字列。新旧いずれも SD-JWT VC 提示として扱う）。 */
  readonly format: SdJwtVcTyp;
  /** 元の SD-JWT VC 文字列（`<issuerJwt>~<d1>~...~`）。 */
  readonly sdJwt: string;
  /** 開示するクレーム名。未指定のクレームの Disclosure は除外される。 */
  readonly disclosedClaims: readonly string[];
  /** Holder の署名鍵（SD-JWT の `cnf.jwk` に対応）。KB-JWT 署名に用いる。 */
  readonly signer: CredentialSigner;
  /** KB-JWT の `iat`（エポック秒）。既定は現在時刻。テストの決定性のため注入可能。 */
  readonly iatSeconds?: number;
  /** 対応する DCQL 要件の `id`。`transaction_data` の `credential_ids` と突き合わせる（省略時は要件 1 件のときその `id`）。 */
  readonly credentialQueryId?: string;
}

/** `buildVPToken` の提示クレデンシャル入力（format 判別ユニオン）。 */
export type PresentationInput = JwtVcPresentationInput | SdJwtPresentationInput;

/**
 * 提示入力が SD-JWT VC（`dc+sd-jwt` / 移行期間の `vc+sd-jwt`）形式かを判定する。
 *
 * `isAcceptedSdJwtVcTyp` は `format` プロパティのみを絞り込むため、判別ユニオン `PresentationInput`
 * 自体を絞り込めるよう型述語で包む。
 */
function isSdJwtPresentationInput(input: PresentationInput): input is SdJwtPresentationInput {
  return isAcceptedSdJwtVcTyp(ownProperty<string>(input, 'format'));
}

/**
 * 1 つの提示クレデンシャル入力から VP Token 要素（文字列）を構成する。
 *
 * - `jwt_vc_json`: `holder` / `verifiableCredentials` から W3C VP を組み立て、`issuePresentation` で
 *   JWT-VP を署名する。`nonce` = リクエスト nonce、`aud` = `client_id`（Holder Binding）。
 * - `dc+sd-jwt` / `vc+sd-jwt`: `selectDisclosures` で開示クレームを絞り、`addKeyBinding` で KB-JWT を
 *   付与する。KB-JWT の `nonce` = リクエスト nonce、`aud` = `client_id`。
 *
 * @throws SD-JWT / VP 構造不正・署名失敗時（VericertsError、各プリミティブ由来）。
 */
function buildVPTokenEntry(
  request: PresentationRequest,
  input: PresentationInput,
  transactionData: readonly TransactionDataEntry[],
): string {
  // `request` は Verifier 由来のデータ、`input` は呼び出し側のオプション。いずれも自身の
  // プロパティに限って読む。これらは **署名済み KB-JWT / JWT-VP** の
  // `nonce` / `aud` / `iat` / `jti` にそのまま載るため、プロトタイプ鎖で読むと、その項目を
  // 持たない要求・省略した呼び出しでも汚染値が署名対象へ入り、リプレイバインドと
  // audience バインドが攻撃者の選んだ値になる。同ファイルの `buildVPTokenTemplate` は
  // 同じ理由で既に `Object.hasOwn` で守られており、こちらだけが漏れていた。
  const nonce = ownProperty<string>(request, 'nonce') as string;
  const audience = ownProperty<string>(request, 'clientId') as string;
  // `nonce` / `aud` が欠落・空・非文字列のまま JWT-VP に署名すると、リプレイ可能な VP になる。
  // SD-JWT 経路（`addKeyBinding`）と同じ 3012 でフォーマット共通に拒否する。
  assertBindingValue(nonce);
  assertBindingValue(audience);
  if (isSdJwtPresentationInput(input)) {
    // `disclosedClaims` は**開示するクレームの一覧**であり、その結果が KB-JWT の `sd_hash` に
    // 署名されて焼き付く。鎖読みだと汚染値の一覧で絞り込みが行われ、攻撃者が選んだ選択的開示が
    // 成立する。姉妹関数 `buildVPTokenTemplate` は own 化済みで、本番経路である
    // こちらだけが漏れていた。
    const disclosedClaims = ownProperty<readonly string[]>(
      input,
      'disclosedClaims',
    ) as readonly string[];
    const sdJwt = ownProperty<string>(input, 'sdJwt') as string;
    const presented = selectDisclosures(sdJwt, disclosedClaims);
    const iatSeconds = ownProperty<number>(input, 'iatSeconds');
    const signer = ownProperty<CredentialSigner>(input, 'signer') as CredentialSigner;
    // 要求の `transaction_data` がこの提示に紐付くなら、そのハッシュを KB-JWT に束縛する。
    return transactionData.length > 0
      ? addKeyBindingWithTransactionData(presented, signer, {
          nonce,
          audience,
          transactionData,
          ...(iatSeconds !== undefined ? { iatSeconds } : {}),
        })
      : addKeyBinding(presented, signer, {
          nonce,
          audience,
          ...(iatSeconds !== undefined ? { iatSeconds } : {}),
        });
  }

  // jwt_vc_json: W3C VP を組み立てて JWT-VP 署名する。
  const presentationId = ownProperty<string>(input, 'presentationId');
  const vp: VerifiablePresentation = {
    '@context': [VC_V2_CONTEXT],
    type: [VP_TYPE],
    // `holder` は署名済み JWT-VP の `iss` になる。継承値を詰め直さない。
    holder: ownProperty<string>(input, 'holder') as string,
    verifiableCredential: ownProperty<VerifiablePresentation['verifiableCredential']>(
      input,
      'verifiableCredentials',
    ) as VerifiablePresentation['verifiableCredential'],
    ...(presentationId !== undefined ? { id: presentationId } : {}),
  };
  const opts: IssuePresentationOptions = { audience, nonce };
  const signer = ownProperty<CredentialSigner>(input, 'signer') as CredentialSigner;
  return issuePresentation(vp, signer, opts);
}

/**
 * OID4VP VP Token を構成する。
 *
 * パース済み `PresentationRequest` のリプレイ防止 `nonce` と検証者識別子 `client_id`（audience）を
 * Holder Binding として各提示クレデンシャルに束縛する。提示クレデンシャルは format ごとに
 * `jwt_vc_json`（JWT-VP）/ `dc+sd-jwt`・`vc+sd-jwt`（SD-JWT + KB-JWT）を構成する。
 *
 * 戻り値は単一クレデンシャルなら文字列、複数なら文字列配列とする。
 *
 * @param request パース済み OID4VP Authorization Request（`request.ts`）。
 * @param inputs 提示するクレデンシャル（`matcher.ts` の選定結果から呼び出し側が構成する）。
 * @returns VP Token（単一なら string、複数なら string[]）。
 * 要求が `transaction_data` を持つときは各提示の KB-JWT に `transaction_data_hashes` を束縛し、束縛できない要求は
 * 1 件も署名せず拒否する（`transaction-data-binding/binding.ts`）。
 *
 * @throws 入力が空の場合・`transaction_data` を束縛できない場合（VericertsError、code `8035`）、`transaction_data` 不正（`8030`）、
 *         VP / SD-JWT 構造不正・署名失敗時（各プリミティブ由来）。
 */
export function buildVPToken(
  request: PresentationRequest,
  inputs: readonly PresentationInput[],
): string | string[] {
  if (inputs.length === 0) {
    throw new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED, {
      context: { reason: 'no_presentation_input' },
    });
  }
  // `transaction_data` を提示ごとに割り当てる。束縛できない要求は 1 件も署名せず拒否する。
  const bindings = resolveTransactionDataBindings(request, inputs, (input) =>
    isSdJwtPresentationInput(input as PresentationInput),
  );
  const entries = inputs.map((input, i) =>
    buildVPTokenEntry(request, input, bindings[i] as readonly TransactionDataEntry[]),
  );
  // 単一クレデンシャルは文字列、複数は配列で送る。
  return entries.length === 1 ? (entries[0] as string) : entries;
}

/**
 * 分離型 Holder Service（Agent Holder）が VP Token テンプレートを組む際の SD-JWT 提示入力。
 *
 * `SdJwtPresentationInput` から `signer` を落とし、代わりに署名 alg だけを受け取る。Holder Service は
 * VC バイト列だけを保持し、Agent Session 秘密鍵を受け取らないことを型で表現する。
 */
export interface SdJwtTemplateInput {
  /** 提示 format 判別子（保持 SD-JWT の `typ` と同一文字列。新旧いずれも SD-JWT VC 提示として扱う）。 */
  readonly format: SdJwtVcTyp;
  /** 保管済みの SD-JWT VC 文字列（`<issuerJwt>~<d1>~...~`）。 */
  readonly sdJwt: string;
  /** 開示するクレーム名。未指定のクレームの Disclosure は除外される。 */
  readonly disclosedClaims: readonly string[];
  /** KB-JWT に署名する Agent Session 鍵の JWS alg（**秘密鍵は渡さない**）。 */
  readonly alg: CredentialAlg;
  /**
   * KB-JWT ヘッダへ載せる鍵 ID。未指定ならヘッダに出力しない。
   *
   * 統合構成の `buildVPToken` は `signer.kid` をヘッダへ伝播するため、同一バイト列を得るには
   * 分離構成でも同じ値を宣言する必要がある。
   */
  readonly kid?: string;
  /** KB-JWT の `iat`（エポック秒）。既定は現在時刻。テストの決定性のため注入可能。 */
  readonly iatSeconds?: number;
}

/**
 * 分離型 Holder Service 向けに、OID4VP リクエストから KB-JWT の署名前テンプレートを構成する。
 *
 * `buildVPToken` の SD-JWT 経路と同じく `nonce` = リクエストの `nonce`、`aud` = `client_id` を
 * Holder Binding として束縛するが、署名は行わない。返したテンプレートの `signingInput` を Agent
 * Session が署名し、`attachKeyBinding` / `attachKeyBindingSignature` で合成すると、`buildVPToken` が
 * 生成するのと同一の VP Token 要素になる。ただしこの同値が成り立つのは、次の 2 条件をいずれも
 * 満たす場合に限る。
 *
 * 1. 入力 SD-JWT VC が `cnf` を持つ、または合成時に `verifySignature: false` を明示する。
 *    `buildVPToken` は内部で `verifySignature: false` を用いるため `cnf` 不在でも成功するが、
 *    `attachKeyBinding` は既定（`verifySignature: true`）では `cnf` 不在を `3012` で拒否する。
 * 2. 入力 SD-JWT VC に KB-JWT が付与されていない。`buildVPToken` は `selectDisclosures` が既存
 *    KB-JWT を捨てるため付与済みでも成功するが、本関数は再付与ガードを絞り込み**前**の入力に
 *    適用するため `3010` で失敗する（下記 `@throws` を参照）。
 *
 * `nonce` / `audience` をパース済みリクエストから導出するため、呼び出し側が両者を取り違えて渡す
 * 余地が無い（`sd_hash` も SDK が提示部から計算する）。
 *
 * @param request パース済み OID4VP Authorization Request（`request.ts`）。
 * @param input 保管済み SD-JWT VC・開示クレーム・Agent Session 鍵の alg / kid。
 * @returns KB-JWT の署名前テンプレート。
 * @throws 要求が `transaction_data` を持つ場合（`8035`。テンプレートは `transaction_data_hashes` を載せられない）、
 *         SD-JWT 構造不正・入力に KB-JWT が付与済み（`3010`）、未対応 alg・`request.nonce` または
 *         `request.clientId` が空文字列（`3012`）の場合（VericertsError）。
 */
export function buildVPTokenTemplate(
  request: PresentationRequest,
  input: SdJwtTemplateInput,
): KeyBindingTemplate {
  // テンプレートはハッシュを載せられない。取引と結び付かない KB-JWT へ署名させない。
  if (hasTransactionData(request)) {
    throw transactionDataBindingFailure('transaction_data_unsupported_in_template');
  }
  // 任意プロパティは `Object.hasOwn` で自身のプロパティに限って読む。`input.kid !== undefined`
  // だとプロトタイプ鎖を辿るため、`kid` を省略した正当な呼び出しでも `Object.prototype.kid` の
  // 汚染値を拾い、それを `KeyBindingTemplateOptions` の**自身のプロパティ**として引き渡す。
  // すると下流 `buildJwsHeader`（`vc/signer.ts`）の `Object.hasOwn` ガードが素通りし、
  // 攻撃者が選んだ鍵 ID が KB-JWT ヘッダに載る（検証側の鍵解決を誤導できる）。
  const kid = Object.hasOwn(input, 'kid') ? input.kid : undefined;
  const iatSeconds = Object.hasOwn(input, 'iatSeconds') ? input.iatSeconds : undefined;
  const sdJwt = ownProperty<string>(input, 'sdJwt') as string;
  // `request` 側も同様に own 限定で読む（`nonce` / `clientId` は KB-JWT の署名対象に載る）。
  return createKeyBindingTemplate(sdJwt, {
    alg: ownProperty<CredentialAlg>(input, 'alg') as CredentialAlg,
    nonce: ownProperty<string>(request, 'nonce') as string,
    audience: ownProperty<string>(request, 'clientId') as string,
    disclosedClaims: ownProperty<readonly string[]>(input, 'disclosedClaims') as readonly string[],
    ...(kid !== undefined ? { kid } : {}),
    ...(iatSeconds !== undefined ? { iatSeconds } : {}),
  });
}
