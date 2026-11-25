/**
 * EUDI PID / (Q)EAA の提示フロー（OID4VP `direct_post`）。
 *
 * HAIP §5.1 に従い、参照形式の提示要求は `request_uri` から JAR を取得して署名を検証する。
 *
 * **要求の解析には非同期の `parsePresentationRequest` を使う。** 同期の
 * `parseAuthorizationRequest` は HTTP 取得ができないため `request_uri` 参照形式を `8030`
 * （`reason: "request_uri_reference"`）で拒否する。HAIP §5.1 は提示要求について JAR を
 * `request_uri` 経由で使うことを必須とするので、同期 API のままでは **HAIP 準拠の Verifier からの
 * 提示要求を `presentPID` / `presentEAA` で 1 件も処理できない**。単一入口へ切り替えることで、
 * 直接形式は従来どおり同期解析され、参照形式は取得 + JAR の署名検証を経て同じ
 * `PresentationRequest` になる（呼び出し側は形式を知らなくてよい）。
 *
 * 本モジュールは Wallet facade（`presentPID` / `presentEAA`）が組み立てられるだけの内部関数を
 * 提供する。ファサード（`presentPID` / `presentEAA`）への配線は `wallet/eudi/facade.ts` が担う。
 *
 * 提示は次の 1 本道で、PID と (Q)EAA の違いは**どの SD-JWT を、どのクレームまで開示するか**の
 * 選定だけである。したがって「要求解析 → VP Token 構成 → 送信 → 提示記録の生成」を単一の
 * ヘルパーへ括り、分岐は選定部分に閉じ込める。
 *
 * 1. Authorization Request をパースする（`parsePresentationRequest`。直接形式と `request_uri`
 *    参照形式（JAR）の両方を 1 本で扱う。参照形式は取得 + JAR の署名検証を経由する）。
 * 2. `buildVPToken` で選択的開示と Key Binding JWT を構成する。`nonce` / `aud` は要求から
 *    バインドされるため、本モジュールがリプレイ防止値を扱うことはない。
 * 3. `submitPresentation` で Verifier へ送信する（HTTPS 必須・3xx 不追従は送信側の責務）。
 * 4. 送信した vp_token を `VerifiablePresentation` として返す（提示記録）。
 *
 * **戻り値の `VerifiablePresentation` は「何を提示したか」の記録であって、ワイヤに乗る形式では
 * ない。** ワイヤ上の提示は手順 3 で送信済みの `vp_token` であり、戻り値の
 * `verifiableCredential` にはその vp_token 文字列をそのまま保持する。呼び出し側が提示履歴
 * （Dashboard ログ）へ記録できるようにするためである。
 *
 * セキュリティ上の注意:
 * - `deps` / Credential のフィールドは分割代入せず、関数値は `nonObjectPrototypeProperty`、
 *   純データは `ownProperty` で読む。特に `credential` を鎖で読むと、`Object.prototype.credential`
 *   の汚染下で**攻撃者が用意した SD-JWT が提示される**。
 * - 下流へ渡す送信オプションには `fetchImpl` を**常に own プロパティとして**載せる（値が
 *   `undefined` でも載せる）。載せずに省略すると、`submitPresentation` の DI 解決が
 *   そのリテラルのプロトタイプ鎖を辿って `Object.prototype.fetchImpl` を掴む。
 * - 例外の `context` は固定識別子のみ。開示クレーム値・vp_token・URL・`cause` を載せない。
 */

import type { VerifiablePresentation } from '../../../credential/presentation/vp.js';
import { VC_V2_CONTEXT, VP_TYPE } from '../../../credential/presentation/vp.js';
import type { CredentialSigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { EAACredential, PIDAttributeName, PIDCredential } from '../../../eudi/pid/index.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../../prototype-safety/own-property.js';
import { parsePresentationRequest } from '../../jar/index.js';
import { FORMAT_SD_JWT_VC_DC } from '../../matcher.js';
import { buildVPToken } from '../../oid4vp/oid4vp.js';
import type { SubmitFetchLike } from '../../oid4vp/oid4vp-submit.js';
import { submitPresentation } from '../../oid4vp/oid4vp-submit.js';
import { assertConsentedTransactionData } from '../../transaction-data-binding/binding.js';
import { presentationRequestOptions } from './request-options.js';
import type { PresentDeps } from './types.js';

/** 提示の失敗（8035、再試行不可）。理由は固定識別子のみ。 */
function presentationFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED, { context: { reason } });
}

/** 1 クレデンシャル分の提示対象（生 SD-JWT と開示するクレーム名）。 */
interface PresentationSource {
  /** 提示する SD-JWT VC のコンパクト表現。 */
  readonly sdJwt: string;
  /** 開示するクレーム名。ここに無いクレームの Disclosure は VP Token から除かれる。 */
  readonly disclosedClaims: readonly string[];
}

/**
 * Credential から提示に使う生 SD-JWT（`raw`）を取り出す。
 *
 * `raw` は **own 限定**で読む。鎖読みだと、`raw` を持たない（＝提示できない）Credential でも
 * `Object.prototype.raw` の汚染値を掴み、**攻撃者が用意した SD-JWT が Verifier へ提示される**。
 *
 * @param credential 提示対象の PID / (Q)EAA Credential。
 * @returns 生 SD-JWT。
 * @throws `raw` が欠落・空白のみの場合（VericertsError、code `8035`）。
 */
function requireRawCredential(credential: object): string {
  const raw = ownProperty<unknown>(credential, 'raw');
  if (!isNonBlankString(raw)) {
    throw presentationFailure('missing_raw_credential');
  }
  return raw;
}

/**
 * signer の `kid`（`did#fragment`）から提示者 DID を導出する。
 *
 * `VerifiablePresentation.holder` は W3C VC Data Model v2.0 で提示者を識別する必須メンバであり、
 * 空文字で埋めると構造として成立しない提示記録になる。そのため `kid` を持たない signer は
 * fail-closed に拒否する（`kid` は KB-JWT のヘッダにも載るため、提示経路では実質必須である）。
 *
 * `kid` は KMS / HSM 鍵ラッパが getter で公開し得るため `nonObjectPrototypeProperty` で読む
 * （own 限定にすると正当なクラスベース signer が「未指定」に化ける）。
 *
 * @param signer Key Binding JWT の署名鍵。
 * @returns `kid` の `#fragment` を除いた DID 部分。
 * @throws `kid` が欠落・空白のみの場合（VericertsError、code `8035`）。
 */
function deriveHolder(signer: CredentialSigner): string {
  const kid = nonObjectPrototypeProperty<unknown>(signer, 'kid');
  if (!isNonBlankString(kid)) {
    throw presentationFailure('missing_holder_key_id');
  }
  const did = kid.split('#')[0];
  return isNonBlankString(did) ? did : kid;
}

/**
 * 要求解析 → VP Token 構成 → 送信 → 提示記録の生成（手順 1〜4）。
 *
 * @param requestURI OID4VP Authorization Request URI。
 * @param sources 提示する SD-JWT と開示クレームの組（1 件以上）。
 * @param deps 署名鍵と送信シーム。
 * @returns 送信した vp_token を保持する `VerifiablePresentation`。
 * @throws 要求解析失敗（code `8030`。参照形式では JAR 取得失敗・署名検証失敗・`jarTrust` 未指定を
 *         含む）、signer 欠落・送信失敗（`8035`）、応答暗号化パラメータ解決失敗（`8036`）/
 *         JWE 構築失敗（`8037`）の場合（VericertsError）。
 */
async function presentSources(
  requestURI: string,
  sources: readonly PresentationSource[],
  deps: PresentDeps,
): Promise<VerifiablePresentation> {
  const signer = nonObjectPrototypeProperty<CredentialSigner>(deps, 'signer');
  if (typeof signer !== 'object' || signer === null) {
    throw presentationFailure('missing_signer');
  }
  const holder = deriveHolder(signer);
  const requestOptions = presentationRequestOptions(deps);
  const fetchImpl = ownProperty<SubmitFetchLike>(requestOptions, 'fetchImpl');
  // 直接形式 / `request_uri` 参照形式（JAR）の双方を単一入口で解く。
  // 参照形式では JAR の署名検証を経由する（`jarTrust` 未指定なら 8030 で fail-closed）。
  const request = await parsePresentationRequest(requestURI, requestOptions);
  // 同意済みの `transaction_data` と署名対象の要求が同一であることを、署名前に確かめる。
  //
  // 照合指定が無いまま `transaction_data` を含む要求に署名すると、Verifier は `request_uri` の
  // 2 回目の GET で取引内容を差し替えられる（同意画面に出した取引と、KB-JWT の
  // `transaction_data_hashes` に束縛される取引が別物になる）。指定が無ければ署名前に拒否する
  // （fail-closed）。`transaction_data` を持たない要求は従来どおり照合なしで進める。
  const consented = nonObjectPrototypeProperty<readonly string[]>(deps, 'consentedTransactionData');
  if (consented !== undefined) {
    assertConsentedTransactionData(request, consented);
  } else if ((ownProperty<readonly string[]>(request, 'transactionData') ?? []).length > 0) {
    throw new VericertsError(ErrorCodes.TRANSACTION_DATA_HASH_MISMATCH, {
      context: { reason: 'transaction_data_consent_required' },
    });
  }
  const vpToken = buildVPToken(
    request,
    sources.map((source) => ({
      format: FORMAT_SD_JWT_VC_DC,
      sdJwt: source.sdJwt,
      disclosedClaims: source.disclosedClaims,
      signer,
    })),
  );
  // `fetchImpl` は値が undefined でも own プロパティとして載せる（下流の DI 解決が
  // このリテラルのプロトタイプ鎖を辿って汚染値を掴まないようにするため）。
  await submitPresentation(request, vpToken, { fetchImpl });
  return {
    '@context': [VC_V2_CONTEXT],
    type: [VP_TYPE],
    holder,
    verifiableCredential: Array.isArray(vpToken) ? [...vpToken] : [vpToken],
  };
}

/**
 * PID を選択的開示して提示する。
 *
 * `disclosedClaims` に挙げた属性の Disclosure だけを VP Token に残す（`buildVPToken` が
 * `selectDisclosures` で絞り込み、その結果を KB-JWT の `sd_hash` に焼き付ける）。開示範囲は
 * 呼び出し側の同意取得結果であり、本関数は範囲を広げない。
 * 要求が `transaction_data` を持つ場合は、そのハッシュ（`transaction_data_hashes`）を KB-JWT に束縛する。
 *
 * @param requestURI OID4VP Authorization Request URI（直接形式・`request_uri` 参照形式のどちらでもよい）。
 * @param disclosedClaims 開示する PID 属性名（同意済みの範囲）。
 * @param credential 提示する PID Credential（`raw` に生 SD-JWT を保持していること）。
 * @param deps 署名鍵と送信シーム。
 * @returns 送信した vp_token を保持する `VerifiablePresentation`。
 * @throws 要求解析失敗（code `8030`。`request_uri` 参照形式では取得失敗・署名検証失敗・
 *         `deps.jarTrust` 未指定を含む）、`raw` 欠落・signer 欠落・送信失敗（`8035`）の場合
 *         （VericertsError）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function presentPIDCredential(
  requestURI: string,
  disclosedClaims: readonly PIDAttributeName[],
  credential: PIDCredential,
  deps: PresentDeps,
): Promise<VerifiablePresentation> {
  const source: PresentationSource = {
    sdJwt: requireRawCredential(credential),
    disclosedClaims: [...disclosedClaims],
  };
  return presentSources(requestURI, [source], deps);
}

/**
 * `vct` が一致する (Q)EAA の top-level クレーム名をすべて取り出す。
 *
 * (Q)EAA は型ごとに属性集合が異なり、SDK 側に「どこまで開示すべきか」の規則が無い。
 * 本スコープでは保持している属性をすべて開示する（絞り込みは Catalogue / Rulebook に基づく
 * 別スコープの責務）。`claims` は **own 限定**で読む。鎖読みだと `claims` を持たない
 * Credential が `Object.prototype.claims` の汚染値を開示対象名の源として使う。
 */
function allClaimNames(credential: EAACredential): readonly string[] {
  const claims = ownProperty<unknown>(credential, 'claims');
  if (typeof claims !== 'object' || claims === null) {
    return [];
  }
  return Object.keys(claims);
}

/**
 * `vct` が一致する (Q)EAA を提示する。
 *
 * `vctFilter` に一致する Credential を保持分から選び、その top-level クレームをすべて開示する。
 * 一致するものが 1 件も無い場合は `PRESENTATION_SUBMIT_FAILED`（8035）で失敗する。
 * `EAA_CATALOGUE_NOT_FOUND`（10003）は使わない。10003 は「その vct が (Q)EAA Catalogue に
 * 登録されていない」ことを表すコードであり（`catalogue.ts`）、**Catalogue に登録済みの型でも
 * 手元に該当 Credential が無い**という本ケースとは原因も対処も異なるため。
 *
 * @param requestURI OID4VP Authorization Request URI（直接形式・`request_uri` 参照形式のどちらでもよい）。
 * @param vctFilter 提示対象の VC Type URI。
 * @param credentials 保持している (Q)EAA Credential 群。
 * @param deps 署名鍵と送信シーム。
 * @returns 送信した vp_token を保持する `VerifiablePresentation`。
 * @throws 要求解析失敗（code `8030`。`request_uri` 参照形式では取得失敗・署名検証失敗・
 *         `deps.jarTrust` 未指定を含む）、該当 Credential なし・`raw` 欠落・signer 欠落・
 *         送信失敗（`8035`）の場合（VericertsError）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function presentEAACredential(
  requestURI: string,
  vctFilter: string,
  credentials: readonly EAACredential[],
  deps: PresentDeps,
): Promise<VerifiablePresentation> {
  // `vct` も own 限定で読む（汚染された `Object.prototype.vct` で無関係な VC が
  // 「一致した」と判定され、要求されていない属性が提示されるのを防ぐ）。
  const matched = credentials.filter(
    (credential) => ownProperty<unknown>(credential, 'vct') === vctFilter,
  );
  if (matched.length === 0) {
    throw presentationFailure('no_matching_credential');
  }
  const sources = matched.map((credential) => ({
    sdJwt: requireRawCredential(credential),
    disclosedClaims: allClaimNames(credential),
  }));
  return presentSources(requestURI, sources, deps);
}
