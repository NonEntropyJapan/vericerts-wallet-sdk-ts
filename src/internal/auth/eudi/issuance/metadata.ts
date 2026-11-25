/**
 * OID4VCI Issuer Metadata 取得（`.well-known/openid-credential-issuer`）。
 *
 * Credential Offer が示すのは `credential_issuer`（発行者の識別子）だけで、Token Endpoint も
 * Credential Endpoint も持たない。受領フロー（`receive.ts`）はこの 2 つのエンドポイントを
 * Issuer Metadata から解決してはじめて先へ進めるため、その解決だけを本モジュールに切り出す。
 * 受領フロー本体と分けるのは、Metadata 取得が「攻撃者が影響し得る URL への HTTP GET」という
 * 独立した攻撃面であり、その入口検査（HTTPS 限定・リダイレクト追跡・タイムアウト）を
 * 1 か所に閉じ込めて監査可能にするためである。
 *
 * セキュリティ上の注意:
 * - `credential_issuer` は Offer 由来 = 攻撃者が影響し得る値。HTTPS 以外は取得せず、
 *   リダイレクト後も HTTPS にとどまることを最終 URL で確認する（SSRF / 平文降格の防止）。
 * - **発見した 2 つのエンドポイントも HTTPS を必須とする。** ここを緩めると、Metadata を
 *   すり替えられた時点で access_token（Bearer）と JWT Proof が平文で攻撃者へ流れる。
 *   下流（`requestCredential` / `requestTokenPreAuthorized`）にも HTTPS 検査はあるが、
 *   本モジュールで先に落とすことで「そもそも送らない」多層防御にする。
 * - タイムアウトは本文読了までを 1 つの `AbortController` で覆う（`clearTimeout` は本文を
 *   読み終えてから行う）。ヘッダだけ先に返して本文を引き延ばす攻撃で無限に待たないため
 *   （`credential/json-schema/fetch-document.ts` と同じ形）。
 * - 例外の `context` には固定の識別子だけを載せ、URL・レスポンス本文・`cause` を一切含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { isPublicHttpsUrl } from '../../../http/public-https-url.js';
import { isBoundedStringList } from '../../../primitives/bounded-input.js';
import { AUTHORIZATION_SERVERS_LIMITS } from '../../../primitives/oid4vci-input-limits.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { sameIdentifier } from '../../oid4vci/identifier/same-identifier.js';
import { fetchWellKnownJson } from '../../well-known-json/index.js';
import {
  resolveCredentialDefinitionTypes,
  resolveCredentialFormats,
  resolveCredentialVcts,
} from './metadata-configurations.js';

/** Issuer Metadata の well-known パス（OID4VCI 1.0 §11.2）。 */
const ISSUER_METADATA_PATH = '/.well-known/openid-credential-issuer';

/**
 * Issuer Metadata から解決した OID4VCI のエンドポイント組。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface IssuerEndpoints {
  /** VC を受け取る Credential Endpoint（`credential_endpoint`、HTTPS）。 */
  readonly credentialEndpoint: string;
  /**
   * 旧 Draft の Issuer Metadata が宣言する `token_endpoint`（HTTPS）。任意。
   *
   * OID4VCI 1.0 Final の Credential Issuer Metadata にこのメンバは無い。Token Endpoint は
   * Authorization Server のもので、AS Metadata（RFC 8414）の `token_endpoint` を使う。
   * 受領フローは AS Metadata を優先し、AS Metadata を取得できないときだけこの値へ後方互換で
   * フォールバックする（`oid4vci-token-endpoint.ts`）。未告知でもキーは省略せず `undefined` を載せる。
   */
  readonly tokenEndpoint?: string;
  /**
   * `c_nonce` を払い出す Nonce Endpoint（`nonce_endpoint`、HTTPS）。任意。
   *
   * Wallet Attestation を添付する受領（`PIDReceiveOptions.walletAttestation`）でのみ必要になる。
   * WUA-PoP の `nonce` には AS が発行した `c_nonce` が必要だが、
   * pre-authorized_code フローの Token Request は AS への最初の要求であり、その応答を待っては
   * 当の Token Request を認証できない。OID4VCI の Nonce Endpoint はこのために存在し、
   * Token Request の**前に** `c_nonce` を払い出す。告知されていない Issuer に対しては、
   * 仕様に反する自家製 nonce を載せた PoP を送らず fail-closed に倒す（`receive.ts`）。
   */
  readonly nonceEndpoint?: string;
  /**
   * 認可を担う Authorization Server の識別子群（`authorization_servers`、HTTPS）。任意。
   *
   * OID4VCI 1.0 §11.2.3 の任意メンバ。Authorization Code Flow は
   * ここで告知された AS の Metadata（`/.well-known/oauth-authorization-server`）を引いて
   * `pushed_authorization_request_endpoint` / `authorization_endpoint` を解決する。
   * 告知が無い場合、ファサードは `credential_issuer` 自身を AS として扱う（OID4VCI 1.0 の既定）。
   */
  readonly authorizationServers?: readonly string[];
  /**
   * `credential_configurations_supported`（OID4VCI 1.0 §11.2.3）から解決した、要求対象の
   * credential configuration id ごとの VC `type` 配列（`credential_definition.type`）。任意。
   *
   * `jwt_vc_json` / `jwt_vc_json-ld` フォーマットの Credential Request が送る
   * `credential_definition.type` は、Issuer 側がその configuration id に対して**実際に登録した
   * 値と一致しなければならない**（walt.id 等の実装はここで一致検証する）。
   * Offer の `credential_configuration_ids` はあくまで Metadata のキー（不透明な識別子）であり、
   * その値自体が VC の `type` と一致する保証は無いため、`fetchIssuerMetadata` の
   * `credentialConfigurationIds` 引数で指定された id だけをこの Map に解決する。
   * 告知が無い / 解決できない id はキーを持たない（呼び出し側が
   * `offer.credential_configuration_ids` へフォールバックできるようにする。fail-closed にしない
   * 理由は、この値が認可・認証の判定に使われないため — 不一致は Issuer 側が拒否するだけで
   * セキュリティ上の実害が無い）。
   */
  readonly credentialDefinitionTypes?: ReadonlyMap<string, readonly string[]>;
  /**
   * 要求対象の credential configuration id ごとの `format`（`credential_configurations_supported[id].format`）。任意。
   *
   * Credential Request の `format` を Offer ではなく Issuer の告知から決める受領経路（拡張の
   * `handleReceiveOffer`）が使う。解決規則は {@link IssuerEndpoints.credentialDefinitionTypes} と同じ
   * （要求対象の id だけ・告知が無い / 非文字列は未収載）。
   */
  readonly credentialFormats?: ReadonlyMap<string, string>;
  /**
   * 要求対象の credential configuration id ごとの `vct`（`credential_configurations_supported[id].vct`）。任意。
   *
   * SD-JWT VC の Credential Request が送る `vct`（旧 Draft 形。draft-13 Annex A.3。1.0 Final の要求に `vct` は無く、
   * `credential_configurations_supported[id].vct` は configuration メタデータ）は、
   * Issuer が告知した値でなければならない。解決規則は
   * {@link IssuerEndpoints.credentialDefinitionTypes} と同じ（要求対象の id だけ・告知が無い /
   * 非文字列は未収載）。
   */
  readonly credentialVcts?: ReadonlyMap<string, string>;
}

/**
 * Metadata 取得の失敗を `ISSUER_COMMUNICATION_FAILED`（3004、再試行可）へ正規化する。
 *
 * `reason` は**固定の識別子のみ**。URL・レスポンス本文・JWT・`cause` は載せない。
 */
function metadataFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED, { context: { reason } });
}

/**
 * レスポンス本文を `IssuerEndpoints` へ検証・正規化する。
 *
 * `credential_endpoint` / `token_endpoint` は **own 限定**（`ownProperty`）で読む。
 * `parseJsonWithoutPrototype` がパース境界でプロトタイプを外す多層防御と重ねる意図で、
 * 鎖読みへ戻すと、当該メンバを持たない Metadata でも `Object.prototype` の汚染値が
 * 「発行者が宣言したエンドポイント」に化ける（fail-open）。
 *
 * @param parsed Metadata 文書（`fetchWellKnownJson` がプロトタイプを外して返したもの）。
 * @param credentialConfigurationIds 指定時、これらの id について `credentialDefinitionTypes`
 *        を解決する。
 * @returns 検証済みのエンドポイント組。
 * @throws エンドポイント欠落 / 非 HTTPS の場合（VericertsError、code `3004`）。
 */
function parseIssuerEndpoints(
  parsed: object,
  credentialConfigurationIds?: readonly string[],
): IssuerEndpoints {
  const credentialEndpoint = ownProperty<unknown>(parsed, 'credential_endpoint');
  const declaredTokenEndpoint = ownProperty<unknown>(parsed, 'token_endpoint');
  if (!isNonBlankString(credentialEndpoint)) {
    throw metadataFailure('missing_endpoint');
  }
  // `token_endpoint` は旧 Draft の互換メンバ（任意）。宣言されているなら必ず非空文字列で、
  // 宣言された値は平文・内部宛へ流さないため `credential_endpoint` と同じ検査を課す。
  if (declaredTokenEndpoint !== undefined && !isNonBlankString(declaredTokenEndpoint)) {
    throw metadataFailure('missing_endpoint');
  }
  // access_token / JWT Proof を平文で送らないため、エンドポイントに HTTPS を課す。
  if (
    !isPublicHttpsUrl(credentialEndpoint) ||
    (declaredTokenEndpoint !== undefined && !isPublicHttpsUrl(declaredTokenEndpoint))
  ) {
    throw metadataFailure('non_https_endpoint');
  }
  const tokenEndpoint = declaredTokenEndpoint;
  // `nonce_endpoint` は任意。告知されている場合だけ採用し、必須 2 つと同じ HTTPS 検査を課す
  // （`c_nonce` は WUA-PoP のリプレイ防止値であり、平文で取りに行くと中間者に固定されうる）。
  const declared = ownProperty<unknown>(parsed, 'nonce_endpoint');
  if (declared !== undefined && (!isNonBlankString(declared) || !isPublicHttpsUrl(declared))) {
    throw metadataFailure('non_https_endpoint');
  }
  // **未告知でもキーを省略せず `undefined` を own プロパティとして載せる。** 省略すると
  // 読み手（`receive.ts`）が素の `endpoints.nonceEndpoint` を読んだときにプロトタイプ鎖へ抜け、
  // `Object.prototype.nonceEndpoint` の汚染値が「Issuer が告知した Nonce Endpoint」として
  // 採用される。その結果、告知の無い Issuer に対しても攻撃者の URL から nonce を取りに行き、
  // AS が発行していない nonce を載せた WUA-PoP が本物の Token Endpoint へ送出されて
  // WUA-PoP のリプレイ防止が崩れる（本ファイル冒頭の方針と同じ理由）。
  const nonceEndpoint = isNonBlankString(declared) ? declared : undefined;
  // `authorization_servers` も任意。`nonceEndpoint` と同じ理由で**未告知でもキーを省略しない**
  // （読み手が素読みしたときに `Object.prototype.authorizationServers` の汚染値が「Issuer が
  // 告知した AS」に化け、攻撃者の AS Metadata から PAR / Authorization Endpoint を引いてしまう）。
  return {
    credentialEndpoint,
    tokenEndpoint,
    nonceEndpoint,
    authorizationServers: parseAuthorizationServers(parsed),
    credentialDefinitionTypes: resolveCredentialDefinitionTypes(parsed, credentialConfigurationIds),
    credentialFormats: resolveCredentialFormats(parsed, credentialConfigurationIds),
    credentialVcts: resolveCredentialVcts(parsed, credentialConfigurationIds),
  };
}

/**
 * `authorization_servers` を検証して取り出す（OID4VCI 1.0 §11.2.3）。
 *
 * 配列の各要素に **HTTPS を課す**。ここを緩めると、Metadata をすり替えられた時点で
 * AS Metadata の取得先が平文になり、PAR / Authorization Endpoint ごと攻撃者が差し替えられる
 * （必須 2 エンドポイントに HTTPS を課すのと同じ理由）。空配列は「告知が無い」と同じに扱う
 * （呼び出し側が `credential_issuer` 自身へフォールバックできるようにする）。
 *
 * @param parsed Metadata 文書（プロトタイプ除去済み）。
 * @returns 検証済みの AS 識別子群。告知が無い / 空配列なら `undefined`。
 * @throws 配列でない / 要素が非文字列・空・非 HTTPS の場合（VericertsError、code `3004`）。
 */
function parseAuthorizationServers(parsed: object): readonly string[] | undefined {
  const declared = ownProperty<unknown>(parsed, 'authorization_servers');
  if (declared === undefined) {
    return undefined;
  }
  if (!Array.isArray(declared)) {
    throw metadataFailure('invalid_metadata');
  }
  // 件数・1 件の長さ・合計長を、走査の前に課す（`resolveAuthorizationServer` の照合量を
  // 「件数 × 長さ」の積で膨らませない）。超過は HTTPS 違反と同じ拒否にする。
  if (
    !isBoundedStringList(declared, AUTHORIZATION_SERVERS_LIMITS, isNonBlankString) ||
    !declared.every((entry) => isPublicHttpsUrl(entry))
  ) {
    throw metadataFailure('non_https_authorization_server');
  }
  return declared.length === 0 ? undefined : (declared as readonly string[]);
}

/**
 * Issuer Metadata を取得し、Token / Credential エンドポイントを解決する。
 *
 * 手順:
 * 1. `credentialIssuer` が HTTPS でなければ**取得せずに**拒否する（fetch は一切発生しない）。
 * 2. `GET {credentialIssuer}/.well-known/openid-credential-issuer` を 10 秒のタイムアウト付きで行う。
 * 3. リダイレクト後の最終 URL が HTTPS を外れていれば拒否する（平文降格の防止）。
 * 4. 非 2xx / JSON 不正 / 必須エンドポイント欠落 / 非 HTTPS エンドポイントを拒否する。
 *
 * 1〜3 と JSON パースは `internal/auth/well-known-json/index.ts` と共有する（AS Metadata 取得と
 * 入口検査が食い違わないようにするため）。本モジュールは 4 の解釈だけを持つ。
 *
 * `fetchImpl` は必ず**引数**で受け取り、`doFetch.call(receiver, ...)` の形で呼ぶ
 * （横断 `fetch-di.ts`。裸呼び出しは prototype メソッド実装の `this` を壊す）。DI 元として
 * 渡すオブジェクトには `fetchImpl` を**常に own プロパティとして**載せる。省略時に空リテラルを
 * 渡すと、そのリテラルが `Object.prototype` を継承しているため、`fetchImpl` を指定していない
 * 正当な呼び出しが汚染された `Object.prototype.fetchImpl` を掴む。
 *
 * GET の init に `body` は**載せない**（`internal/http/fetch-json.ts` が共有トランスポートとして
 * そうする）。GET + body は Node/undici とブラウザで `Request` 構築の時点で TypeError になるため、
 * 空文字でも実 fetch を使う本番経路が 1 度もネットワークへ到達しない。
 *
 * @param credentialIssuer Credential Offer の `credential_issuer`（HTTPS の絶対 URL）。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム（テスト注入用）。省略時はグローバル `fetch`。
 * @param credentialConfigurationIds 指定時、これらの id について
 *        `IssuerEndpoints.credentialDefinitionTypes` を解決する。省略時は
 *        解決しない（`undefined` のまま）。
 * @returns 検証済みの Credential / Token エンドポイント。
 * @throws 非 HTTPS / 通信失敗 / タイムアウト / 非 2xx / リダイレクト降格 / 非 JSON Content-Type /
 *         本文の 1 MiB 超過 / JSON 不正 / エンドポイント欠落の場合（VericertsError、code `3004`）。
 *         Content-Type とサイズ上限は共有トランスポート由来で、**Content-Type を付けない / JSON 系で
 *         ない Issuer は fail-closed になる**。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function fetchIssuerMetadata(
  credentialIssuer: string,
  fetchImpl?: FetchLike,
  credentialConfigurationIds?: readonly string[],
): Promise<IssuerEndpoints> {
  // 取得と入口検査（HTTPS 限定・リダイレクト降格の拒否・本文読了までのタイムアウト・
  // プロトタイプ除去）は `well-known-json/index.ts` と共有する。AS Metadata 取得
  // （`oid4vci/oid4vci-as-metadata.ts`）と検査が食い違わないようにするため。
  const parsed = await fetchWellKnownJson(
    credentialIssuer,
    ISSUER_METADATA_PATH,
    fetchImpl,
    metadataFailure,
  );
  // `credential_issuer` は取得に用いた識別子（= Offer の値）と一致しなければならない
  // （OID4VCI 1.0 §12.2.4）。照合しないと、別テナントの Metadata（別の `credential_endpoint` /
  // `authorization_servers`）を信じて Offer 由来の `pre-authorized_code` 等をそこへ送る。
  const declaredIssuer = ownProperty<unknown>(parsed, 'credential_issuer');
  if (typeof declaredIssuer !== 'string' || !sameIdentifier(declaredIssuer, credentialIssuer)) {
    throw metadataFailure('issuer_mismatch');
  }
  return parseIssuerEndpoints(parsed, credentialConfigurationIds);
}
