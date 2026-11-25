/**
 * Authorization Code Flow の呼び出し側入力（`AuthorizationCodeFlowOptions`）の読み取りと検証。
 *
 * `receive.ts` の「AS / Issuer と何を順に話すか」から「呼び出し側から何を受け取ったか」を分離する
 * （依存側の同じ役割は `deps.ts`。方針・記法は `eudi/issuance/deps.ts` と同一である）。
 * 呼び出し側が渡すオブジェクトは `JSON.parse` を通らないため `parse-json.ts` のパース境界での
 * プロトタイプ除去が**一切効かない**（`own-property.ts`「本ヘルパーが効かない範囲」）。したがって
 * 読み取り時点の判定が唯一の防御線であり、その判定をこの 1 か所へ集約する。
 * 併せて「1 回だけ読んで以降はローカルだけを使う」ことで、own アクセサ付きのオブジェクトを
 * 渡されたときに検査した値と実際に使う値が食い違う（TOCTOU）余地を無くす。
 *
 * とくに `redirectUri` / `clientId` を鎖読みすると、指定していない正当な呼び出しで
 * `Object.prototype` の汚染値が「AS 登録済みのコールバック先」として PAR に push され、認可コードが
 * 攻撃者へ返る。`clientAssertion` の汚染値は指定していない `<WUA>~<WUA-PoP>` を PAR と
 * Token Request の両方へ送出する。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { isPublicHttpsUrl } from '../../../http/public-https-url.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { CredentialDefinition } from '../oid4vci.js';
import type { OAuth2AuthzDetails } from '../par/index.js';
import type { AuthorizationCodeEndpoints, AuthorizationCodeFlowOptions } from './types.js';

/** フロー内で `TOKEN_REQUEST_FAILED`（8010）へ寄せる失敗。理由は固定識別子のみ。 */
export function flowFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED, { context: { reason } });
}

/** `options` から読み出した、フローが実際に使う要求内容の組。 */
export interface ResolvedOptions {
  readonly endpoints: AuthorizationCodeEndpoints;
  /** JWT Proof の `aud` になる Credential Issuer Identifier（OID4VCI 1.0 §8.2.1.1）。 */
  readonly credentialIssuer: string;
  /** 認可応答の `iss` と完全一致を要求する AS の識別子（RFC 9207）。 */
  readonly authorizationServerIssuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly format: string;
  readonly credentialDefinition: CredentialDefinition;
  readonly vct?: string;
  readonly credentialConfigurationId: string | undefined;
  readonly scope: string | undefined;
  readonly authorizationDetails: readonly OAuth2AuthzDetails[] | undefined;
  readonly clientAssertion: string | undefined;
  readonly clientAssertionType: string | undefined;
}

/**
 * 4 つのエンドポイントを own 限定で読み、非空かつ HTTPS であることを確認する。
 *
 * **4 つとも本フローの入口で HTTPS を要求する**（`types.ts` が宣言する不変条件）。下流プリミティブ
 * にも HTTPS 検査はあるが、`requestTokenAuthorizationCode` のそれは `clientAssertion` 指定時のみの
 * 条件付きで、後方互換のため無条件化できない。委譲だけで済ませると `clientAssertion` を指定しない
 * 正当な呼び出しで `tokenEndpoint: 'http://…'` が素通りし、**認可コード・`code_verifier`・
 * `access_token` が平文で流れる**。本 API は新規で後方互換の制約が無いため、フロー側で無条件に
 * 課す。下流の検査はそのまま残り多層防御になる（判定の重複ではなく層の重ね）。
 */
function resolveEndpoints(options: AuthorizationCodeFlowOptions): AuthorizationCodeEndpoints {
  const raw = ownProperty<unknown>(options, 'endpoints');
  if (typeof raw !== 'object' || raw === null) {
    throw flowFailure('invalid_endpoints');
  }
  const parEndpoint = ownProperty<unknown>(raw, 'parEndpoint');
  const authorizationEndpoint = ownProperty<unknown>(raw, 'authorizationEndpoint');
  const tokenEndpoint = ownProperty<unknown>(raw, 'tokenEndpoint');
  const credentialEndpoint = ownProperty<unknown>(raw, 'credentialEndpoint');
  const declaredNonceEndpoint = ownProperty<unknown>(raw, 'nonceEndpoint');
  // 空文字・空白のみの拒否はコードベース全体で 1 規則にする（`non-empty-string.ts`）。
  if (
    !isNonBlankString(parEndpoint) ||
    !isNonBlankString(authorizationEndpoint) ||
    !isNonBlankString(tokenEndpoint) ||
    !isNonBlankString(credentialEndpoint)
  ) {
    throw flowFailure('invalid_endpoints');
  }
  // 1 つでも非 HTTPS なら fetch を発生させる前に落とす（`types.ts` の不変条件）。
  if (
    !isPublicHttpsUrl(parEndpoint) ||
    !isPublicHttpsUrl(authorizationEndpoint) ||
    !isPublicHttpsUrl(tokenEndpoint) ||
    !isPublicHttpsUrl(credentialEndpoint)
  ) {
    throw flowFailure('non_https_endpoint');
  }
  // `nonceEndpoint` は任意。宣言されているなら他と同じ検査を課す。未宣言でもキーを省略せず
  // `undefined` を own プロパティとして載せる（読み手が鎖読みで汚染値を拾わないように）。
  if (
    declaredNonceEndpoint !== undefined &&
    (!isNonBlankString(declaredNonceEndpoint) || !isPublicHttpsUrl(declaredNonceEndpoint))
  ) {
    throw flowFailure('non_https_endpoint');
  }
  const nonceEndpoint = isNonBlankString(declaredNonceEndpoint) ? declaredNonceEndpoint : undefined;
  return {
    parEndpoint,
    authorizationEndpoint,
    tokenEndpoint,
    credentialEndpoint,
    nonceEndpoint,
  };
}

/** `options` を 1 回だけ読み出して検証する（読み方の根拠は本ファイル冒頭）。 */
export function resolveOptions(options: AuthorizationCodeFlowOptions): ResolvedOptions {
  const clientId = ownProperty<unknown>(options, 'clientId');
  const redirectUri = ownProperty<unknown>(options, 'redirectUri');
  const format = ownProperty<unknown>(options, 'format');
  const credentialIssuer = ownProperty<unknown>(options, 'credentialIssuer');
  const authorizationServerIssuer = ownProperty<unknown>(options, 'authorizationServerIssuer');
  const credentialDefinition = ownProperty<unknown>(options, 'credentialDefinition');
  if (
    typeof clientId !== 'string' ||
    typeof redirectUri !== 'string' ||
    !isNonBlankString(credentialIssuer) ||
    !isNonBlankString(authorizationServerIssuer) ||
    typeof format !== 'string' ||
    typeof credentialDefinition !== 'object' ||
    credentialDefinition === null
  ) {
    throw flowFailure('invalid_options');
  }
  return {
    endpoints: resolveEndpoints(options),
    credentialIssuer,
    authorizationServerIssuer,
    clientId,
    redirectUri,
    format,
    credentialDefinition: credentialDefinition as CredentialDefinition,
    vct: ownProperty<string>(options, 'vct'),
    credentialConfigurationId: ownProperty<string>(options, 'credentialConfigurationId'),
    scope: ownProperty<string>(options, 'scope'),
    authorizationDetails: ownProperty<readonly OAuth2AuthzDetails[]>(
      options,
      'authorizationDetails',
    ),
    clientAssertion: ownProperty<string>(options, 'clientAssertion'),
    clientAssertionType: ownProperty<string>(options, 'clientAssertionType'),
  };
}
