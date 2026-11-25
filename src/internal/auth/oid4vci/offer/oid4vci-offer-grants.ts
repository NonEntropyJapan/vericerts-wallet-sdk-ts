/**
 * Credential Offer の `grants` の型と検証・正規化。
 *
 * grant ごとのメンバは OID4VCI 1.0 §4.1.1 に従う。
 *
 * `oid4vci-offer.ts` から分離したのは、Offer の取得（URI パース・参照形式の HTTP GET）と
 * grant の解釈が別の関心事であり、grant が 2 種類（`pre-authorized_code` / `authorization_code`）
 * に増えた時点で 1 ファイルに置くと「どの検証がどの grant に効くのか」が読み取れなくなるため。
 *
 * セキュリティ上の注意:
 * - Offer は**攻撃者が影響し得る入力**である。型不正はすべて `OFFER_URI_PARSE_FAILED`（3003）へ
 *   正規化し、例外に入力本文を載せない。
 * - **告知された grant だけをキーとして生やす**（未告知のキーを `undefined` で生やすと、
 *   読み手の `Object.hasOwn` による有無の判定と食い違う）。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { isAuthorizationServerValue } from '../../../primitives/oid4vci-input-limits.js';
import { isNonEmptyString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { parseTxCode, type TxCode } from './tx-code.js';

/** `urn:ietf:params:oauth:grant-type:pre-authorized_code` grant のキー。 */
export const PRE_AUTHORIZED_CODE_GRANT =
  'urn:ietf:params:oauth:grant-type:pre-authorized_code' as const;

/** `authorization_code` grant のキー（OID4VCI 1.0 §4.1.1）。 */
export const AUTHORIZATION_CODE_GRANT = 'authorization_code' as const;

/** Pre-Authorized Code Flow の grant 詳細。 */
export interface PreAuthorizedCodeGrant {
  /** Token Request に用いる pre-authorized code。 */
  readonly 'pre-authorized_code': string;
  /** tx_code が必要な場合の要件。省略時は PIN 不要。 */
  readonly tx_code?: TxCode;
  /**
   * この grant の code を発行した AS の識別子（`authorization_server`）。任意。
   *
   * Issuer Metadata の `authorization_servers` が複数を告知している場合の絞り込みに使う
   * （OID4VCI 1.0 §4.1.1）。Token Request は `authorization_code` grant と同じ規則
   * （`resolveAuthorizationServer`）で選んだ AS へ送る。
   */
  readonly authorization_server?: string;
}

/**
 * Authorization Code Flow の grant 詳細（OID4VCI 1.0 §4.1.1）。
 *
 * 本 grant は Pre-Authorized Code Flow と違い、Offer 自体に認可の材料を持たない。Wallet は
 * Issuer / AS Metadata を引いて PAR → 認可 → Token の順に進む。
 */
export interface AuthorizationCodeGrant {
  /**
   * Issuer が Offer と認可要求を紐付けるための不透明な状態値（`issuer_state`）。任意。
   *
   * 検証して保持するだけで、PAR へは載せない（転送は Planned・未実装）。
   * **Wallet は中身を解釈しない**
   * （Issuer 側のセッション識別子であり、構造を仮定すると Issuer の実装に結合する）。
   */
  readonly issuer_state?: string;
  /**
   * この grant の認可を担う AS の識別子（`authorization_server`）。任意。
   *
   * Issuer Metadata の `authorization_servers` が複数を告知している場合の絞り込みに使う
   * （OID4VCI 1.0 §4.1.1）。告知が無ければ呼び出し側が `authorization_servers` の先頭、
   * それも無ければ `credential_issuer` 自身を AS として扱う。
   */
  readonly authorization_server?: string;
}

/** Credential Offer の grants。 */
export interface CredentialGrants {
  /** Pre-Authorized Code Flow の grant。 */
  readonly [PRE_AUTHORIZED_CODE_GRANT]?: PreAuthorizedCodeGrant;
  /** Authorization Code Flow の grant。 */
  readonly [AUTHORIZATION_CODE_GRANT]?: AuthorizationCodeGrant;
}

/**
 * grants フィールドを検証し正規化する。
 *
 * Pre-Authorized Code grant が存在する場合は `pre-authorized_code`（非空文字列）と
 * 任意の `tx_code` を検証する。grants 自体は省略可能（Authorization Code Flow 等）。
 *
 * @param value `grants` の生値（`unknown`）。
 * @returns 妥当な場合は `CredentialGrants`。`undefined` 入力時は `undefined`。
 * @throws 型不正の場合（VericertsError、code `3003`）。
 */
export function parseGrants(value: unknown): CredentialGrants | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  const obj = value as Record<string, unknown>;
  const preAuthorized = parsePreAuthorizedGrant(
    ownProperty<unknown>(obj, PRE_AUTHORIZED_CODE_GRANT),
  );
  const authorizationCode = parseAuthorizationCodeGrant(
    ownProperty<unknown>(obj, AUTHORIZATION_CODE_GRANT),
  );
  // 両方とも告知が無い場合も空オブジェクトを返す（従来どおり許容する）。Offer が示す grant を
  // 呼び出し側が判定できるよう、**告知された grant だけをキーとして生やす**（未告知のキーを
  // `undefined` で生やすと `Object.hasOwn` による有無の判定と食い違う）。
  return {
    ...(preAuthorized === undefined ? {} : { [PRE_AUTHORIZED_CODE_GRANT]: preAuthorized }),
    ...(authorizationCode === undefined ? {} : { [AUTHORIZATION_CODE_GRANT]: authorizationCode }),
  };
}

/**
 * `pre-authorized_code` grant を検証・正規化する。
 *
 * @param value grant の生値（`unknown`）。
 * @returns 妥当な場合は正規化した grant。未告知なら `undefined`。
 * @throws 型不正 / `pre-authorized_code` 欠落の場合（VericertsError、code `3003`）。
 */
function parsePreAuthorizedGrant(value: unknown): PreAuthorizedCodeGrant | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  const grant = value as Record<string, unknown>;
  const code = ownProperty<unknown>(grant, 'pre-authorized_code');
  if (typeof code !== 'string' || code.length === 0) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  const txCode = parseTxCode(ownProperty<unknown>(grant, 'tx_code'));
  // `authorization_server` は任意（OID4VCI 1.0 §4.1.1）。告知された値が非文字列 / 空文字なら拒否する
  // （`authorization_code` grant と同じ。空文字は well-known URL の組み立てで相対パスに化ける）。
  const authorizationServer = ownProperty<unknown>(grant, 'authorization_server');
  if (authorizationServer !== undefined && !isAuthorizationServerValue(authorizationServer)) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  return {
    'pre-authorized_code': code,
    ...(txCode === undefined ? {} : { tx_code: txCode }),
    ...(authorizationServer === undefined ? {} : { authorization_server: authorizationServer }),
  };
}

/**
 * `authorization_code` grant を検証・正規化する。
 *
 * 必須メンバは無い（OID4VCI 1.0 §4.1.1。`issuer_state` / `authorization_server` はいずれも任意）。
 * ただし**告知された値が文字列でない / 空文字なら拒否する**。空文字の `issuer_state` をそのまま
 * PAR へ載せると、Issuer 側で「状態値あり」として扱われるか無視されるかが実装依存になり、
 * どちらに転んでも Wallet からは観測できない。同様に空文字の `authorization_server` は
 * well-known URL の組み立てで `/.well-known/...` という相対パスに化ける。
 *
 * @param value grant の生値（`unknown`）。
 * @returns 妥当な場合は正規化した grant。未告知なら `undefined`。
 * @throws 型不正の場合（VericertsError、code `3003`）。
 */
function parseAuthorizationCodeGrant(value: unknown): AuthorizationCodeGrant | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  const grant = value as Record<string, unknown>;
  const issuerState = ownProperty<unknown>(grant, 'issuer_state');
  const authorizationServer = ownProperty<unknown>(grant, 'authorization_server');
  if (issuerState !== undefined && !isNonEmptyString(issuerState)) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  if (authorizationServer !== undefined && !isAuthorizationServerValue(authorizationServer)) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  return {
    ...(issuerState === undefined ? {} : { issuer_state: issuerState }),
    ...(authorizationServer === undefined ? {} : { authorization_server: authorizationServer }),
  };
}
