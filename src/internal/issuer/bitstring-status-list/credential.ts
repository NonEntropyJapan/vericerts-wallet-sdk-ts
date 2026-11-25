/**
 * `BitstringStatusListCredential`（JWT-VC 形式）の発行と検証。
 *
 * W3C §2.2 BitstringStatusListCredential /
 * §3.2 Validate Algorithm。JSON-LD + Data Integrity Proof 形式のリスト VC は SDK に検証プリミティブが無く
 * （`verifyCredential` が扱うのは JWT-VC のみ）、署名を検証できないものは受理しないため扱わない。
 *
 * 検証の順序（W3C §3.2）: 署名・時刻（`verifyCredential`。期限切れは 3024、署名不正は 3010）→
 * リスト URL の突合（`vc.id` ≠ 参照 URL は 3010。署名が有効でも別 URL のリストへのすり替えを拒否）→
 * 種別（`BitstringStatusListCredential` / `BitstringStatusList` でなければ 3002）→ `encodedList` の復号と
 * 最小長検査（`BitstringStatusList.decode`）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URL・JWT を含めない。
 */

import { issueCredentialAsync } from '../../credential/vc/issue.js';
import type { AnyCredentialSigner } from '../../credential/vc/signer.js';
import type { VerifiableCredential } from '../../credential/vc/vc.js';
import { type VerifyCredentialOptions, verifyCredential } from '../../credential/vc/verify.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isEpochSeconds } from '../../primitives/option-guard.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { BitstringStatusList } from './list.js';

/** リスト VC の `type`（W3C §2.2）。 */
export const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE = 'BitstringStatusListCredential' as const;

/** リスト VC の `credentialSubject.type`（W3C §2.2）。 */
export const BITSTRING_STATUS_LIST_TYPE = 'BitstringStatusList' as const;

/** W3C VC Data Model v2.0 の base context。 */
const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

/** `signBitstringStatusListCredential` のオプション。 */
export interface BitstringStatusListCredentialOptions {
  /** リスト VC を公開する URL（必須。エントリの `statusListCredential` と一致させる）。 */
  readonly id: string;
  /** 発行者識別子（必須。`iss` / `issuer`）。 */
  readonly issuer: string;
  /** 発行時刻（エポック秒）。既定は現在時刻。テストの決定性のため注入可能。 */
  readonly issuanceSeconds?: number;
  /** 発行時刻からの有効期間（秒、任意）。指定すると `expirationDate`（= JWT `exp`）を設定する。 */
  readonly ttlSeconds?: number;
}

/** エポック秒を秒精度の ISO 8601（`...Z`）にする。 */
function toIsoSeconds(seconds: number): string {
  return new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');
}

/**
 * リストを JWT-VC 形式の `BitstringStatusListCredential` として署名する（W3C §3.1）。
 *
 * JWT の登録クレーム（`iss` / `sub` / `jti` / `nbf` / `exp`）は内包 VC と整合させて組み立てるため、
 * `verifyBitstringStatusListCredential`（= `verifyCredential`）がそのまま受理する。状態を更新したら
 * 再度呼んで再署名した最新のリスト VC を配信する。
 *
 * @param list 公開するリスト。
 * @param signer JWT-VC 署名鍵（同期 / 非同期（KMS / HSM）のどちらも可）。
 * @param opts 公開 URL・発行者・発行時刻・有効期間。
 * @returns コンパクト JWT-VC。
 * @throws `id` / `issuer` が空 / `issuanceSeconds` が不正 / `ttlSeconds` が正の整数でない場合（code `3002`）、
 *   署名演算が失敗した場合（code `1020`）。
 */
export async function signBitstringStatusListCredential(
  list: BitstringStatusList,
  signer: AnyCredentialSigner,
  opts: BitstringStatusListCredentialOptions,
): Promise<string> {
  const id = ownProperty<string>(opts, 'id');
  const issuer = ownProperty<string>(opts, 'issuer');
  const ttlSeconds = ownProperty<number>(opts, 'ttlSeconds');
  const iat = ownProperty<number>(opts, 'issuanceSeconds') ?? Math.floor(Date.now() / 1000);
  if (
    typeof id !== 'string' ||
    id === '' ||
    typeof issuer !== 'string' ||
    issuer === '' ||
    !isEpochSeconds(iat) ||
    (ttlSeconds !== undefined && !(Number.isInteger(ttlSeconds) && ttlSeconds > 0))
  ) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const vc: VerifiableCredential = {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential', BITSTRING_STATUS_LIST_CREDENTIAL_TYPE],
    id,
    issuer,
    issuanceDate: toIsoSeconds(iat),
    ...(ttlSeconds === undefined ? {} : { expirationDate: toIsoSeconds(iat + ttlSeconds) }),
    credentialSubject: {
      id: `${id}#list`,
      type: BITSTRING_STATUS_LIST_TYPE,
      statusPurpose: list.purpose,
      encodedList: await list.encode(),
      ...(list.statusSize === 1 ? {} : { statusSize: list.statusSize }),
    },
  };
  return issueCredentialAsync(vc, signer, { nowSeconds: iat });
}

/**
 * JWT-VC 形式のリスト VC を検証し、リストを取り出す（W3C §3.2 Validate Algorithm）。
 *
 * @param jwt 取得したリスト VC（コンパクト JWT-VC）。
 * @param expectedUrl 参照元エントリの `statusListCredential`。リスト VC の `id` と一致しなければならない。
 * @param opts 署名検証鍵・現在時刻（`verifyCredential` のオプション）。
 * @returns 復号済みのリスト（最小長検査済み）。
 * @throws 署名不正 / `vc.id` ≠ `expectedUrl`（code `3010`）、期限切れ（`3024`）、有効化前（`3025`）、
 *   種別違い・`statusPurpose` / `encodedList` / `statusSize` の型不正・`encodedList` 不正・最小長未満
 *   （`STATUS_LIST_LENGTH_ERROR`。code `3002`）。
 */
export async function verifyBitstringStatusListCredential(
  jwt: string,
  expectedUrl: string,
  opts: VerifyCredentialOptions,
): Promise<BitstringStatusList> {
  const { payload } = verifyCredential(jwt, opts);
  // `verifyCredential` は VC 1.1 系（`vc` claim）に加え VC 2.0 系（`vc` 非包み）も通すため、
  // `vc` claim の有無はここで確かめる。Status List VC は `vc` claim の形（本 SDK が発行する形）だけを
  // 扱い、それ以外は従来どおり構造不正（3002）。以降は読み取りだけ own 限定で行う。
  const vc = ownProperty<Record<string, unknown>>(payload, 'vc');
  if (vc === undefined) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  if (ownProperty<unknown>(vc, 'id') !== expectedUrl) {
    // 署名が有効でも、別 URL のリストを掴まされた（差し替え）ことを意味する。
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  const types = ownProperty<unknown>(vc, 'type');
  const subject = ownProperty<unknown>(vc, 'credentialSubject');
  if (
    !Array.isArray(types) ||
    !types.includes(BITSTRING_STATUS_LIST_CREDENTIAL_TYPE) ||
    typeof subject !== 'object' ||
    subject === null ||
    ownProperty<unknown>(subject, 'type') !== BITSTRING_STATUS_LIST_TYPE
  ) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return BitstringStatusList.decode(
    ownProperty<unknown>(subject, 'encodedList'),
    ownProperty<unknown>(subject, 'statusPurpose'),
    ownProperty<unknown>(subject, 'statusSize') ?? 1,
  );
}
