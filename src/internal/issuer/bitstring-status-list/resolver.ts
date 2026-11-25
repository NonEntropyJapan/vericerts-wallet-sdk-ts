/**
 * Bitstring Status List のエントリを取得・検証・評価する（取得 → リスト VC 検証 → エントリ評価）。
 *
 * W3C §3.2 Validate Algorithm 全体を 1 本にまとめる。
 *
 * **Fail-closed**: 取得失敗（`fetchCredential` の例外）はそのまま伝播し、検証に失敗したリストが
 * 「有効」として返ることはない。IETF Token Status List の `createStatusListResolver` が持つ
 * Fail-open（FO-1 / FO-2）は Token 専用の stale キャッシュに依存するため、
 * Bitstring Status List には持ち込まない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URL・JWT を含めない。
 */

import type { VerifyCredentialOptions } from '../../credential/vc/verify.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { verifyBitstringStatusListCredential } from './credential.js';
import { type BitstringStatusResult, checkBitstringStatus } from './entry.js';

/** `resolveBitstringStatus` のオプション。 */
export interface BitstringStatusResolverOptions {
  /**
   * リスト VC（コンパクト JWT-VC）を URL から取得する関数（DI）。ネットワーク I/O は呼び出し側に委ねる。
   * 取得失敗は投げてよい（そのまま伝播する）。
   */
  readonly fetchCredential: (url: string) => Promise<string>;
  /** リスト VC の署名検証鍵・現在時刻（`verifyCredential` のオプション）。 */
  readonly verify: VerifyCredentialOptions;
}

/**
 * `credentialStatus` エントリを解決して値を返す。
 *
 * @param entry 検証対象 VC の `credentialStatus`（`BitstringStatusListEntry`。外部入力）。
 * @param opts 取得関数と検証オプション。
 * @returns 読み取った値・用途・（`message` 目的の）メッセージ。
 * @throws `statusListCredential` が文字列でない・`fetchCredential` が関数でない・取得結果が文字列でない
 *   場合（code `3002`）。`fetchCredential` の失敗はそのまま伝播。リスト VC の検証失敗は
 *   `verifyBitstringStatusListCredential`、エントリの不整合は `checkBitstringStatus` のとおり。
 */
export async function resolveBitstringStatus(
  entry: unknown,
  opts: BitstringStatusResolverOptions,
): Promise<BitstringStatusResult> {
  const fetchCredential = nonObjectPrototypeProperty<
    BitstringStatusResolverOptions['fetchCredential']
  >(opts, 'fetchCredential');
  const verify = ownProperty<VerifyCredentialOptions>(opts, 'verify');
  const url =
    typeof entry === 'object' && entry !== null
      ? ownProperty<unknown>(entry, 'statusListCredential')
      : undefined;
  if (
    typeof fetchCredential !== 'function' ||
    typeof verify !== 'object' ||
    verify === null ||
    typeof url !== 'string' ||
    url === ''
  ) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const jwt = await fetchCredential(url);
  if (typeof jwt !== 'string') {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const list = await verifyBitstringStatusListCredential(jwt, url, verify);
  return checkBitstringStatus(entry, list);
}
