/**
 * Credential Offer の `tx_code`（ユーザー入力 PIN の要件）の型と検証・正規化。
 *
 * `oid4vci-offer-grants.ts` から分離したのは、ディレクトリ行数上限（linterly）の都合と、`tx_code` の
 * 検証が grant 構造の検証から独立しているため。仕様 SoT: OID4VCI 1.0 §4.1.1。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';

/** `tx_code.description` の最大文字数（OID4VCI 1.0 §4.1.1）。 */
const TX_CODE_DESCRIPTION_MAX_LENGTH = 300;

/**
 * tx_code（ユーザー入力 PIN）の要件。
 *
 * `tx_code` オブジェクトが**存在すること自体**が「Token Request に PIN が必須」の印であり、
 * メンバはすべて任意（OID4VCI 1.0 §4.1.1。`{}` も正当）。
 */
export interface TxCode {
  /** 期待される PIN の桁数。Issuer が告知した場合のみ（正の整数）。 */
  readonly length?: number;
  /** 入力モード（`'numeric'` | `'text'`）。Issuer が省略した場合は既定の `'numeric'`。 */
  readonly input_mode: 'numeric' | 'text';
  /** PIN の送付方法等を説明する文言（300 文字以内）。Issuer が告知した場合のみ。 */
  readonly description?: string;
}

/**
 * tx_code フィールドを検証し正規化する。
 *
 * メンバはすべて任意（OID4VCI 1.0 §4.1.1）。告知された場合のみ型を検査し、
 * 未告知の `input_mode` は既定の `'numeric'` で埋める。
 *
 * @param value `tx_code` の生値（`unknown`）。
 * @returns 妥当な場合は `TxCode`。`undefined` 入力時は `undefined`。
 * @throws 型不正の場合（VericertsError、code `3003`）。
 */
export function parseTxCode(value: unknown): TxCode | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  const obj = value as Record<string, unknown>;
  const length = ownProperty<unknown>(obj, 'length');
  if (
    length !== undefined &&
    (typeof length !== 'number' || !Number.isInteger(length) || length <= 0)
  ) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  const inputModeValue = ownProperty<unknown>(obj, 'input_mode');
  const inputMode = inputModeValue === undefined ? 'numeric' : inputModeValue;
  if (inputMode !== 'numeric' && inputMode !== 'text') {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  const description = ownProperty<unknown>(obj, 'description');
  if (
    description !== undefined &&
    (typeof description !== 'string' || [...description].length > TX_CODE_DESCRIPTION_MAX_LENGTH)
  ) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED);
  }
  return {
    input_mode: inputMode,
    ...(length === undefined ? {} : { length }),
    ...(description === undefined ? {} : { description }),
  };
}
