/**
 * did:plc の DID 形式と CID 形式の検査。
 *
 * DID は `did:plc:` + base32 小文字（`a-z2-7`）24 文字。仕様は小文字への正規化を推奨するが、SDK は DID 文字列の一致で
 * 同一性を判定するため、大文字を含む識別子は正規化せず `2001` で拒否する。
 * CID は CIDv1 / base32（`b`）/ `dag-cbor`（0x71）/ `sha-256`（0x12）の 36 バイトを再エンコードして一致するものだけを受理する。
 *
 * セキュリティ上の注意: 例外メッセージや `context` に入力値を含めない。
 */

import { base32nopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';

/** did:plc の形式。 */
export const PLC_DID_PATTERN = /^did:plc:[a-z2-7]{24}$/;

const CID_PATTERN = /^b[a-z2-7]{58}$/;
const CID_HEADER = [0x01, 0x71, 0x12, 0x20];

/**
 * did:plc の形式を検査する。
 *
 * @throws 形式不正（VericertsError、code `2001`）。
 */
export function assertPlcDid(did: unknown): asserts did is string {
  if (typeof did !== 'string' || !PLC_DID_PATTERN.test(did)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}

/**
 * `prev` に使う CID の形式（CIDv1 / base32 / dag-cbor / sha-256）を検査する。
 *
 * @throws 形式不正（VericertsError、code `2001`、`context.reason: 'plc_operation_invalid'`）。
 */
export function assertPrevCid(prev: unknown): asserts prev is string {
  if (typeof prev === 'string' && CID_PATTERN.test(prev)) {
    try {
      const bytes = base32nopad.decode(prev.slice(1).toUpperCase());
      if (
        bytes.length === 36 &&
        CID_HEADER.every((byte, index) => bytes[index] === byte) &&
        base32nopad.encode(bytes).toLowerCase() === prev.slice(1)
      ) {
        return;
      }
    } catch {
      // 下の拒否へ落とす。
    }
  }
  throw new VericertsError(ErrorCodes.INVALID_DID, {
    context: { reason: 'plc_operation_invalid' },
  });
}
