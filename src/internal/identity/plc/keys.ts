/**
 * did:plc の鍵（`did:key` 表記）と ECDSA 署名の検証・正規化。
 *
 * - 回転鍵は secp256k1 / P-256 のみ（Ed25519 は署名を検証できない鍵種別として拒否）。
 * - 署名は **low-S・64 バイト compact（r || s）・base64url（パディングなし）** の正規形だけを受理する。
 *   High-S や非正規形の base64url は、同じ操作に複数の有効な署名（= 複数の CID）を許し、DID や `prev` の
 *   参照が一意でなくなるため検証で拒否する。署名の対象は DAG-CBOR の符号化バイト列（sig を除く）で、
 *   ECDSA-SHA256（`prehash` 既定）。
 *
 * セキュリティ上の注意: 例外メッセージや `context` に鍵・署名・操作の内容を含めない。
 */

import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DidKeyType } from '../did.js';
import { parseDidKey } from '../method-key.js';

/** 署名のバイト長（r 32B || s 32B）。 */
const SIGNATURE_LENGTH = 64;

/** 署名を検証できる ECDSA 曲線。 */
type EcdsaCurve = typeof secp256k1 | typeof p256;

/** 回転鍵として使える（署名を検証できる）鍵。 */
export interface PlcRotationKey {
  readonly keyType: 'secp256k1' | 'P-256';
  readonly publicKey: Uint8Array;
}

function curveOf(keyType: PlcRotationKey['keyType']): EcdsaCurve {
  return keyType === 'secp256k1' ? secp256k1 : p256;
}

function invalidOperation(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID, {
    context: { reason: 'plc_operation_invalid' },
  });
}

/**
 * `did:key` 表記の鍵を構文として検証して分解する。
 *
 * @param didKey `did:key:z...`。
 * @returns 鍵タイプと raw 公開鍵。
 * @throws `did:key` として不正な場合（VericertsError、code `2001`）。
 */
export function parseKey(didKey: string): { keyType: DidKeyType; publicKey: Uint8Array } {
  try {
    return parseDidKey(didKey);
  } catch {
    throw invalidOperation();
  }
}

/**
 * 回転鍵（secp256k1 / P-256 の `did:key`）を検証して分解する。曲線上の点でない鍵も拒否する。
 *
 * @param didKey `did:key:z...`。
 * @returns 回転鍵。
 * @throws Ed25519 / 不正な `did:key` / 曲線上にない点の場合（VericertsError、code `2001`）。
 */
export function parseRotationKey(didKey: string): PlcRotationKey {
  const { keyType, publicKey } = parseKey(didKey);
  if (keyType === 'Ed25519') {
    throw invalidOperation();
  }
  try {
    curveOf(keyType).Point.fromBytes(publicKey);
  } catch {
    throw invalidOperation();
  }
  return { keyType, publicKey };
}

/**
 * 署名（base64url、パディングなし）を 64 バイトにデコードする。再エンコードして一致しない非正規形は拒否する。
 *
 * @returns 64 バイトの署名。不正なら `undefined`。
 */
export function decodeSignature(sig: string): Uint8Array | undefined {
  let bytes: Uint8Array;
  try {
    bytes = base64urlnopad.decode(sig);
  } catch {
    return undefined;
  }
  if (bytes.length !== SIGNATURE_LENGTH || base64urlnopad.encode(bytes) !== sig) {
    return undefined;
  }
  return bytes;
}

/**
 * 署名を鍵で検証する（low-S のみ受理）。署名 1 回ぶんの検証仕事量は呼び出し側が計上する。
 *
 * @param key 検証する鍵。
 * @param unsigned sig を除いた操作の DAG-CBOR。
 * @param sig base64url（パディングなし）の署名。
 * @returns 有効なら `true`。形式不正・不一致・High-S は `false`。
 */
export function verifySignature(key: PlcRotationKey, unsigned: Uint8Array, sig: string): boolean {
  const bytes = decodeSignature(sig);
  if (bytes === undefined) {
    return false;
  }
  try {
    return curveOf(key.keyType).verify(bytes, unsigned, key.publicKey, { lowS: true });
  } catch {
    return false;
  }
}

/**
 * 署名器が返した 64 バイトの署名を low-S へ正規化し、base64url（パディングなし）にする。
 *
 * @param keyType 署名に使った鍵の種別。
 * @param raw 署名器の戻り値（r || s）。
 * @throws 64 バイトでない・r / s が範囲外の場合（VericertsError、code `2010`、`context.reason: 'plc_signature_invalid'`）。
 */
export function normalizeSignature(keyType: PlcRotationKey['keyType'], raw: Uint8Array): string {
  if (raw instanceof Uint8Array && raw.length === SIGNATURE_LENGTH) {
    try {
      const curve = curveOf(keyType);
      const signature = curve.Signature.fromBytes(raw, 'compact');
      const normalized = signature.hasHighS()
        ? new curve.Signature(signature.r, curve.Point.Fn.ORDER - signature.s)
        : signature;
      return base64urlnopad.encode(normalized.toBytes('compact'));
    } catch {
      // r / s の検査失敗も署名形式のエラーへ正規化する。
    }
  }
  throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
    context: { reason: 'plc_signature_invalid' },
  });
}
