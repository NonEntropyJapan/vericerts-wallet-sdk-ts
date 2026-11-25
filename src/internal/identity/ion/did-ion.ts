/**
 * did:ion の DID 形式と long-form のローカル検証。
 *
 * ```text
 * did:ion:<did-suffix>                  # short-form（アンカー後）
 * did:ion:<did-suffix>:<初期状態>        # long-form（アンカー前から解決可能）
 * ```
 *
 * - `did-suffix` は Create 操作の Suffix Data を JCS で正規化し、SHA-256 の multihash（`0x12 0x20`）を
 *   base64url（パディングなし）にしたもの（先頭 `Ei`）。
 * - 初期状態は `{ suffixData, delta }` を JCS で正規化して base64url にしたもの。
 * - long-form は (a) `suffixData` のハッシュ = `did-suffix`、(b) `delta` のハッシュ = `suffixData.deltaHash` を
 *   必ずローカルで確かめる。不一致は `2010`（`ion_long_form_mismatch`）。
 *   保証するのは DID と初期状態の対応だけで、ノードが返す文書を初期状態から再構成して突き合わせることはしない。
 *
 * 受理する形式は上の 2 形だけで、ネットワーク名などの追加セグメントは `2001`（`ion_unsupported_form`）。
 * JCS は `webvh/codec.ts` の `canonicalize`（RFC 8785 のキー順・数値・文字列表現）を共有する。
 *
 * セキュリティ上の注意: 例外の `context` に DID・初期状態の内容を含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { MAX_DID_LENGTH } from '../did-format.js';
import {
  consumeResolutionWork,
  type ResolutionWorkBudget,
  WORK_UNITS_PER_KEY_HASH,
} from '../resolution-budget.js';
import { canonicalize } from '../webvh/codec.js';

/** DID の接頭辞。 */
const DID_ION_PREFIX = 'did:ion:';

/** multihash（sha2-256）の先頭 2 バイト（コード `0x12`・長さ `0x20`）。 */
const MULTIHASH_SHA256_PREFIX = Uint8Array.of(0x12, 0x20);

/** multihash（sha2-256）全体の長さ。 */
const MULTIHASH_BYTES = 34;

/** long-form の検証 1 回（`suffixData` と `delta` の JCS + SHA-256 の 2 回）の仕事量。 */
export const WORK_UNITS_PER_ION_LONG_FORM = 2 * WORK_UNITS_PER_KEY_HASH;

/** 解析済みの did:ion。 */
export interface ParsedDidIon {
  /** did-suffix（base64url の multihash）。 */
  readonly suffix: string;
  /** long-form の初期状態セグメント（short-form では `undefined`）。 */
  readonly longForm?: string;
}

function invalidDid(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID, { context: { reason } });
}

/** `value` が、sha2-256 multihash の canonical な base64url（パディングなし）か。 */
function isMultihashBase64url(value: string): boolean {
  let bytes: Uint8Array;
  try {
    bytes = base64urlnopad.decode(value);
  } catch {
    return false;
  }
  return (
    bytes.length === MULTIHASH_BYTES &&
    bytes[0] === MULTIHASH_SHA256_PREFIX[0] &&
    bytes[1] === MULTIHASH_SHA256_PREFIX[1] &&
    base64urlnopad.encode(bytes) === value
  );
}

/**
 * did:ion を `did:ion:<suffix>` / `did:ion:<suffix>:<long-form>` の 2 形に限って解析する。
 *
 * @throws 接頭辞違い・長さ超過・suffix 不正・long-form セグメントが空 / base64url でない（code `2001`、
 *   `ion_invalid_suffix` / `ion_invalid_long_form`）、追加セグメントを持つ形（code `2001`、`ion_unsupported_form`）。
 */
export function parseDidIon(did: string): ParsedDidIon {
  if (!did.startsWith(DID_ION_PREFIX) || did.length > MAX_DID_LENGTH) {
    throw invalidDid('ion_invalid_suffix');
  }
  const segments = did.slice(DID_ION_PREFIX.length).split(':');
  if (segments.length > 2) {
    // `did:ion:<network>:<suffix>` など。表記は各メソッドの定めで、検証手段がない形は受理しない。
    throw invalidDid('ion_unsupported_form');
  }
  const [suffix, longForm] = segments as [string, string | undefined];
  if (!isMultihashBase64url(suffix)) {
    throw invalidDid('ion_invalid_suffix');
  }
  if (longForm === undefined) {
    return { suffix };
  }
  if (longForm.length === 0 || !/^[A-Za-z0-9_-]+$/.test(longForm)) {
    throw invalidDid('ion_invalid_long_form');
  }
  return { suffix, longForm };
}

/** 値の JCS の SHA-256 multihash を base64url にする（Sidetree の `canonicalizeThenHashThenEncode`）。 */
function hashThenEncode(value: unknown): string {
  const digest = sha256(new TextEncoder().encode(canonicalize(value)));
  const multihash = new Uint8Array(MULTIHASH_BYTES);
  multihash.set(MULTIHASH_SHA256_PREFIX, 0);
  multihash.set(digest, MULTIHASH_SHA256_PREFIX.length);
  return base64urlnopad.encode(multihash);
}

function mismatch(): VericertsError {
  return new VericertsError(ErrorCodes.DID_DOC_INVALID, {
    context: { reason: 'ion_long_form_mismatch' },
  });
}

/**
 * long-form の初期状態をローカルで検証する。short-form は何もしない。
 *
 * 検証の仕事量（ハッシュ 2 回ぶん）を `scope` に計上する。計上は JSON のパースより前に行い、尽きた
 * スコープでは `2001`（`resolution_work_limit`）で拒否する。
 *
 * @throws 初期状態が base64url / JSON / `{ suffixData, delta }` の形でない（code `2001`、
 *   `ion_invalid_long_form`）・スコープの予算超過（code `2001`）・ハッシュ不一致（code `2010`、
 *   `ion_long_form_mismatch`）。
 */
export function verifyIonLongForm(parsed: ParsedDidIon, scope?: ResolutionWorkBudget): void {
  if (parsed.longForm === undefined) {
    return;
  }
  consumeResolutionWork(scope, WORK_UNITS_PER_ION_LONG_FORM);
  let initialState: unknown;
  try {
    initialState = parseJsonWithoutPrototype(
      new TextDecoder('utf-8', { fatal: true }).decode(base64urlnopad.decode(parsed.longForm)),
    );
  } catch {
    throw invalidDid('ion_invalid_long_form');
  }
  if (typeof initialState !== 'object' || initialState === null || Array.isArray(initialState)) {
    throw invalidDid('ion_invalid_long_form');
  }
  const suffixData = ownProperty<unknown>(initialState, 'suffixData');
  const delta = ownProperty<unknown>(initialState, 'delta');
  if (typeof suffixData !== 'object' || suffixData === null || Array.isArray(suffixData)) {
    throw invalidDid('ion_invalid_long_form');
  }
  if (typeof delta !== 'object' || delta === null || Array.isArray(delta)) {
    throw invalidDid('ion_invalid_long_form');
  }
  const deltaHash = ownProperty<unknown>(suffixData, 'deltaHash');
  if (typeof deltaHash !== 'string') {
    throw invalidDid('ion_invalid_long_form');
  }
  if (hashThenEncode(suffixData) !== parsed.suffix || hashThenEncode(delta) !== deltaHash) {
    throw mismatch();
  }
}
