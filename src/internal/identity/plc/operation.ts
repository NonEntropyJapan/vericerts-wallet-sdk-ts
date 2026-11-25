/**
 * did:plc の操作（`plc_operation` / `plc_tombstone` / 旧形式 `create`）のモデルと符号化。
 *
 * - 署名の対象は **sig を除いた操作の DAG-CBOR**。CID は署名済み操作の DAG-CBOR を SHA-256 で
 *   ハッシュした CIDv1（base32 / `dag-cbor` 0x71 / `sha-256` 0x12）で、次の操作の `prev` が指す。
 * - DID はジェネシス（署名済み）の DAG-CBOR の SHA-256 を base32 化した**先頭 24 文字**。
 * - 旧形式 `create`（signingKey / recoveryKey / handle / service）は**検証でのみ受理**し、旧形式のまま符号化して
 *   ハッシュ・署名検証する。文書の組み立てのために `PlcOperationData` へ正規化する（参照実装の `normalizeOp`）。
 * - 未知のキーを持つ操作は拒否する（DAG-CBOR にそのまま載ってハッシュされるため、検証側と生成側で
 *   解釈が割れる余地を作らない）。
 *
 * セキュリティ上の注意: 例外メッセージや `context` に操作の内容・DID を含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base32nopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { encodeDagCbor } from './dag-cbor.js';
import { parseKey, parseRotationKey } from './keys.js';

/** PLC のサービス（`services` の値）。 */
export interface PlcService {
  type: string;
  /** http / https の URL。 */
  endpoint: string;
}

/** 操作が持つ DID の状態データ。 */
export interface PlcOperationData {
  /** `did:key`。0〜5 件、secp256k1 / P-256。優先度順（先頭が最強）。生成 API は 1 件以上・重複なし。 */
  rotationKeys: readonly string[];
  /** キー名 → `did:key`（`#` なし）。 */
  verificationMethods: Readonly<Record<string, string>>;
  alsoKnownAs: readonly string[];
  services: Readonly<Record<string, PlcService>>;
}

/** 署名済みの操作（JSON 表現）。 */
export interface PlcSignedOperation {
  type: 'plc_operation' | 'plc_tombstone';
  prev: string | null;
  sig: string;
  [k: string]: unknown;
}

/** 操作 1 件の最大サイズ（署名済み・DAG-CBOR のバイト数）。 */
export const MAX_OPERATION_BYTES = 7500;
/** `rotationKeys` の最大件数。 */
export const MAX_ROTATION_KEYS = 5;

/** CIDv1 の接頭辞（version 1 / dag-cbor 0x71 / sha-256 0x12 / 長さ 32）。 */
const CID_PREFIX = Uint8Array.from([0x01, 0x71, 0x12, 0x20]);
/** DID 識別子の長さ。 */
const IDENTIFIER_LENGTH = 24;

/** 検証済みの操作 1 件。 */
export interface ParsedOperation {
  readonly kind: 'operation' | 'tombstone' | 'legacy';
  readonly prev: string | null;
  readonly sig: string;
  /** sig を除いた操作の DAG-CBOR（署名の対象）。 */
  readonly unsigned: Uint8Array;
  /** 署名済み操作の DAG-CBOR。 */
  readonly signed: Uint8Array;
  /** 署名済み操作の CID。 */
  readonly cid: string;
  /** 正規化した状態データ（tombstone は `undefined`）。 */
  readonly data: PlcOperationData | undefined;
}

export type Raw = Record<string, unknown>;

function invalidOperation(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID, {
    context: { reason: 'plc_operation_invalid' },
  });
}

export function isRecord(value: unknown): value is Raw {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

/** `own` のキー集合が `allowed` と完全一致することを要求する。 */
function assertExactKeys(raw: Raw, allowed: readonly string[]): void {
  const keys = Object.keys(raw);
  if (keys.length !== allowed.length || !allowed.every((key) => Object.hasOwn(raw, key))) {
    throw invalidOperation();
  }
}

/** 署名済み操作の DAG-CBOR → CID（`b` + base32 小文字）。 */
export function cidOfSignedBytes(signed: Uint8Array): string {
  const digest = sha256(signed);
  const bytes = new Uint8Array(CID_PREFIX.length + digest.length);
  bytes.set(CID_PREFIX, 0);
  bytes.set(digest, CID_PREFIX.length);
  return `b${base32nopad.encode(bytes).toLowerCase()}`;
}

/** ジェネシス（署名済み）の DAG-CBOR → DID（`did:plc:` + 先頭 24 文字）。 */
export function didOfGenesisBytes(signed: Uint8Array): string {
  return `did:plc:${base32nopad.encode(sha256(signed)).toLowerCase().slice(0, IDENTIFIER_LENGTH)}`;
}

/** 既存操作の回転鍵を検証する（0〜5 件・secp256k1 / P-256 の `did:key`）。 */
function assertSupportedRotationKeys(keys: unknown): asserts keys is string[] {
  if (!isStringArray(keys) || keys.length > MAX_ROTATION_KEYS) {
    throw invalidOperation();
  }
  for (const key of keys) {
    parseRotationKey(key);
  }
}

/** 生成 API は制御権の意図しない放棄・重複を避けるため、1 件以上・重複なしを要求する。 */
export function assertRotationKeys(keys: unknown): asserts keys is string[] {
  assertSupportedRotationKeys(keys);
  if (keys.length === 0 || new Set(keys).size !== keys.length) {
    throw invalidOperation();
  }
}

function readVerificationMethods(raw: unknown): Record<string, string> {
  if (!isRecord(raw)) {
    throw invalidOperation();
  }
  const result: Record<string, string> = Object.create(null);
  for (const [name, key] of Object.entries(raw)) {
    if (name.length === 0 || typeof key !== 'string') {
      throw invalidOperation();
    }
    parseKey(key);
    result[name] = key;
  }
  return result;
}

function readServices(raw: unknown): Record<string, PlcService> {
  if (!isRecord(raw)) {
    throw invalidOperation();
  }
  const result: Record<string, PlcService> = Object.create(null);
  for (const [name, service] of Object.entries(raw)) {
    if (name.length === 0 || !isRecord(service)) {
      throw invalidOperation();
    }
    assertExactKeys(service, ['type', 'endpoint']);
    const { type, endpoint } = service;
    if (typeof type !== 'string' || typeof endpoint !== 'string') {
      throw invalidOperation();
    }
    result[name] = { type, endpoint };
  }
  return result;
}

/** 状態データ 4 項目を検証して取り出す（`plc_operation` と、生成時の入力検査で共有）。 */
export function readOperationData(raw: Raw): PlcOperationData {
  const { rotationKeys, verificationMethods, alsoKnownAs, services } = raw;
  // 既存ログには制御権を放棄する空配列と重複鍵が許される。生成 API の制約とは分ける。
  assertSupportedRotationKeys(rotationKeys);
  if (!isStringArray(alsoKnownAs)) {
    throw invalidOperation();
  }
  return {
    rotationKeys: [...rotationKeys],
    verificationMethods: readVerificationMethods(verificationMethods),
    alsoKnownAs: [...alsoKnownAs],
    services: readServices(services),
  };
}

/** 旧形式 `create` を `PlcOperationData` へ正規化する（参照実装 `normalizeOp` と同じ写像）。 */
function normalizeLegacy(raw: Raw): PlcOperationData {
  const { signingKey, recoveryKey, handle, service } = raw;
  if (
    typeof signingKey !== 'string' ||
    typeof recoveryKey !== 'string' ||
    typeof handle !== 'string' ||
    typeof service !== 'string'
  ) {
    throw invalidOperation();
  }
  parseKey(signingKey);
  parseKey(recoveryKey);
  return {
    rotationKeys: [recoveryKey, signingKey],
    verificationMethods: { atproto: signingKey },
    alsoKnownAs: [
      handle.startsWith('at://')
        ? handle
        : `at://${handle.replace('http://', '').replace('https://', '')}`,
    ],
    services: {
      atproto_pds: {
        type: 'AtprotoPersonalDataServer',
        endpoint: /^https?:\/\//.test(service) ? service : `https://${service}`,
      },
    },
  };
}

/**
 * 監査ログの `operation`（JSON）を構文検証し、署名の対象・署名済みバイト・CID を計算する。
 *
 * @param operation JSON としてパース済みの操作。
 * @returns 検証済みの操作。
 * @throws 形式不正（VericertsError、code `2001`、`context.reason: 'plc_operation_invalid'`）。
 */
export function parseOperation(operation: unknown): ParsedOperation {
  if (!isRecord(operation)) {
    throw invalidOperation();
  }
  const { type, prev, sig } = operation;
  if (typeof sig !== 'string' || (prev !== null && typeof prev !== 'string')) {
    throw invalidOperation();
  }
  let kind: ParsedOperation['kind'];
  let data: PlcOperationData | undefined;
  if (type === 'plc_operation') {
    assertExactKeys(operation, [
      'type',
      'rotationKeys',
      'verificationMethods',
      'alsoKnownAs',
      'services',
      'prev',
      'sig',
    ]);
    kind = 'operation';
    data = readOperationData(operation);
  } else if (type === 'plc_tombstone') {
    assertExactKeys(operation, ['type', 'prev', 'sig']);
    if (prev === null) {
      throw invalidOperation();
    }
    kind = 'tombstone';
  } else if (type === 'create') {
    assertExactKeys(operation, [
      'type',
      'signingKey',
      'recoveryKey',
      'handle',
      'service',
      'prev',
      'sig',
    ]);
    if (prev !== null) {
      throw invalidOperation();
    }
    kind = 'legacy';
    data = normalizeLegacy(operation);
  } else {
    throw invalidOperation();
  }
  const { sig: _sig, ...unsignedOperation } = operation;
  const unsigned = encodeDagCbor(unsignedOperation);
  const signed = encodeDagCbor(operation);
  return { kind, prev, sig, unsigned, signed, cid: cidOfSignedBytes(signed), data };
}
