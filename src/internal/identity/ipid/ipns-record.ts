/**
 * IPNS レコード（V2）の検証と、解決先 CID の取り出し。
 *
 * `did:ipid:<ipns-name>` の IPNS 名は所有者の公開鍵に由来する。Gateway（第三者運営 / 前段の中間者）が返す
 * 本文をそのまま DID Document として採用すると、攻撃者が任意の検証鍵を含む Document を返せる。
 * そこで Gateway からは署名付きレコードそのもの（`application/vnd.ipfs.ipns-record`）を取得し、
 * IPNS 名から導出した公開鍵で署名を検証したうえで、レコードが指す `/ipfs/<CID>` だけを採用する。
 * その CID の本文は `cid.ts` のハッシュ照合を通して初めて DID Document になる。
 *
 * **検証できる範囲（それ以外は fail-closed で拒否する）。**
 * - 名前: multihash `identity` に Ed25519 公開鍵（libp2p `PublicKey` protobuf、36 バイト）を埋め込んだ
 *   形式（`12D3Koo...` / `k51qzi5uqu5d...`）のみ。公開鍵が名前に含まれない sha2-256 形式（RSA / ECDSA）は
 *   レコード側の `pubKey` を信用する別経路になるため対象外とし拒否する。
 * - レコード: V2 署名（`signatureV2` / `data`）を持つもの。V2 署名の無い V1 のみのレコードは拒否する。
 * - `data`（CBOR）が標準の 5 フィールド（Value / Validity / ValidityType / Sequence / TTL）だけを持ち、
 *   protobuf 側に重複して現れる同名フィールドと一致すること（署名外の値で挙動を変えさせない）。
 * - 有効期限（`ValidityType` = EOL）が現在時刻より先であること。
 *
 * **検証しない範囲。** `Sequence` の単調増加は、過去に見たレコードの記憶（状態）が要るため状態を持たない
 * 解決器では検証できない。古いが EOL 内のレコードを返す巻き戻しは、EOL までの間は防げない（IPNS の仕様上の
 * 限界。EOL を短くして発行する運用で縮める）。
 *
 * 例外メッセージや `context` にレコード本体・鍵バイト・DID を含めない。
 */

import { CBOR_MAJOR, readCborHeader } from '../../cbor.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { verifyEd25519 } from '../../keymanager/ed25519.js';
import { decodeMultihash } from '../content-hash/multihash.js';
import {
  consumeResolutionWork,
  type ResolutionWorkBudget,
  WORK_UNITS_PER_SIGNATURE,
} from '../resolution-budget.js';
import { classifyIpidIdentifier, decodeIpidIdentifierBytes } from './cid.js';

/** Gateway が返す IPNS レコードの Content-Type（trustless gateway 仕様）。 */
export const IPNS_RECORD_CONTENT_TYPE = 'application/vnd.ipfs.ipns-record';

/** IPNS レコード本文の上限（バイト）。公式実装の上限は 10 KiB。 */
export const MAX_IPNS_RECORD_BYTES = 10 * 1024;

/** V2 署名の対象に前置される固定文字列。 */
const SIGNATURE_V2_PREFIX = new TextEncoder().encode('ipns-signature:');
/** multihash `identity`。 */
const MULTIHASH_IDENTITY = 0x00;
/** multicodec `libp2p-key`。 */
const CODEC_LIBP2P_KEY = 0x72;
/** libp2p `PublicKey` protobuf（`KeyType` = Ed25519(1)、`Data` = 32 バイト）の固定プレフィックス。 */
const ED25519_PUBLIC_KEY_PROTOBUF_PREFIX = Uint8Array.from([0x08, 0x01, 0x12, 0x20]);
const ED25519_PUBLIC_KEY_LENGTH = 32;
/** `ValidityType` = EOL（`Validity` は RFC 3339 の有効期限）。 */
const VALIDITY_TYPE_EOL = 0n;
/** `data` の CBOR マップが持ち得るキー数（Value / Validity / ValidityType / Sequence / TTL）。 */
const CBOR_FIELD_COUNT = 5;
const UTF8 = new TextDecoder('utf-8', { fatal: true });

/** protobuf / CBOR の値（バイト列 or 非負整数）。 */
type FieldValue = Uint8Array | bigint;

function invalidRecord(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.DID_DOC_INVALID, { context: { reason } });
}

/** IPNS 名から Ed25519 公開鍵（32 バイト）を取り出す。埋め込み形式でなければ `undefined`。 */
export function ed25519KeyFromIpnsName(name: string): Uint8Array | undefined {
  if (classifyIpidIdentifier(name) !== 'ipns') {
    return undefined;
  }
  const bytes = decodeIpidIdentifierBytes(name);
  if (bytes === undefined) {
    return undefined;
  }
  // CIDv1（version 1, codec libp2p-key）は先頭 2 バイトを除いた残りが multihash。PeerID はそのまま multihash。
  const multihashBytes = bytes[0] === 0x01 ? bytes.subarray(2) : bytes;
  if (bytes[0] === 0x01 && bytes[1] !== CODEC_LIBP2P_KEY) {
    return undefined;
  }
  const multihash = decodeMultihash(multihashBytes);
  if (multihash?.code !== MULTIHASH_IDENTITY) {
    return undefined;
  }
  const { digest } = multihash;
  const prefixLength = ED25519_PUBLIC_KEY_PROTOBUF_PREFIX.length;
  if (
    digest.length !== prefixLength + ED25519_PUBLIC_KEY_LENGTH ||
    !ED25519_PUBLIC_KEY_PROTOBUF_PREFIX.every((byte, index) => digest[index] === byte)
  ) {
    return undefined;
  }
  return digest.subarray(prefixLength);
}

/** unsigned LEB128（最大 64bit）を 1 個読む。非 canonical / 範囲外 / 途切れは `undefined`。 */
function readVarint64(
  bytes: Uint8Array,
  offset: number,
): { value: bigint; next: number } | undefined {
  let value = 0n;
  for (let i = 0; i < 10; i += 1) {
    const byte = bytes[offset + i];
    if (byte === undefined) {
      return undefined;
    }
    value |= BigInt(byte & 0x7f) << BigInt(7 * i);
    if ((byte & 0x80) === 0) {
      // 最終バイトが 0 の多バイト表現は非 canonical。
      if (i > 0 && byte === 0) {
        return undefined;
      }
      return value < 1n << 64n ? { value, next: offset + i + 1 } : undefined;
    }
  }
  return undefined;
}

/** `IpnsEntry` protobuf を（フィールド番号 → 値）に解く。重複・未対応の wire type・余剰は拒否する。 */
function parseIpnsEntry(record: Uint8Array): Map<number, FieldValue> {
  const fields = new Map<number, FieldValue>();
  let offset = 0;
  while (offset < record.length) {
    const tag = readVarint64(record, offset);
    if (tag === undefined) {
      throw invalidRecord('ipns_record_malformed');
    }
    const fieldNumber = Number(tag.value >> 3n);
    const wireType = Number(tag.value & 7n);
    let value: FieldValue;
    if (wireType === 0) {
      const read = readVarint64(record, tag.next);
      if (read === undefined) {
        throw invalidRecord('ipns_record_malformed');
      }
      value = read.value;
      offset = read.next;
    } else if (wireType === 2) {
      const length = readVarint64(record, tag.next);
      if (length === undefined || length.value > BigInt(record.length - length.next)) {
        throw invalidRecord('ipns_record_malformed');
      }
      const end = length.next + Number(length.value);
      value = record.subarray(length.next, end);
      offset = end;
    } else {
      throw invalidRecord('ipns_record_malformed');
    }
    if (fields.has(fieldNumber)) {
      throw invalidRecord('ipns_record_malformed');
    }
    fields.set(fieldNumber, value);
  }
  return fields;
}

/** `data`（CBOR マップ）を 5 つの標準フィールドだけに解く。それ以外の形は拒否する。 */
function parseSignedData(data: Uint8Array): Map<string, FieldValue> {
  const header = readCborHeader(data, 0);
  if (header?.majorType !== CBOR_MAJOR.map || header.value > CBOR_FIELD_COUNT) {
    throw invalidRecord('ipns_record_malformed');
  }
  const fields = new Map<string, FieldValue>();
  let offset = header.headerLen;
  for (let i = 0; i < header.value; i += 1) {
    const keyHead = readCborHeader(data, offset);
    if (keyHead?.majorType !== CBOR_MAJOR.textString) {
      throw invalidRecord('ipns_record_malformed');
    }
    const keyStart = offset + keyHead.headerLen;
    const keyBytes = data.subarray(keyStart, keyStart + keyHead.value);
    if (keyBytes.length !== keyHead.value) {
      throw invalidRecord('ipns_record_malformed');
    }
    let key: string;
    try {
      key = UTF8.decode(keyBytes);
    } catch {
      throw invalidRecord('ipns_record_malformed');
    }
    const valueHead = readCborHeader(data, keyStart + keyHead.value);
    if (valueHead === undefined || fields.has(key)) {
      throw invalidRecord('ipns_record_malformed');
    }
    const valueStart = keyStart + keyHead.value + valueHead.headerLen;
    if (valueHead.majorType === CBOR_MAJOR.unsigned) {
      fields.set(key, BigInt(valueHead.value));
      offset = valueStart;
    } else if (valueHead.majorType === CBOR_MAJOR.byteString) {
      const bytes = data.subarray(valueStart, valueStart + valueHead.value);
      if (bytes.length !== valueHead.value) {
        throw invalidRecord('ipns_record_malformed');
      }
      fields.set(key, bytes);
      offset = valueStart + valueHead.value;
    } else {
      throw invalidRecord('ipns_record_malformed');
    }
  }
  const known = ['Value', 'Validity', 'ValidityType', 'Sequence', 'TTL'];
  if (offset !== data.length || [...fields.keys()].some((key) => !known.includes(key))) {
    throw invalidRecord('ipns_record_malformed');
  }
  return fields;
}

function sameValue(left: FieldValue, right: FieldValue): boolean {
  if (typeof left === 'bigint' || typeof right === 'bigint') {
    return left === right;
  }
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/** protobuf 側に現れる V1 互換フィールド（番号）と `data` 側の名前の対応。 */
const PROTOBUF_FIELD_TO_DATA_KEY: ReadonlyArray<readonly [number, string]> = [
  [1, 'Value'],
  [3, 'ValidityType'],
  [4, 'Validity'],
  [5, 'Sequence'],
  [6, 'TTL'],
];

/** RFC 3339 の有効期限（UTC・Z 終端、小数秒 1〜9 桁）を epoch ミリ秒にする。不正なら `undefined`。 */
function parseEolMillis(validity: Uint8Array): number | undefined {
  let text: string;
  try {
    text = UTF8.decode(validity);
  } catch {
    return undefined;
  }
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(text);
  if (match === null) {
    return undefined;
  }
  const millis = Date.parse(`${match[1]}.${(match[2] ?? '').padEnd(3, '0').slice(0, 3)}Z`);
  return Number.isNaN(millis) ? undefined : millis;
}

/**
 * Gateway が返した IPNS レコードを検証し、レコードが指す CID（`/ipfs/<CID>` の `<CID>`）を返す。
 *
 * 署名検証（Ed25519 1 回）は検証の前に `scope` へ前払いする。
 *
 * @param name did:ipid の IPNS 名（method-specific id）。
 * @param record Gateway から取得したレコード（protobuf）のバイト列。
 * @param scope 解決スコープの予算。
 * @param nowMillis 現在時刻（epoch ミリ秒、テストで差し替える）。
 * @returns 署名済みレコードの `Value` が指す CID（multibase 文字列）。
 * @throws 検証できない名前・レコード不正・署名不正・期限切れ・解決先が `/ipfs/<CID>` でない場合
 *   （VericertsError、code `2010`、`context.reason` は `ipns_key_unsupported` / `ipns_record_malformed` /
 *   `ipns_signature_invalid` / `ipns_record_expired` / `ipns_value_invalid`）。予算超過は code `2001`。
 */
export function verifyIpnsRecord(
  name: string,
  record: Uint8Array,
  scope: ResolutionWorkBudget | undefined,
  nowMillis: number = Date.now(),
): string {
  const publicKey = ed25519KeyFromIpnsName(name);
  if (publicKey === undefined) {
    throw invalidRecord('ipns_key_unsupported');
  }
  const entry = parseIpnsEntry(record);
  const signature = entry.get(8);
  const data = entry.get(9);
  if (!(signature instanceof Uint8Array) || !(data instanceof Uint8Array)) {
    throw invalidRecord('ipns_record_malformed');
  }
  consumeResolutionWork(scope, WORK_UNITS_PER_SIGNATURE);
  const signed = new Uint8Array(SIGNATURE_V2_PREFIX.length + data.length);
  signed.set(SIGNATURE_V2_PREFIX, 0);
  signed.set(data, SIGNATURE_V2_PREFIX.length);
  if (!verifyEd25519(signed, signature, publicKey)) {
    throw invalidRecord('ipns_signature_invalid');
  }
  // 署名の通った `data` だけを真とし、署名外の protobuf フィールドは一致する場合のみ許す。
  const signedFields = parseSignedData(data);
  for (const [fieldNumber, key] of PROTOBUF_FIELD_TO_DATA_KEY) {
    const outside = entry.get(fieldNumber);
    const inside = signedFields.get(key);
    if (outside !== undefined && (inside === undefined || !sameValue(outside, inside))) {
      throw invalidRecord('ipns_record_malformed');
    }
  }
  const value = signedFields.get('Value');
  const validity = signedFields.get('Validity');
  if (!(value instanceof Uint8Array) || !(validity instanceof Uint8Array)) {
    throw invalidRecord('ipns_record_malformed');
  }
  if (signedFields.get('ValidityType') !== VALIDITY_TYPE_EOL) {
    throw invalidRecord('ipns_record_malformed');
  }
  const eol = parseEolMillis(validity);
  if (eol === undefined) {
    throw invalidRecord('ipns_record_malformed');
  }
  if (eol <= nowMillis) {
    throw invalidRecord('ipns_record_expired');
  }
  let path: string;
  try {
    path = UTF8.decode(value);
  } catch {
    throw invalidRecord('ipns_value_invalid');
  }
  const cid = /^\/ipfs\/([A-Za-z0-9]+)$/.exec(path)?.[1];
  if (cid === undefined || classifyIpidIdentifier(cid) !== 'cid') {
    throw invalidRecord('ipns_value_invalid');
  }
  return cid;
}
