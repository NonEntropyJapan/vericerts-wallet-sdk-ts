/**
 * `personal_sign`（ERC-191）/ `eth_signTypedData_v4`（EIP-712）の署名対象バイト列の組み立てと、
 * `Signer` の 65 バイト recoverable 署名から標準 Ethereum 署名 hex（`r||s||v`、`v` は 27/28）への
 * 整形。
 *
 * `Signer.sign(data)` は `keccak256(data)` を内部で計算してから secp256k1 recoverable 署名する
 * （`keymanager.ts` の `getSigner` 参照）。したがって本モジュールが返す `payload` は
 * **ハッシュ前**のバイト列であり、そのまま `Signer.sign` へ渡せば各標準が定義する最終ダイジェストと
 * 一致する:
 * - `personal_sign`: `sign(keccak256("\x19Ethereum Signed Message:\n" ‖ len(message) ‖ message))`
 *   （ERC-191 `0x45` 版。`len(message)` は非ゼロパディングの ASCII 10 進数）。
 * - `eth_signTypedData_v4`: `sign(keccak256("\x19\x01" ‖ domainSeparator ‖ hashStruct(message)))`
 *   （EIP-712）。
 *
 * ethers 非依存（extension の alias 方針。`legacy-tx-serializer.ts` と同じ理由）。
 */

import { VericertsError } from '../errors.js';
import { isHexString } from '../evm-format.js';
import { keccak256 } from '../keymanager/address.js';
import { eip191SignedBytes, looksLikeEs256kRSigningInput } from '../keymanager/eip191.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { concatBytes } from './bytes.js';
import {
  fail,
  isStructType,
  memoizedTypeHash,
  newTypeHashMemo,
  parseArrayType,
  structFieldsOf,
  type TypedData,
  type TypeHashMemo,
} from './eth-typed-data-types.js';

/**
 * 公開サブパス `vericerts-wallet-sdk/asset-eth-signing`（extension の alias 先は本ファイル）の型・`encodeType` の窓口。
 * 実体は `eth-typed-data-types.ts`（行数上限のため分離）。
 */
export { encodeType, type TypedData, type TypedDataField } from './eth-typed-data-types.js';

import { bytesToHex, decodeHexDigits } from './hex-codec.js';
import { personalSignMessageBytes } from './personal-sign-message.js';

const UINT_BITS_MAX = 256;
const ADDRESS_HEX_LENGTH = 40;
const WORD_LENGTH = 32;
const RECOVERABLE_SIGNATURE_LENGTH = 65;

/**
 * `0x` プレフィックス付き hex 文字列をバイト列へ変換する。
 *
 * `0x` の有無は `evm-format.ts` の SSOT（{@link isHexString}）で検証し、プレフィックス無しの
 * 生 hex 文字列（桁数・パターンのみ一致するもの）は拒否する。
 */
function hexToBytes(hex: string): Uint8Array {
  if (!isHexString(hex, { allowEmpty: true })) fail();
  const normalized = hex.slice(2);
  if (normalized.length % 2 !== 0) fail();
  return decodeHexDigits(normalized);
}

/**
 * `personal_sign` の `params[0]`（EIP-1193 の hex エンコード済みメッセージ）を ERC-191 の
 * 署名対象バイト列へ組み立てる。
 *
 * `data` が妥当な `0x` hex（偶数長）ならそのバイト列をメッセージとみなし、そうでなければ
 * UTF-8 文字列そのものをメッセージとみなす（MetaMask 等が非 hex 入力を許容する慣行に合わせる。
 * どちらの場合も「メッセージのバイト列」を得るだけで、以降の prefix 組み立ては同一）。
 *
 * メッセージが `alg: "ES256K-R"` の JWS signing-input（`base64url(header).…`）に見える場合は拒否する（`SIGN_FAILED`）。
 * ES256K-R の JWS 署名は signing-input への EIP-191 署名と同一のため、通すと dApp が `personal_sign` 経由で利用者の
 * DID の署名（VP / VC / id_token）を偽造できる。
 *
 * @param data `personal_sign` の第一引数（hex 文字列、または非 hex の生テキスト）。
 * @returns `Signer.sign` にそのまま渡せる ERC-191 署名対象バイト列。
 */
export function personalSignPayload(data: string): Uint8Array {
  const message = personalSignMessageBytes(data);
  rejectEs256kRSigningInput(message);
  return eip191SignedBytes(message);
}

/** ES256K-R の JWS signing-input に見えるメッセージなら `SIGN_FAILED`。署名時ガードと承認前検証が共有する唯一の判定。 */
function rejectEs256kRSigningInput(message: Uint8Array): void {
  if (looksLikeEs256kRSigningInput(message)) fail();
}

/**
 * `personal_sign` の `params[0]` が署名してよい入力かを、署名せずに確かめる（承認ダイアログの**前**に使う）。
 * {@link personalSignPayload} と同じ正規化・同じ判定（{@link looksLikeEs256kRSigningInput}）を使うため、承認前に通した
 * 入力は署名時にも同じ理由で拒否されず、承認前に拒否した入力は署名時にも必ず拒否される。
 *
 * @throws `1020 SIGN_FAILED` メッセージが `alg: "ES256K-R"` の JWS signing-input に見える場合（ヘッダ長・hex 化に依らない）。
 */
export function assertPersonalSignAllowed(data: string): void {
  rejectEs256kRSigningInput(personalSignMessageBytes(data));
}

/** `value` を `bigint` へ正規化する（10 進 / `0x` hex 文字列、安全整数の number、bigint を許す）。 */
function toBigInt(value: unknown): bigint {
  if (typeof value === 'bigint') return value;
  // 小数・NaN・Infinity・安全整数範囲外は丸め込まれて別の値になるため拒否する。
  if (typeof value === 'number') return Number.isSafeInteger(value) ? BigInt(value) : fail();
  // 空文字列（`BigInt('')===0n`）・空白・`0b`/`0o` 等の曖昧な表記は許さない。
  if (typeof value === 'string')
    return /^-?(\d+|0x[0-9a-fA-F]+)$/.test(value) ? BigInt(value) : fail();
  fail();
}

/** `uintN` / `intN` の幅 N（省略時 256）。1〜256 の 8 の倍数でなければ `fail()`。 */
function parseIntBits(digits: string): number {
  if (digits === '') return UINT_BITS_MAX;
  const bits = Number(digits);
  if (!Number.isInteger(bits) || bits < 8 || bits > UINT_BITS_MAX || bits % 8 !== 0) fail();
  return bits;
}

/** `uintN` / `intN` を範囲検査のうえ 32 バイト big-endian（符号付きは 2 の補数）へエンコードする。 */
function encodeIntWord(value: bigint, signed: boolean, bits: number): Uint8Array {
  const width = BigInt(bits);
  const min = signed ? -(1n << (width - 1n)) : 0n;
  const max = signed ? (1n << (width - 1n)) - 1n : (1n << width) - 1n;
  if (value < min || value > max) fail();
  const modulus = 1n << BigInt(UINT_BITS_MAX);
  const normalized = value < 0n ? modulus + value : value;
  const bytes = new Uint8Array(WORD_LENGTH);
  let remaining = normalized;
  for (let i = WORD_LENGTH - 1; i >= 0; i--) {
    bytes[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

/** `address` を左ゼロパディングした 32 バイトへエンコードする。 */
function encodeAddressWord(value: unknown): Uint8Array {
  if (typeof value !== 'string') fail();
  const bytes = hexToBytes(value);
  if (bytes.length !== ADDRESS_HEX_LENGTH / 2) fail();
  const word = new Uint8Array(WORD_LENGTH);
  word.set(bytes, WORD_LENGTH - bytes.length);
  return word;
}

/** `bool` を 32 バイトの `0`/`1` へエンコードする。`true`/`false` 以外（欠落・文字列等）は拒否する。 */
function encodeBoolWord(value: unknown): Uint8Array {
  if (typeof value !== 'boolean') fail();
  const word = new Uint8Array(WORD_LENGTH);
  word[WORD_LENGTH - 1] = value ? 1 : 0;
  return word;
}

/** `bytes1`〜`bytes32` を右ゼロパディングした 32 バイトへエンコードする。 */
function encodeFixedBytesWord(value: unknown, size: number): Uint8Array {
  if (size < 1 || size > WORD_LENGTH) fail();
  if (typeof value !== 'string') fail();
  const bytes = hexToBytes(value);
  if (bytes.length !== size) fail();
  const word = new Uint8Array(WORD_LENGTH);
  word.set(bytes, 0);
  return word;
}

/** `bytes` / `string`（動的型）の内容を `keccak256` した 32 バイトへエンコードする。 */
function encodeDynamicWord(type: 'bytes' | 'string', value: unknown): Uint8Array {
  if (typeof value !== 'string') fail();
  const content = type === 'string' ? new TextEncoder().encode(value) : hexToBytes(value);
  return keccak256(content);
}

/**
 * EIP-712 の 1 フィールド分の「エンコード済み値」（常に 32 バイト）を返す。
 * atomic → 値そのもの、`bytes`/`string` → 内容の keccak256、配列 → 要素の連結の keccak256、
 * struct 参照 → {@link hashStruct}。
 */
function encodeFieldValue(
  type: string,
  value: unknown,
  types: TypedData['types'],
  typeHashes: TypeHashMemo,
): Uint8Array {
  // 1 回の署名計算で処理する値ノードの総数を縛る。超過は署名しない。
  if (--typeHashes.encodeNodesLeft < 0) fail();
  const arrayType = parseArrayType(type);
  if (arrayType) {
    if (!Array.isArray(value)) fail();
    // 固定長配列 `T[n]` は宣言と異なる要素数のデータへ署名しない（ethers の TypedDataEncoder と同じ）。
    if (arrayType.length !== undefined && value.length !== arrayType.length) fail();
    const elements = value.map((element) =>
      encodeFieldValue(arrayType.elementType, element, types, typeHashes),
    );
    return keccak256(concatBytes(...elements));
  }
  if (isStructType(type, types)) {
    if (typeof value !== 'object' || value === null) fail();
    return hashStruct(type, types, value as Record<string, unknown>, typeHashes);
  }
  if (type === 'string' || type === 'bytes') return encodeDynamicWord(type, value);
  if (type === 'address') return encodeAddressWord(value);
  if (type === 'bool') return encodeBoolWord(value);
  const fixedBytes = /^bytes(\d+)$/.exec(type);
  if (fixedBytes) return encodeFixedBytesWord(value, Number(fixedBytes[1]));
  const uint = /^uint(\d*)$/.exec(type);
  if (uint) return encodeIntWord(toBigInt(value), false, parseIntBits(uint[1] ?? ''));
  const int = /^int(\d*)$/.exec(type);
  if (int) return encodeIntWord(toBigInt(value), true, parseIntBits(int[1] ?? ''));
  fail();
}

/**
 * EIP-712 `encodeData = typeHash ‖ enc(value1) ‖ enc(value2) ‖ …`。
 *
 * `typeHashes` は 1 回の署名計算の間だけ有効な「struct 型名 → typeHash」のメモ。`typeHash` は `types` の総
 * サイズに比例するため、struct インスタンスごとに再計算すると処理量が (types サイズ) × (インスタンス数) の
 * 二次になる（types 283 KB × 6,000 インスタンスで 35 秒停止）。呼び出しごとに作る（`types` を
 * 変更して再利用される状況で古い値を返さないため、モジュール大域のキャッシュにはしない）。
 */
function encodeData(
  primaryType: string,
  types: TypedData['types'],
  data: Readonly<Record<string, unknown>>,
  typeHashes: TypeHashMemo,
): Uint8Array {
  const fields = structFieldsOf(types, primaryType);
  if (fields === undefined) fail();
  // 型定義の検査（同名フィールド重複の拒否を含む）を値の再帰より先に行う。子を何度も読む入力を、
  // 1 つも読む前に弾くため。
  const typeHash = memoizedTypeHash(primaryType, types, typeHashes);
  // message のフィールドも own 限定で読む。dApp が省略したフィールドを `Object.prototype` の汚染値で埋めると、
  // 承認画面（own 値のみ）に無い値を含む digest に署名してしまう。欠落は型別検査で 1020 になる。
  const encodedFields = fields.map((field) =>
    encodeFieldValue(
      field.type,
      Object.hasOwn(data, field.name) ? data[field.name] : undefined,
      types,
      typeHashes,
    ),
  );
  return concatBytes(typeHash, ...encodedFields);
}

/** EIP-712 `hashStruct(s) = keccak256(encodeData(s))`。 */
function hashStruct(
  primaryType: string,
  types: TypedData['types'],
  data: Readonly<Record<string, unknown>>,
  typeHashes: TypeHashMemo,
): Uint8Array {
  return keccak256(encodeData(primaryType, types, data, typeHashes));
}

/** `EIP712Domain` の許容フィールドと、仕様が定める正準の並び順。 */
const DOMAIN_FIELD_ORDER: readonly { readonly name: string; readonly type: string }[] = [
  { name: 'name', type: 'string' },
  { name: 'version', type: 'string' },
  { name: 'chainId', type: 'uint256' },
  { name: 'verifyingContract', type: 'address' },
  { name: 'salt', type: 'bytes32' },
];

/**
 * `domainSeparator = hashStruct(eip712Domain)`。ドメインに実在するフィールドのみを仕様順で
 * `EIP712Domain` 型として組み立てる（未使用フィールドは型定義から除く、EIP-712 本文の規則）。
 */
function domainSeparator(domain: TypedData['domain']): Uint8Array {
  const presentFields = DOMAIN_FIELD_ORDER.filter((field) => Object.hasOwn(domain, field.name));
  if (presentFields.length === 0) fail();
  return hashStruct('EIP712Domain', { EIP712Domain: presentFields }, domain, newTypeHashMemo());
}

/**
 * `eth_signTypedData_v4` の署名対象バイト列（EIP-712）を組み立てる。
 *
 * @param typedData `eth_signTypedData_v4` の `params[1]`（`types` / `primaryType` / `domain` / `message`）。
 * @returns `Signer.sign` にそのまま渡せる `"\x19\x01" ‖ domainSeparator ‖ hashStruct(message)`。
 * @throws 型定義・値の不整合（未対応型、struct 未定義、hex/アドレス形式不正等）の場合
 *         （VericertsError、code `1020`）。入力値は例外に含めない。
 */
export function typedDataV4Payload(typedData: TypedData): Uint8Array {
  try {
    // 4 つの最上位キーも own 限定で読む（省略した JS 呼び出しで `Object.prototype` の汚染値を採用しない）。
    const domain = ownProperty<TypedData['domain']>(typedData, 'domain');
    const primaryType = ownProperty<string>(typedData, 'primaryType');
    const types = ownProperty<TypedData['types']>(typedData, 'types');
    const message = ownProperty<TypedData['message']>(typedData, 'message');
    if (domain === undefined || primaryType === undefined || types === undefined) fail();
    if (message === undefined) fail();
    const domainHash = domainSeparator(domain);
    const struct = hashStruct(primaryType, types, message, newTypeHashMemo());
    return concatBytes(Uint8Array.of(0x19, 0x01), domainHash, struct);
  } catch (cause) {
    if (cause instanceof VericertsError) throw cause;
    fail();
  }
}

/**
 * `Signer.sign` が返す 65 バイト recoverable 署名（`r(32) || s(32) || recovery(1)`、
 * `recovery` は 0/1）を、標準 Ethereum 署名 hex（`r || s || v`、`v` は 27/28）へ整形する。
 *
 * @param signature `Signer.sign` の戻り値（65 バイト）。
 * @returns `0x` プレフィックス付き 130 hex 文字の署名。
 * @throws 署名長が 65 バイトでない場合（VericertsError、code `1020`）。
 */
export function formatEthereumSignature(signature: Uint8Array): string {
  if (signature.length !== RECOVERABLE_SIGNATURE_LENGTH) fail();
  const v = (signature[signature.length - 1] as number) + 27;
  return bytesToHex(
    concatBytes(signature.subarray(0, RECOVERABLE_SIGNATURE_LENGTH - 1), Uint8Array.of(v)),
  );
}
