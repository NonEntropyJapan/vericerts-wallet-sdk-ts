/**
 * EIP-712 の型定義（`TypedData`）と `encodeType` / `typeHash` の計算（`eth-signing.ts` の下位ロジック）。
 *
 * `typeHash` の計算量は `types` の総サイズに比例するため、
 * 呼び出し側（`eth-signing.ts`）は {@link memoizedTypeHash} で型名ごとに 1 回だけ計算する。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { keccak256 } from '../keymanager/address.js';

/** 署名計算の失敗（`SIGN_FAILED`）。入力値は例外に含めない。 */
export function fail(): never {
  throw new VericertsError(ErrorCodes.SIGN_FAILED);
}

/** EIP-712 型定義（`types` の 1 エントリ）。 */
export interface TypedDataField {
  readonly name: string;
  readonly type: string;
}

/** `eth_signTypedData_v4` の `params[1]`（JSON-Schema は EIP-712 本文の `TypedData` 定義に準拠）。 */
export interface TypedData {
  readonly types: Readonly<Record<string, readonly TypedDataField[]>>;
  readonly primaryType: string;
  readonly domain: Readonly<Record<string, unknown>>;
  readonly message: Readonly<Record<string, unknown>>;
}

/**
 * struct のフィールド型文字列（`Foo[][]` 等を含む）の最大文字数。正規の型は高々数十文字。配列サフィックスを
 * 1 つずつ剥がす処理は文字列長に対して二次になり、500 KB の型 1 つで 21 秒以上停止するため、入口で打ち切る。
 */
export const MAX_FIELD_TYPE_CHARS = 256;

/**
 * `type` が配列型（`Foo[]` / `Foo[3]`）かを判定し、要素型と固定長 n（動的配列は `undefined`）を返す。配列でなければ `null`。
 * 型文字列が {@link MAX_FIELD_TYPE_CHARS} を超えるときは `fail()`（`1020`）。末尾から 1 回だけ線形に走査する。
 */
export function parseArrayType(
  type: string,
): { readonly elementType: string; readonly length: number | undefined } | null {
  if (type.length > MAX_FIELD_TYPE_CHARS) fail();
  if (!type.endsWith(']')) return null;
  const open = type.lastIndexOf('[');
  if (open < 1) return null;
  const digits = type.slice(open + 1, -1);
  if (!/^\d*$/.test(digits)) return null;
  return { elementType: type.slice(0, open), length: digits === '' ? undefined : Number(digits) };
}

/** struct 型（`types` に定義がある型）かどうか。 */
export function isStructType(type: string, types: TypedData['types']): boolean {
  return Object.hasOwn(types, type);
}

/**
 * `types` の struct 定義を **own 限定**で引く（無ければ `undefined`）。素の `types[name]` は鎖を辿るため、
 * `Object.prototype.<型名>` が汚染された環境で、dApp が定義していない型（`types: {}` の `primaryType: 'Evil'` 等）が
 * 汚染値で定義されたものとして受理される。
 */
export function structFieldsOf(
  types: TypedData['types'],
  typeName: string,
): readonly TypedDataField[] | undefined {
  return Object.hasOwn(types, typeName) ? types[typeName] : undefined;
}

/** `primaryType` から到達可能な参照 struct 型（`primaryType` 自身を除く）を名前昇順で集める。 */
function collectReferencedTypes(primaryType: string, types: TypedData['types']): string[] {
  const seen = new Set<string>();
  const visit = (typeName: string): void => {
    const fields = structFieldsOf(types, typeName);
    if (fields === undefined) fail();
    for (const field of fields) {
      // 多次元配列（`A[][]` / `A[2][]`）は、基底型に達するまで末尾の `[n]` を 1 つずつ剥がす。
      let baseType = field.type;
      let arrayType = parseArrayType(baseType);
      while (arrayType) {
        baseType = arrayType.elementType;
        arrayType = parseArrayType(baseType);
      }
      if (isStructType(baseType, types) && baseType !== primaryType && !seen.has(baseType)) {
        seen.add(baseType);
        visit(baseType);
      }
    }
  };
  visit(primaryType);
  return [...seen].sort();
}

/**
 * struct 定義 1 件の `Type(type1 name1,type2 name2,...)` 表現。同名フィールドの重複は拒否する（`fail()`）。
 * EIP-712 の `encodeType` は名前の一意性が前提で、重複を許すと `data[name]` が同じ子を何度も読み、入力サイズに
 * 対して `fan^depth` 回のエンコードが走る。
 */
function encodeStructType(typeName: string, types: TypedData['types']): string {
  const fields = structFieldsOf(types, typeName);
  if (fields === undefined) fail();
  if (new Set(fields.map((f) => f.name)).size !== fields.length) fail();
  return `${typeName}(${fields.map((f) => `${f.type} ${f.name}`).join(',')})`;
}

/** EIP-712 `encodeType`: 主 struct の定義に続けて、参照する struct 定義を名前昇順で連結する。 */
export function encodeType(primaryType: string, types: TypedData['types']): string {
  const referenced = collectReferencedTypes(primaryType, types);
  return [primaryType, ...referenced].map((name) => encodeStructType(name, types)).join('');
}

/**
 * 1 回の署名計算の間だけ有効な「struct 型名 → typeHash」のメモと、`encodeType` 文字列の総量・値のエンコード
 * ノード数の残り予算（{@link encodeData}）。
 */
export interface TypeHashMemo {
  readonly hashes: Map<string, Uint8Array>;
  encodeCharsLeft: number;
  encodeNodesLeft: number;
}

/**
 * 1 回の署名計算で `encodeType` を作って keccak256 に掛ける総文字数の上限。型が相互に参照する長い連鎖
 * （N 型が連なると各 typeHash が O(N) 文字）は、型ごとに 1 回に抑えても全体で O(N²) になる。正規の typed data
 * （Permit2 / Seaport 等）は高々数 KB。
 */
export const MAX_TYPE_ENCODE_CHARS = 1024 * 1024;

/**
 * 1 回の署名計算で値をエンコードするノード数（`encodeFieldValue` の呼び出し = struct フィールド 1 個または配列要素 1 個）の上限。
 * 同名フィールドの重複（{@link encodeStructType} が拒否する）で同じ子を何度も読ませる入力は `fan^depth` / `K×N` 回の
 * 処理になる。重複を拒否しても、`message` が同一オブジェクトを複数箇所から参照する呼び出し（JSON 由来ではあり得ない
 * 形）で同じ膨張が起き得るため、総ノード数でも縛る。`MAX_DAPP_PARAMS_BYTES`（512 KiB）の JSON が取り得る
 * 要素数（`1,` の繰り返しで約 26 万）に近い 20 万を、正規の typed data（Permit2 / Seaport 等は数百ノード）に十分な余裕で採る。
 */
export const MAX_ENCODE_NODES = 200_000;

export function newTypeHashMemo(): TypeHashMemo {
  return {
    hashes: new Map(),
    encodeCharsLeft: MAX_TYPE_ENCODE_CHARS,
    encodeNodesLeft: MAX_ENCODE_NODES,
  };
}

/** EIP-712 `typeHash = keccak256(encodeType(primaryType))` を型名ごとに 1 回だけ計算する。総量が予算を超えたら `fail()`。 */
export function memoizedTypeHash(
  primaryType: string,
  types: TypedData['types'],
  memo: TypeHashMemo,
): Uint8Array {
  let hash = memo.hashes.get(primaryType);
  if (hash === undefined) {
    const encoded = encodeType(primaryType, types);
    memo.encodeCharsLeft -= encoded.length;
    if (memo.encodeCharsLeft < 0) fail();
    hash = keccak256(new TextEncoder().encode(encoded));
    memo.hashes.set(primaryType, hash);
  }
  return hash;
}
