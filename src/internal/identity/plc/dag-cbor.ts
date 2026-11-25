/**
 * did:plc の操作を符号化する最小の DAG-CBOR エンコーダー。
 *
 * PLC の操作は文字列・null・配列・マップだけで構成されるため、扱う型をその 4 種に限る。
 * 整数・浮動小数・真偽値・バイト列・未定義値は操作に現れないので**受け付けず**、`2001` で拒否する
 * （「静かに別の符号化へ丸める」と CID が一致しない操作を作る / 検証してしまう）。
 *
 * DAG-CBOR の規則（https://ipld.io/specs/codecs/dag-cbor/spec/）のうち、この型の範囲で効くもの:
 * - 長さは最短形（引数 0〜23 は 1 バイトに畳む、以降は 1 / 2 / 4 バイト）。不定長は使わない。
 * - マップのキーは文字列だけで、**キーの UTF-8 バイト長の昇順、同長なら辞書順（バイト比較）**。
 *   JSON のキー順や JS の `sort()`（UTF-16 コード単位）とは一致しないため、バイト列で比べる。
 * - 同一キーの重複は不可。
 *
 * セキュリティ上の注意: 例外メッセージや `context` に操作の内容を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';

const MAJOR_TEXT = 3 << 5;
const MAJOR_ARRAY = 4 << 5;
const MAJOR_MAP = 5 << 5;
const CBOR_NULL = 0xf6;

/** 対のない（lone）サロゲート。UTF-8 に符号化できず、`TextEncoder` は黙って U+FFFD に置換してしまう。 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** DAG-CBOR へ符号化できる値（PLC の操作が使う型）。 */
export type DagCborValue =
  | string
  | null
  | readonly DagCborValue[]
  | { readonly [key: string]: DagCborValue };

const textEncoder = new TextEncoder();

function invalid(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID, {
    context: { reason: 'plc_operation_invalid' },
  });
}

/** 型 + 長さの引数ヘッダ（最短形）を出力に積む。 */
function pushHead(out: number[], major: number, length: number): void {
  if (length < 24) {
    out.push(major | length);
  } else if (length < 0x100) {
    out.push(major | 24, length);
  } else if (length < 0x10000) {
    out.push(major | 25, length >>> 8, length & 0xff);
  } else {
    out.push(
      major | 26,
      length >>> 24,
      (length >>> 16) & 0xff,
      (length >>> 8) & 0xff,
      length & 0xff,
    );
  }
}

function pushBytes(out: number[], bytes: Uint8Array): void {
  for (const byte of bytes) {
    out.push(byte);
  }
}

/** 2 つのバイト列を DAG-CBOR のマップキー順（長さ優先、同長はバイト辞書順）で比較する。 */
function compareKeyBytes(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) {
    return a.length - b.length;
  }
  for (let i = 0; i < a.length; i += 1) {
    const diff = (a[i] as number) - (b[i] as number);
    if (diff !== 0) {
      return diff;
    }
  }
  return 0;
}

function encodeText(out: number[], text: string): Uint8Array {
  if (LONE_SURROGATE.test(text)) {
    throw invalid();
  }
  const bytes = textEncoder.encode(text);
  pushHead(out, MAJOR_TEXT, bytes.length);
  pushBytes(out, bytes);
  return bytes;
}

function encodeInto(out: number[], value: unknown, depth: number): void {
  // PLC の操作は 3 段（操作 → services → 1 サービス）。深い入力は符号化せず拒否する。
  if (depth > 8) {
    throw invalid();
  }
  if (value === null) {
    out.push(CBOR_NULL);
    return;
  }
  if (typeof value === 'string') {
    encodeText(out, value);
    return;
  }
  if (Array.isArray(value)) {
    pushHead(out, MAJOR_ARRAY, value.length);
    for (const item of value) {
      encodeInto(out, item, depth + 1);
    }
    return;
  }
  if (typeof value === 'object' && value !== undefined) {
    const entries = Object.keys(value).map((key) => {
      if (LONE_SURROGATE.test(key)) {
        throw invalid();
      }
      return { key: textEncoder.encode(key), value: (value as Record<string, unknown>)[key] };
    });
    entries.sort((a, b) => compareKeyBytes(a.key, b.key));
    pushHead(out, MAJOR_MAP, entries.length);
    for (const entry of entries) {
      pushHead(out, MAJOR_TEXT, entry.key.length);
      pushBytes(out, entry.key);
      encodeInto(out, entry.value, depth + 1);
    }
    return;
  }
  throw invalid();
}

/**
 * 値を DAG-CBOR にエンコードする。
 *
 * @param value 文字列・null・配列・マップ（文字列キー）だけで構成された値。
 * @returns DAG-CBOR のバイト列。
 * @throws 上記以外の型（数値・真偽値・`undefined` 等）・対のないサロゲートを含む文字列・深すぎる入力の
 *         場合（VericertsError、code `2001`、`context.reason: 'plc_operation_invalid'`）。
 */
export function encodeDagCbor(value: unknown): Uint8Array {
  const out: number[] = [];
  encodeInto(out, value, 0);
  return Uint8Array.from(out);
}
