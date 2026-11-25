/**
 * バックアップ CBOR の「仕事量予算つき」ネイティブ復号。
 *
 * 旧実装は復号前検査（tag・不定長・深さだけを見る）の後に `cbor-x` で復号し、`JSON.stringify` →
 * `JSON.parse`（reviver が全オブジェクトを複製）で null プロトタイプ化していた。この「検査は一部だけ・
 * 本処理は別」の構造が、検査の穴ごとに個別の上限を足しては迂回される原因だった
 * （共有参照の指数展開 → byte string の `Buffer.toJSON()` 展開 約 380 倍 → 空 map 多数の
 * 約 360 倍複製）。ここでは **検査と復元を 1 回の走査に統合**し、`cbor-x` と JSON 往復を経由しない。
 *
 * - 値を作る前に、入力長・総ノード数・入れ子深さの 3 つの予算を必ず消費する。コンテナは宣言された要素数を
 *   **確保前に** 総ノード数へ計上するため、宣言だけ巨大な入力は 1 要素も作らずに拒否される。
 * - 生成物は入力長 $\le$ {@link BACKUP_CBOR_LIMITS.maxBytes}・ノード数 $\le$
 *   {@link BACKUP_CBOR_LIMITS.maxNodes} で頭打ち（ノード 1 個あたりの割り当ては定数）。
 * - 受理するのは `WalletBackup` が取り得る JSON 表現可能な値だけ: 整数・有限の浮動小数・text string・
 *   bool / null / undefined・配列・text キーの map。byte string（major 2）・tag（major 6。共有参照 28/29 を含む）・
 *   不定長・非 text キー・不正な UTF-8・NaN / Infinity・末尾の余剰バイトは拒否する（fail-closed）。
 * - map は `Object.create(null)` に直接書き込む（`Object.prototype` を継承しない。`__proto__` も
 *   通常の own データプロパティになる）。重複キーは後勝ち（`JSON.parse` と同じ）。
 */

import { CBOR_MAJOR, readCborHeader } from '../../cbor.js';

/** 復号の仕事量予算。 */
export interface BackupCborLimits {
  /** 入力の最大バイト数。 */
  readonly maxBytes: number;
  /** データ項目の総数（map のキーと値は別々に数える）。 */
  readonly maxNodes: number;
  /** コンテナの最大入れ子深さ。`WalletBackup` は 5 段程度なので 32 段で十分。 */
  readonly maxDepth: number;
}

/** 既定の予算。1M ノードは VC 数 × フィールド数として十分で、確保量は数十〜百数十 MB で頭打ちになる。 */
export const BACKUP_CBOR_LIMITS: BackupCborLimits = {
  maxBytes: 32 * 1024 * 1024,
  maxNodes: 1_000_000,
  maxDepth: 32,
};

/** 拒否理由。 */
export type BackupCborRejectReason =
  | 'input-too-long'
  | 'too-many-nodes'
  | 'too-deep'
  | 'unsupported-type'
  | 'malformed';

/** 予算超過・未対応型・不正な形の拒否。呼び出し側が `4033` へ変換する。 */
export class BackupCborRejection extends Error {
  constructor(readonly reason: BackupCborRejectReason) {
    super(`backup cbor rejected: ${reason}`);
    this.name = 'BackupCborRejection';
  }
}

/** simple value（major type 7）の additional information。 */
const SIMPLE = { false: 20, true: 21, null: 22, undefined: 23 } as const;

const utf8 = new TextDecoder('utf-8', { fatal: true });

/** float16（IEEE 754 binary16）を number へ。 */
function decodeFloat16(high: number, low: number): number {
  const half = (high << 8) | low;
  const sign = half & 0x8000 ? -1 : 1;
  const exponent = (half >> 10) & 0x1f;
  const fraction = half & 0x3ff;
  if (exponent === 0) {
    return sign * fraction * 2 ** -24;
  }
  if (exponent === 31) {
    return fraction === 0 ? sign * Number.POSITIVE_INFINITY : Number.NaN;
  }
  return sign * (fraction + 1024) * 2 ** (exponent - 25);
}

/** 1 回の復号の状態（走査位置と消費済み予算）。 */
class Walker {
  pos = 0;
  nodes = 0;
  private readonly view: DataView;

  constructor(
    private readonly bytes: Uint8Array,
    private readonly limits: BackupCborLimits,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  /** `count` 個のノードを予算へ計上する（値を確保する前に呼ぶ）。 */
  charge(count: number): void {
    this.nodes += count;
    if (this.nodes > this.limits.maxNodes) {
      throw new BackupCborRejection('too-many-nodes');
    }
  }

  /** 残りバイト数（1 ノードは最低 1 バイトなので、宣言要素数の上限になる）。 */
  get remaining(): number {
    return this.bytes.length - this.pos;
  }

  /** 1 データ項目を復号する。`depth` は現在のコンテナ入れ子数。 */
  item(depth: number): unknown {
    const first = this.bytes[this.pos];
    if (first === undefined) {
      throw new BackupCborRejection('malformed');
    }
    if (first >> 5 === CBOR_MAJOR.simple) {
      return this.simple(first);
    }
    const head = readCborHeader(this.bytes, this.pos);
    if (head === undefined) {
      throw new BackupCborRejection('malformed');
    }
    this.pos += head.headerLen;
    switch (head.majorType) {
      case CBOR_MAJOR.unsigned:
        return head.value;
      case CBOR_MAJOR.negative:
        return -1 - head.value;
      case CBOR_MAJOR.textString:
        return this.text(head.value);
      case CBOR_MAJOR.array:
        return this.array(head.value, depth);
      case CBOR_MAJOR.map:
        return this.map(head.value, depth);
      default:
        // byte stringと tag（共有参照 28/29 を含む）。
        throw new BackupCborRejection('unsupported-type');
    }
  }

  private simple(first: number): unknown {
    const info = first & 0x1f;
    const at = this.pos;
    this.pos += 1;
    switch (info) {
      case SIMPLE.false:
        return false;
      case SIMPLE.true:
        return true;
      case SIMPLE.null:
        return null;
      case SIMPLE.undefined:
        return undefined;
      case 25:
      case 26:
      case 27: {
        const width = 2 ** (info - 24);
        if (width > this.bytes.length - this.pos) {
          throw new BackupCborRejection('malformed');
        }
        this.pos += width;
        const value =
          info === 25
            ? decodeFloat16(this.bytes[at + 1] as number, this.bytes[at + 2] as number)
            : info === 26
              ? this.view.getFloat32(at + 1)
              : this.view.getFloat64(at + 1);
        if (!Number.isFinite(value)) {
          throw new BackupCborRejection('unsupported-type');
        }
        // -0 は JSON 往復で 0 になっていたため、同じ値へ正規化する。
        return value === 0 ? 0 : value;
      }
      default:
        throw new BackupCborRejection('unsupported-type');
    }
  }

  private text(length: number): string {
    if (length > this.remaining) {
      throw new BackupCborRejection('malformed');
    }
    try {
      const decoded = utf8.decode(this.bytes.subarray(this.pos, this.pos + length));
      this.pos += length;
      return decoded;
    } catch {
      throw new BackupCborRejection('malformed');
    }
  }

  private enter(declared: number, depth: number): void {
    // 宣言要素数が残りバイトで賄えない入力は、確保も走査もせずに拒否する。
    if (declared > this.remaining) {
      throw new BackupCborRejection('malformed');
    }
    if (depth >= this.limits.maxDepth) {
      throw new BackupCborRejection('too-deep');
    }
    this.charge(declared);
  }

  private array(count: number, depth: number): unknown[] {
    this.enter(count, depth);
    const out: unknown[] = [];
    for (let i = 0; i < count; i += 1) {
      out.push(this.item(depth + 1));
    }
    return out;
  }

  private map(entries: number, depth: number): object {
    this.enter(entries * 2, depth);
    const out = Object.create(null) as Record<string, unknown>;
    for (let i = 0; i < entries; i += 1) {
      const key = this.item(depth + 1);
      if (typeof key !== 'string') {
        throw new BackupCborRejection('unsupported-type');
      }
      const value = this.item(depth + 1);
      // `JSON.stringify` 往復と同じく、undefined の値を持つキーは存在しない扱いにする。
      if (value !== undefined) {
        out[key] = value;
      }
    }
    return out;
  }
}

/**
 * 単一の CBOR データ項目を、予算内でだけ復号する。
 *
 * @param bytes CBOR バイト列（外部入力）。
 * @param limits 仕事量予算。テストで小さな値を差し込めるよう引数にしている。
 * @returns 復元した値（map は `Object.prototype` を継承しない）。
 * @throws {@link BackupCborRejection} 予算超過・未対応の型・不正な形・末尾の余剰バイトがある場合。
 */
export function decodeBoundedCbor(
  bytes: Uint8Array,
  limits: BackupCborLimits = BACKUP_CBOR_LIMITS,
): unknown {
  if (bytes.length > limits.maxBytes) {
    throw new BackupCborRejection('input-too-long');
  }
  const walker = new Walker(bytes, limits);
  walker.charge(1);
  const value = walker.item(0);
  if (walker.pos !== bytes.length) {
    throw new BackupCborRejection('malformed');
  }
  return value;
}
