/**
 * seen-nonces cache の高負荷時プリフィルタ。
 *
 * `store.ts` の `checkAndUse` / `put` / `has` は毎回 `adapter.get()` を発行する。Redis / SQLite /
 * IndexedDB のようなアダプタではこれがネットワーク・I/O 往復になり、高負荷時は「大半を占める
 * 初見の nonce」判定のためだけに往復が発生してボトルネックになる。本フィルタは「絶対に追加されて
 * いない」を偽陰性ゼロで判定できる probabilistic set として働き、`mightContain` が `false` を
 * 返した場合に限り呼び出し側が `adapter.get` を安全に省略できる（＝前段プリフィルタ）。`true`
 * （"maybe"）の場合は通常どおり `adapter.get` で確定判定する。
 *
 * **偽陰性は許されない**（見た nonce を「見ていない」と誤判定すると replay 検知が抜ける）。
 * 一方で偽陽性は安全側（無駄な `adapter.get` が発生するだけで判定は正しく行われる）。この非対称性
 * のため要素は追加のみで、削除は行わない（削除に対応する counting bloom filter は本用途では不要）。
 *
 * 単一の固定容量フィルタだと、想定件数（`capacity`）を超えて追加し続けた場合に偽陽性率が既定値
 * （0.1%）から際限なく劣化し、プリフィルタとしての効果が失われる。これを避けるため
 * Almeida et al. の Scalable Bloom Filter に倣い、現行レイヤーが容量に達したら新しい
 * （より大きな容量・より厳しい目標誤り率の）レイヤーを追加する。`mightContain` は全レイヤーの
 * OR で判定するため、レイヤーが増えても偽陰性は発生しない。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import type { BloomFilterOptions } from './types.js';

/** 既定の目標偽陽性率（0.1%）。 */
export const DEFAULT_BLOOM_FALSE_POSITIVE_RATE = 0.001;

/** レイヤー拡張時の容量倍率（Scalable Bloom Filter の growth factor `s`）。 */
const GROWTH_FACTOR = 2;

/** レイヤー拡張時の目標誤り率の締め付け比率（同 tightening ratio `r`）。層を重ねても合成後の誤り率が収束するよう狭める。 */
const TIGHTENING_RATIO = 0.9;

/** 最適なビット配列長 `m = ceil(-n・ln(p) / ln(2)^2)`（標準的な bloom filter のサイジング式）。 */
function optimalBitCount(capacity: number, falsePositiveRate: number): number {
  const bitCount = Math.ceil((-capacity * Math.log(falsePositiveRate)) / Math.log(2) ** 2);
  return Math.max(8, bitCount);
}

/** 最適なハッシュ関数数 `k = round((m/n)・ln(2))`。 */
function optimalHashCount(bitCount: number, capacity: number): number {
  const hashCount = Math.round((bitCount / capacity) * Math.log(2));
  return Math.max(1, Math.min(hashCount, 32));
}

/** FNV-1a（32bit）。ビット分散のみが目的で暗号学的性質は要求しない。 */
function fnv1a(key: string, seed: number): number {
  let hash = seed >>> 0;
  for (let i = 0; i < key.length; i += 1) {
    hash ^= key.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

/**
 * Kirsch–Mitzenmacher の二重ハッシュで独立した 2 つの 32bit ハッシュを合成する。
 * `k` 個のハッシュ関数を個別に持つ代わりに `g_i(x) = h1(x) + i・h2(x)` で近似する標準的な手法で、
 * 実測の衝突特性は個別ハッシュ `k` 個と同等であることが知られている。
 */
function doubleHash(key: string): readonly [h1: number, h2: number] {
  const h1 = fnv1a(key, 0x811c9dc5);
  const h2 = fnv1a(key, 0x9e3779b9);
  // h2 = 0 だと全ハッシュが h1 に縮退し衝突が増える。0 は極めて稀だが 1 に丸めて回避する。
  return [h1, h2 === 0 ? 1 : h2];
}

/**
 * ビット index からバイト位置とバイト内ビット位置を求める。
 *
 * **`>>` / `&` のビット演算で求めてはならない。** 両者は被演算子を int32 へ丸めるため、単一レイヤーの
 * `capacity` が拡張を重ねて非常に大きくなり `bitCount`（ひいては index）が `2^31` を超えると、
 * `index >> 3` が符号反転して負のバイト位置になる。`Uint8Array` は負の index への代入を
 * サイレントに無視するため `#setBit` が no-op になり、`#getBit` は常に `false` を返す。結果として
 * `mightContain` が既知の nonce を「未知」と誤判定し、replay 検知の前段フィルタが偽陰性を返す
 * （ファイル冒頭の不変条件に違反する）。符号付き 32 ビット整数への変換を避けるため、
 * バイト位置とビット位置を `Math.floor` と `%` で求める。
 */
export function bitPosition(index: number): readonly [byteIndex: number, bitOffset: number] {
  return [Math.floor(index / 8), index % 8];
}

/** 固定容量の 1 レイヤー。ビット配列は追加のみで削除しない。 */
class BloomFilterLayer {
  readonly capacity: number;
  readonly falsePositiveRate: number;
  /** 追加済み件数。`BloomFilter` が容量到達を直接判定するために公開する（クラス外からは変更しない）。 */
  count = 0;
  readonly #bits: Uint8Array;
  readonly #bitCount: number;
  readonly #hashCount: number;

  constructor(capacity: number, falsePositiveRate: number) {
    this.capacity = capacity;
    this.falsePositiveRate = falsePositiveRate;
    this.#bitCount = optimalBitCount(capacity, falsePositiveRate);
    this.#bits = new Uint8Array(Math.ceil(this.#bitCount / 8));
    this.#hashCount = optimalHashCount(this.#bitCount, capacity);
  }

  add(key: string): void {
    const [h1, h2] = doubleHash(key);
    for (let i = 0; i < this.#hashCount; i += 1) {
      this.#setBit((h1 + i * h2) % this.#bitCount);
    }
    this.count += 1;
  }

  mightContain(key: string): boolean {
    const [h1, h2] = doubleHash(key);
    for (let i = 0; i < this.#hashCount; i += 1) {
      if (!this.#getBit((h1 + i * h2) % this.#bitCount)) {
        return false;
      }
    }
    return true;
  }

  #setBit(index: number): void {
    const [byteIndex, bitOffset] = bitPosition(index);
    const current = this.#bits[byteIndex] ?? 0;
    this.#bits[byteIndex] = current | (1 << bitOffset);
  }

  #getBit(index: number): boolean {
    const [byteIndex, bitOffset] = bitPosition(index);
    const current = this.#bits[byteIndex] ?? 0;
    return (current & (1 << bitOffset)) !== 0;
  }
}

/**
 * `NonceStoreOptions.bloomFilter` から生成する、追加専用の probabilistic set。
 * 詳細な設計意図はファイル冒頭のコメントを参照。
 */
export class BloomFilter {
  #current: BloomFilterLayer;
  readonly #previousLayers: BloomFilterLayer[] = [];

  /**
   * @param options 初期容量・目標偽陽性率。省略時は容量 10000 / 偽陽性率 0.1%。
   * @throws `RangeError` `falsePositiveRate` が `(0, 1)` の範囲外の場合。
   */
  constructor(options: BloomFilterOptions = {}) {
    const capacity = Math.max(1, Math.floor(ownProperty<number>(options, 'capacity') ?? 10_000));
    const falsePositiveRate =
      ownProperty<number>(options, 'falsePositiveRate') ?? DEFAULT_BLOOM_FALSE_POSITIVE_RATE;
    if (!(falsePositiveRate > 0 && falsePositiveRate < 1)) {
      throw new RangeError(
        `falsePositiveRate は 0 より大きく 1 未満でなければなりません（受け取った値: ${falsePositiveRate}）`,
      );
    }
    this.#current = new BloomFilterLayer(capacity, falsePositiveRate);
  }

  /** キーを追加する。追加のみで削除はできない（削除に対応しない理由はファイル冒頭を参照）。 */
  add(key: string): void {
    if (this.#current.count >= this.#current.capacity) {
      this.#previousLayers.push(this.#current);
      this.#current = new BloomFilterLayer(
        this.#current.capacity * GROWTH_FACTOR,
        this.#current.falsePositiveRate * TIGHTENING_RATIO,
      );
    }
    this.#current.add(key);
  }

  /**
   * キーが追加されたことが「あり得るか」を返す。
   *
   * `false` は「絶対に追加されていない」（偽陰性ゼロ）。`true` は「追加された可能性がある」
   * （偽陽性を含みうる）。呼び出し側は `false` の場合に限り、本体ストアへの問い合わせを省略してよい。
   */
  mightContain(key: string): boolean {
    if (this.#current.mightContain(key)) {
      return true;
    }
    return this.#previousLayers.some((layer) => layer.mightContain(key));
  }
}
