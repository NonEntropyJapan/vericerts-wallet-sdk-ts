/**
 * SD-JWT の Disclosure を payload へ再帰的に適用して平文クレームを復元する（RFC 9901 §7.1）。
 *
 * - オブジェクトの `_sd`（文字列配列。文字列でない要素・配列でない `_sd` は digest として扱わず無視する。
 *   §7.1 3.b.i）→ オブジェクトプロパティ Disclosure（3 要素）を
 *   そのオブジェクトへ追加する（§4.2.1）。
 * - 配列要素 `{ "...": digest }`（キーがちょうど `...` の 1 つで値が文字列）→ 配列要素 Disclosure（2 要素）の値で
 *   置き換える（§4.2.2）。
 * - 復元した値の中にも `_sd` / `{ "...": digest }` があり得るので任意の深さで繰り返す（§4.2.6）。
 *
 * 以下はいずれも 3010（`SIG_INVALID`）で拒否する。例外に salt・開示値は載せない:
 * - 同一 digest の Disclosure が複数ある / payload・開示値に同じ digest が 2 回以上現れる。
 * - どこからも参照されない Disclosure（改竄・捏造、親 Disclosure を欠いた入れ子を含む）。
 * - `_sd` に配列要素 Disclosure、配列の `...` にオブジェクトプロパティ Disclosure を指された。
 * - 最上位で `NON_DISCLOSABLE_CLAIMS` のクレームを Disclosure 化した（評価回避の防止）。
 * - 既存の平文クレームや他の Disclosure と同名のクレーム（署名済みクレームの隠蔽防止）。
 * - 入れ子が `MAX_JSON_NESTING_DEPTH` を超える（Disclosure の連鎖で再帰を枯渇させる入力の防止）。
 *
 * `payload` / 開示値は `parseJsonWithoutPrototype` を通って届く `null` プロトタイプの素データで、
 * 戻り値も `Object.create(null)` で組む（`claims.ts` の `recoverClaims` 注記を参照）。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { defineDataProperty } from '../../prototype-safety/define-data-property.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { MAX_JSON_NESTING_DEPTH } from '../../prototype-safety/parse-json.js';
import { isPlainObject } from '../object-guards.js';
import type { Disclosure } from './disclosure.js';
import { NON_DISCLOSABLE_CLAIMS } from './non-disclosable-claims.js';

/** 配列要素の Disclosure 参照を表す予約キー。 */
const ARRAY_ELEMENT_KEY = '...';

function reject(): never {
  throw new VericertsError(ErrorCodes.SIG_INVALID);
}

/**
 * 復元先オブジェクトへクレームを**自身のデータプロパティとして**設定する。
 *
 * `target[name] = value` は `name` が `__proto__` のとき own プロパティを作らずプロトタイプを
 * 差し替える（クレームが消え、返した集合が攻撃者の選んだオブジェクトを継承する）。
 * `defineDataProperty` は記述子を `null` プロトタイプで組むので `__proto__` でも通常の own データ
 * プロパティになり、`Object.prototype.get` 汚染下でも落ちない。
 */
function defineClaim(target: Record<string, unknown>, name: string, value: unknown): void {
  defineDataProperty(target, name, value);
}

/** 配列要素が `{ "...": digest }`（キーがちょうど `...` の 1 つで値が文字列）なら digest を返す。 */
function arrayElementDigest(element: unknown): string | undefined {
  if (!isPlainObject(element) || Object.keys(element).length !== 1) {
    return undefined;
  }
  const digest = ownProperty<unknown>(element, ARRAY_ELEMENT_KEY);
  return typeof digest === 'string' ? digest : undefined;
}

class DisclosureResolver {
  readonly #byDigest = new Map<string, Disclosure>();
  /** payload・開示値に現れた digest（重複参照の検出用）。 */
  readonly #referenced = new Set<string>();
  /** 参照されて消費された Disclosure の digest。 */
  readonly #used = new Set<string>();

  constructor(private readonly disclosures: readonly Disclosure[]) {
    for (const disclosure of disclosures) {
      if (this.#byDigest.has(disclosure.digest)) {
        reject();
      }
      this.#byDigest.set(disclosure.digest, disclosure);
    }
  }

  /** payload 全体を復元し、全 Disclosure が消費されたことを確認する。 */
  resolve(payload: Record<string, unknown>): Record<string, unknown> {
    const claims = this.#object(payload, 1, true);
    for (const disclosure of this.disclosures) {
      if (!this.#used.has(disclosure.digest)) {
        reject();
      }
    }
    return claims;
  }

  /** digest を参照済みにして対応する Disclosure（decoy なら `undefined`）を返す。 */
  #take(digest: string): Disclosure | undefined {
    if (this.#referenced.has(digest)) {
      reject();
    }
    this.#referenced.add(digest);
    const disclosure = this.#byDigest.get(digest);
    if (disclosure !== undefined) {
      this.#used.add(digest);
    }
    return disclosure;
  }

  /**
   * 値を復元する。深さはコンテナ（配列・オブジェクト）へ入るときだけ数える。パーサ
   * （`parse-json.ts` の `stripPrototypes`）も同じ数え方なので、パーサが受理する入力は
   * 末端がプリミティブでも拒否しない。
   */
  #value(value: unknown, depth: number): unknown {
    if (Array.isArray(value)) {
      this.#assertDepth(depth);
      return this.#array(value, depth);
    }
    if (isPlainObject(value)) {
      this.#assertDepth(depth);
      return this.#object(value, depth, false);
    }
    return value;
  }

  #assertDepth(depth: number): void {
    if (depth > MAX_JSON_NESTING_DEPTH) {
      reject();
    }
  }

  #array(source: readonly unknown[], depth: number): unknown[] {
    const result: unknown[] = [];
    for (const element of source) {
      const digest = arrayElementDigest(element);
      if (digest !== undefined) {
        const disclosure = this.#take(digest);
        if (disclosure === undefined) {
          continue; // 未開示（または decoy）の要素は取り除く。
        }
        if (disclosure.claimName !== undefined) {
          reject(); // 配列要素にオブジェクトプロパティ Disclosure は使えない。
        }
        result.push(this.#value(disclosure.value, depth + 1));
      } else {
        result.push(this.#value(element, depth + 1));
      }
    }
    return result;
  }

  #object(
    source: Record<string, unknown>,
    depth: number,
    topLevel: boolean,
  ): Record<string, unknown> {
    const result = Object.create(null) as Record<string, unknown>;
    for (const [key, value] of Object.entries(source)) {
      if (key === '_sd' || (topLevel && key === '_sd_alg')) {
        continue;
      }
      // 最上位の登録済みクレーム（`cnf` / `status` 等）は検証側が payload 本体から読むので、
      // 中身に Disclosure は適用せず署名済みの値のまま残す。
      defineClaim(
        result,
        key,
        topLevel && NON_DISCLOSABLE_CLAIMS.has(key) ? value : this.#value(value, depth + 1),
      );
    }
    const sd = ownProperty<unknown>(source, '_sd');
    if (sd === undefined) {
      return result;
    }
    if (!Array.isArray(sd)) {
      return result;
    }
    for (const digest of sd) {
      if (typeof digest !== 'string') {
        continue;
      }
      const disclosure = this.#take(digest);
      if (disclosure === undefined) {
        continue; // decoy digest、または Holder が提示から外した Disclosure。
      }
      const name = disclosure.claimName;
      if (
        name === undefined ||
        Object.hasOwn(result, name) ||
        (topLevel && NON_DISCLOSABLE_CLAIMS.has(name))
      ) {
        reject();
      }
      defineClaim(result, name, this.#value(disclosure.value, depth + 1));
    }
    return result;
  }
}

/**
 * `payload`（Issuer-signed JWT の payload）へ `disclosures` を再帰的に適用した平文クレームを返す。
 *
 * 最上位の `_sd` / `_sd_alg` は結果から除く。`_sd_alg` の検査は呼び出し側（`recoverClaims`）が行う。
 *
 * @throws 上記のいずれかに該当する場合（VericertsError、code `3010`）。
 */
export function applyDisclosures(
  payload: Record<string, unknown>,
  disclosures: readonly Disclosure[],
): Record<string, unknown> {
  return new DisclosureResolver(disclosures).resolve(payload);
}
