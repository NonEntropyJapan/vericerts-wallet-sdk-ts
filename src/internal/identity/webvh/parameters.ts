/**
 * did:webvh v1.0 の `parameters` の検証と、版ごとの有効なパラメータへの適用。
 *
 * spec: DIF didwebvh v1.0「`did:webvh` DID Method Parameters」。
 * - 許す名前は `method` / `scid` / `updateKeys` / `nextKeyHashes` / `witness` / `watchers` / `portable` / `deactivated` / `ttl`
 *   のみ（未知の名前は拒否）。型・値域に合わない値は拒否する。
 * - 省略は「前の値を維持」。初版で省略したものは既定値（`nextKeyHashes` `[]`・`witness` `{}`・`watchers` `[]`・
 *   `portable` `false`・`deactivated` `false`・`ttl` `3600`）。
 * - `null` は使ってはならないが、古いログの `null` は SHOULD で既定値に読み替える（spec: General Rules for Parameters の note）。
 * - `method` は初版で必須かつ `did:webvh:1.0` と**完全に**一致すること。他の値（`did:webvh:0.4`・`did:webvh:1.0-rc1` を含む）は
 *   既定値に落とさず拒否する。後続の版で変える場合も同様（下位版への変更の拒否は、受理する版が 1 つなので同じ規則に含まれる）。
 * - `scid` は初版だけ。`portable: true` は初版だけ。
 * - 失効は `parameters.deactivated`（`state.deactivated` ではない）。
 *
 * 例外メッセージ・`context` に DID 文字列・鍵・URL を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import {
  MAX_KEYS_PER_ENTRY,
  MAX_WATCHER_URL_CHARS,
  MAX_WATCHERS_PER_ENTRY,
  rejectDidLogOversized,
} from './limits.js';
import { isSha256MultihashBase58 } from './multihash.js';
import { parseWitnessParameter, type WebVhWitnessConfig } from './witness/config.js';

/** 受理する `parameters.method`（did:webvh 仕様 v1.0）。 */
export const DID_WEBVH_METHOD = 'did:webvh:1.0';

/** `ttl` の既定値（秒）。 */
export const DEFAULT_TTL = 3600;

/** `ttl` の上限（秒、2^31）。 */
export const MAX_TTL = 2 ** 31;

/** 仕様が定義する `parameters` の名前。 */
const KNOWN_PARAMETERS: ReadonlySet<string> = new Set([
  'method',
  'scid',
  'updateKeys',
  'nextKeyHashes',
  'witness',
  'watchers',
  'portable',
  'deactivated',
  'ttl',
]);

/** 1 つの版を処理した後に有効なパラメータ（次の版の検証と解決メタデータの元）。 */
export interface ActiveParameters {
  readonly scid: string;
  readonly updateKeys: readonly string[];
  readonly nextKeyHashes: readonly string[];
  readonly witness: WebVhWitnessConfig | undefined;
  readonly watchers: readonly string[];
  readonly portable: boolean;
  readonly deactivated: boolean;
  readonly ttl: number;
}

/** 1 エントリが宣言したパラメータ（省略は `undefined`、`null` は既定値へ読み替え済み）。 */
export interface ParameterDelta {
  readonly scid?: string;
  readonly updateKeys?: readonly string[];
  readonly nextKeyHashes?: readonly string[];
  /** `null`: witness なし（`{}`）を明示。 */
  readonly witness?: WebVhWitnessConfig | null;
  readonly watchers?: readonly string[];
  readonly portable?: boolean;
  readonly deactivated?: boolean;
  readonly ttl?: number;
}

function invalid(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID);
}

/** 文字列だけの重複しない配列（件数は走査前に上限で縛る）。 */
function stringList(value: unknown, max: number): string[] {
  if (!Array.isArray(value)) {
    throw invalid();
  }
  rejectDidLogOversized(value.length, max);
  const list: unknown[] = [...value];
  if (list.some((item) => typeof item !== 'string') || new Set(list).size !== list.length) {
    throw invalid();
  }
  return list as string[];
}

/**
 * `parameters.watchers` を検証する。各要素は http(s) の絶対 URL で、重複しない。`[]` は解除。
 *
 * @throws 配列でない・件数 / 長さ超過・URL でない・重複する場合（VericertsError、code `2001`）。
 */
export function parseWatchers(value: unknown): string[] {
  const urls = stringList(value, MAX_WATCHERS_PER_ENTRY);
  for (const url of urls) {
    rejectDidLogOversized(url.length, MAX_WATCHER_URL_CHARS);
    try {
      const { protocol } = new URL(url);
      if (protocol !== 'https:' && protocol !== 'http:') {
        throw invalid();
      }
    } catch {
      throw invalid();
    }
  }
  return urls;
}

/** `ttl`: 0〜2^31 の整数（秒）。 */
export function parseTtl(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > MAX_TTL) {
    throw invalid();
  }
  return value;
}

function parseBoolean(value: unknown): boolean {
  if (typeof value !== 'boolean') {
    throw invalid();
  }
  return value;
}

/**
 * 1 エントリの `parameters` を検証し、宣言された値を取り出す。
 *
 * @param raw エントリの `parameters`。
 * @param isFirst 初版か。
 * @throws 未知の名前・型 / 値域の違反・`method` の不一致・初版での必須項目の欠落・後続の版での `scid` /
 *   `portable: true`（VericertsError、code `2001`）。
 */
export function readParameterDelta(raw: unknown, isFirst: boolean): ParameterDelta {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw invalid();
  }
  if (Object.keys(raw).some((name) => !KNOWN_PARAMETERS.has(name))) {
    throw invalid();
  }
  const method = ownProperty<unknown>(raw, 'method');
  if (method !== undefined ? method !== DID_WEBVH_METHOD : isFirst) {
    throw invalid();
  }
  const scid = ownProperty<unknown>(raw, 'scid');
  if (isFirst ? !isSha256MultihashBase58(scid) : scid !== undefined) {
    throw invalid();
  }
  const updateKeys = ownProperty<unknown>(raw, 'updateKeys');
  if (isFirst && (updateKeys === undefined || updateKeys === null)) {
    throw invalid();
  }
  const nextKeyHashes = ownProperty<unknown>(raw, 'nextKeyHashes');
  const witness = ownProperty<unknown>(raw, 'witness');
  const watchers = ownProperty<unknown>(raw, 'watchers');
  const portable = ownProperty<unknown>(raw, 'portable');
  const deactivated = ownProperty<unknown>(raw, 'deactivated');
  const ttl = ownProperty<unknown>(raw, 'ttl');
  const portableValue =
    portable === undefined || portable === null ? undefined : parseBoolean(portable);
  if (!isFirst && portableValue === true) {
    throw invalid();
  }
  // 全メンバを own プロパティとして返す（`undefined` も明示）。省略したメンバが `Object.prototype` の汚染値を拾わない。
  return {
    scid: typeof scid === 'string' ? scid : undefined,
    updateKeys:
      updateKeys === undefined
        ? undefined
        : updateKeys === null
          ? []
          : stringList(updateKeys, MAX_KEYS_PER_ENTRY),
    nextKeyHashes:
      nextKeyHashes === undefined
        ? undefined
        : nextKeyHashes === null
          ? []
          : stringList(nextKeyHashes, MAX_KEYS_PER_ENTRY),
    witness: witness === undefined ? undefined : witness === null ? null : parseWitness(witness),
    watchers: watchers === undefined ? undefined : watchers === null ? [] : parseWatchers(watchers),
    portable: portable === undefined ? undefined : (portableValue ?? false),
    deactivated:
      deactivated === undefined
        ? undefined
        : deactivated === null
          ? false
          : parseBoolean(deactivated),
    ttl: ttl === undefined ? undefined : ttl === null ? DEFAULT_TTL : parseTtl(ttl),
  };
}

/** `witness`: `{}` は `null`（witness なしの明示）、それ以外は検証済みの構成。 */
function parseWitness(value: unknown): WebVhWitnessConfig | null {
  return parseWitnessParameter(value) ?? null;
}

/**
 * 宣言されたパラメータを、直前の有効なパラメータへ適用する（省略は維持、初版は既定値）。
 *
 * 事前コミット（pre-rotation）が有効な間（直前の `nextKeyHashes` が非空）は、`updateKeys` と `nextKeyHashes` を
 * **両方とも明示**しなければならず、`updateKeys` は空にできない（継承による回避を許さない。spec: `nextKeyHashes`）。
 *
 * @param previous 直前の版を処理した後のパラメータ。初版は `undefined`。
 * @param delta この版が宣言したパラメータ。
 * @throws 直前の版が失効している・事前コミット中の省略 / 空の `updateKeys`（VericertsError、code `2001`）。
 */
export function applyParameters(
  previous: ActiveParameters | undefined,
  delta: ParameterDelta,
): ActiveParameters {
  if (previous === undefined) {
    return {
      scid: delta.scid as string,
      updateKeys: delta.updateKeys as readonly string[],
      nextKeyHashes: delta.nextKeyHashes ?? [],
      witness: delta.witness ?? undefined,
      watchers: delta.watchers ?? [],
      portable: delta.portable ?? false,
      deactivated: delta.deactivated ?? false,
      ttl: delta.ttl ?? DEFAULT_TTL,
    };
  }
  if (previous.deactivated) {
    throw invalid();
  }
  if (previous.nextKeyHashes.length > 0) {
    if (
      delta.updateKeys === undefined ||
      delta.updateKeys.length === 0 ||
      delta.nextKeyHashes === undefined
    ) {
      throw invalid();
    }
  }
  return {
    scid: previous.scid,
    updateKeys: delta.updateKeys ?? previous.updateKeys,
    nextKeyHashes: delta.nextKeyHashes ?? previous.nextKeyHashes,
    witness: delta.witness === undefined ? previous.witness : (delta.witness ?? undefined),
    watchers: delta.watchers ?? previous.watchers,
    // `portable: true` は初版だけ（`readParameterDelta` が拒否）。後続の `false` は恒久的に移動を禁じる。
    portable: previous.portable && delta.portable !== false,
    deactivated: delta.deactivated ?? false,
    ttl: delta.ttl ?? previous.ttl,
  };
}

/**
 * ログ（検証済みでなくてよい）を畳んで、最後の版を処理した後に有効なパラメータを返す。署名・ハッシュは検証しない。
 * 生成側（`updateDidWebVh`）が、次版の `parameters` を検証側と同じ規則で検査するために使う。
 *
 * @param entries 1 件以上の Log エントリ（行順）。
 * @throws `parameters` が不正・失効後に版が続く場合（VericertsError、code `2001`）。
 */
export function activeParametersOf(
  entries: readonly { readonly parameters: unknown }[],
): ActiveParameters {
  let active: ActiveParameters | undefined;
  for (const [index, entry] of entries.entries()) {
    active = applyParameters(active, readParameterDelta(entry.parameters, index === 0));
  }
  if (active === undefined) {
    throw invalid();
  }
  return active;
}
