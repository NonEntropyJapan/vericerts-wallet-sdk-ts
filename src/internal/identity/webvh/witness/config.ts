/**
 * `parameters.witness` の検証と、witness の `did:key` 識別子の扱い。
 *
 * spec: DIF didwebvh v1.0「The `witness` Parameter」「Witness DIDs and Reputation」。
 * - `witness` は `{}`（witness なし）か `{ threshold, witnesses: [{ id }] }`。`weight` は無い（v1.0）。
 * - `witnesses` は非空で、各 `id` は `did:key`（Ed25519）かつ重複しない（NFC 正規化後のバイト列比較）。
 * - `threshold` は 1 以上 `witnesses` の件数以下の整数。不正な値を「witness なし」に読み替えない（拒否する）。
 * - 不正な witness 構成は署名検証の時点ではなく、パラメータの検証の時点で拒否する。
 *
 * 例外メッセージ・`context` に witness の識別子を含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { MAX_WITNESSES_PER_ENTRY, rejectDidLogOversized } from '../limits.js';
import { ed25519PublicKeyFromMultikey } from '../proof.js';

/** 検証済みの witness 構成。`witnesses` は `did:key` 識別子（`did:key:z6Mk...`）。 */
export interface WebVhWitnessConfig {
  readonly threshold: number;
  readonly witnesses: readonly string[];
}

/** witness 識別子の接頭辞。 */
const DID_KEY_PREFIX = 'did:key:';

function invalid(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID);
}

/**
 * `did:key:<multikey>`（Ed25519）から Multikey を取り出す。
 *
 * @throws `did:key:` 形式でない・フラグメントを含む・Ed25519 Multikey でない場合（VericertsError、code `2001`）。
 */
export function multikeyOfDidKey(didKey: string): string {
  if (!didKey.startsWith(DID_KEY_PREFIX)) {
    throw invalid();
  }
  const multikey = didKey.slice(DID_KEY_PREFIX.length);
  ed25519PublicKeyFromMultikey(multikey);
  return multikey;
}

/**
 * `parameters.witness` を検証して構成にする。`{}` は witness なし（`undefined`）。
 *
 * @param value `parameters.witness`（JSON 値）。
 * @returns witness 構成。witness なしなら `undefined`。
 * @throws 形式不正・未知のメンバ・`witnesses` が空・件数超過・`did:key` でない/重複する `id`・`threshold` が範囲外の場合
 *   （VericertsError、code `2001`）。
 */
export function parseWitnessParameter(value: unknown): WebVhWitnessConfig | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalid();
  }
  const keys = Object.keys(value);
  if (keys.length === 0) {
    return undefined;
  }
  if (keys.some((key) => key !== 'threshold' && key !== 'witnesses')) {
    throw invalid();
  }
  const threshold = ownProperty<unknown>(value, 'threshold');
  const list = ownProperty<unknown>(value, 'witnesses');
  if (!Array.isArray(list) || list.length === 0) {
    throw invalid();
  }
  rejectDidLogOversized(list.length, MAX_WITNESSES_PER_ENTRY);
  const ids = new Set<string>();
  for (const item of list as unknown[]) {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      throw invalid();
    }
    if (Object.keys(item).some((key) => key !== 'id')) {
      throw invalid();
    }
    const id = ownProperty<unknown>(item, 'id');
    if (typeof id !== 'string') {
      throw invalid();
    }
    multikeyOfDidKey(id);
    const normalized = id.normalize('NFC');
    if (ids.has(normalized)) {
      throw invalid();
    }
    ids.add(normalized);
  }
  if (
    typeof threshold !== 'number' ||
    !Number.isInteger(threshold) ||
    threshold < 1 ||
    threshold > ids.size
  ) {
    throw invalid();
  }
  return { threshold, witnesses: [...ids] };
}

/** 検証済み構成を、ログへ書く JSON（`{ threshold, witnesses: [{ id }] }`）にする。 */
export function witnessParameterOf(config: WebVhWitnessConfig | undefined): {
  threshold?: number;
  witnesses?: { id: string }[];
} {
  return config === undefined
    ? {}
    : { threshold: config.threshold, witnesses: config.witnesses.map((id) => ({ id })) };
}
