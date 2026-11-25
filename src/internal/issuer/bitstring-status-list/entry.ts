/**
 * W3C Bitstring Status List の `credentialStatus` エントリ（`BitstringStatusListEntry`）の生成と、
 * リストに対する評価（`checkBitstringStatus`）。
 *
 * W3C §2.1 BitstringStatusListEntry /
 * §3.2 Validate Algorithm（エントリとリストの突合・インデックス範囲・`message` の解決）。
 *
 * エントリは検証対象 VC の `credentialStatus`（外部入力）なので、すべて自身のプロパティに限って読み、
 * 型を確かめる。エントリとリストが食い違う場合（種別・用途・`statusSize`・不正／範囲外のインデックス）は
 * すべて `VC_SCHEMA_INVALID`（3002）で拒否し、取り違えた別エントリのビットが「失効していない」と読まれる
 * ことを防ぐ（fail-closed）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URL・インデックス・ビット値を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { BitstringStatusList, BitstringStatusPurpose } from './list.js';

/** `credentialStatus` エントリの `type`（W3C §2.1）。 */
export const BITSTRING_STATUS_LIST_ENTRY_TYPE = 'BitstringStatusListEntry' as const;

/** `message` 目的の `statusMessage` 1 件（`status` は `0x0` / `0x1` … の 16 進文字列）。 */
export interface BitstringStatusMessage {
  readonly status: string;
  readonly message: string;
}

/** VC の `credentialStatus` に載せる `BitstringStatusListEntry`（W3C §2.1）。 */
export interface BitstringStatusListEntry {
  readonly id?: string;
  readonly type: typeof BITSTRING_STATUS_LIST_ENTRY_TYPE;
  readonly statusPurpose: BitstringStatusPurpose;
  /** 10 進の非負整数文字列（W3C: 文字列）。 */
  readonly statusListIndex: string;
  /** リスト VC の URL（`BitstringStatusListCredential` の `id`）。 */
  readonly statusListCredential: string;
  /** 1 エントリのビット数。1 のとき省略する（W3C の既定）。 */
  readonly statusSize?: number;
  readonly statusMessage?: readonly BitstringStatusMessage[];
}

/** エントリの評価結果。`StatusCheckResult`（`valid` / `purpose` / `value`）と同形に `message` を足したもの。 */
export interface BitstringStatusResult {
  /** 値が 0 か。`revocation` / `suspension` ではそのまま有効性（`assertStatusValid` に渡せる）。 */
  readonly valid: boolean;
  readonly purpose: BitstringStatusPurpose;
  /** 読み取ったエントリ値。 */
  readonly value: number;
  /** `message` 目的で `statusMessage` に一致するものがあれば、そのメッセージ。 */
  readonly message?: string;
}

/** `createBitstringStatusListEntry` のオプション。 */
export interface CreateBitstringStatusListEntryOptions {
  readonly id?: string;
  /** `message` 目的のときだけ指定できる（それ以外は 3002）。 */
  readonly statusMessage?: readonly BitstringStatusMessage[];
}

/**
 * リストの `index` を指す `credentialStatus` エントリを組み立てる（W3C §3.1）。
 *
 * @param list 対象リスト（用途・`statusSize` をエントリへ写す）。
 * @param index 割り当てたインデックス（`0 <= index < list.length`）。
 * @param statusListCredential 当該リスト VC の公開 URL（リスト VC の `id` と一致させる）。
 * @param opts `id` / `statusMessage`。
 * @returns `BitstringStatusListEntry`。
 * @throws `index` が範囲外 / URL が空 / `message` 以外で `statusMessage` を渡した場合（code `3002`）。
 */
export function createBitstringStatusListEntry(
  list: BitstringStatusList,
  index: number,
  statusListCredential: string,
  opts: CreateBitstringStatusListEntryOptions = {},
): BitstringStatusListEntry {
  const statusMessage = ownProperty<readonly BitstringStatusMessage[]>(opts, 'statusMessage');
  const id = ownProperty<string>(opts, 'id');
  if (
    !Number.isInteger(index) ||
    index < 0 ||
    index >= list.length ||
    typeof statusListCredential !== 'string' ||
    statusListCredential === '' ||
    (statusMessage !== undefined && list.purpose !== 'message') ||
    (id !== undefined && typeof id !== 'string')
  ) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return {
    ...(id === undefined ? {} : { id }),
    type: BITSTRING_STATUS_LIST_ENTRY_TYPE,
    statusPurpose: list.purpose,
    statusListIndex: String(index),
    statusListCredential,
    ...(list.statusSize === 1 ? {} : { statusSize: list.statusSize }),
    ...(statusMessage === undefined ? {} : { statusMessage }),
  };
}

/** `statusListIndex`（10 進の非負整数文字列）を数値にする。 */
function parseIndex(value: unknown): number {
  if (typeof value !== 'string' || !/^[0-9]+$/.test(value)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const index = Number(value);
  if (!Number.isSafeInteger(index)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return index;
}

/** `statusMessage`（任意）を型検証して返す。配列でない・要素が `{status, message}` 文字列対でなければ 3002。 */
function parseStatusMessages(value: unknown): readonly BitstringStatusMessage[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return value.map((item: unknown) => {
    const status = typeof item === 'object' && item !== null ? ownProperty(item, 'status') : null;
    const message = typeof item === 'object' && item !== null ? ownProperty(item, 'message') : null;
    if (typeof status !== 'string' || typeof message !== 'string') {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    return { status, message };
  });
}

/**
 * 検証済みのリストからエントリの値を読む（W3C §3.2 の「status の取得」）。
 *
 * エントリの `type` / `statusPurpose` / `statusSize` がリストと食い違えばすべて 3002 で拒否する
 * （`statusSize` を省略したエントリは 1 ビットのリストにのみ対応する）。`message` 目的では、読んだ値の
 * 16 進表記（`0x2` など）に一致する `statusMessage` のメッセージを返す（一致が複数なら最後のもの。
 * Go 実装と同じ。メッセージの意味づけはアプリ定義で、SDK は解決だけを行う）。
 *
 * @param entry VC の `credentialStatus`（外部入力。`unknown`）。
 * @param list 検証済みのリスト。
 * @returns 読み取った値・用途・（`message` 目的の）メッセージ。
 * @throws エントリがリストと整合しない / インデックスが不正・範囲外の場合（code `3002`）。
 */
export function checkBitstringStatus(
  entry: unknown,
  list: BitstringStatusList,
): BitstringStatusResult {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const statusSize = ownProperty<unknown>(entry, 'statusSize');
  if (
    ownProperty<unknown>(entry, 'type') !== BITSTRING_STATUS_LIST_ENTRY_TYPE ||
    ownProperty<unknown>(entry, 'statusPurpose') !== list.purpose ||
    (statusSize === undefined ? list.statusSize !== 1 : statusSize !== list.statusSize)
  ) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const index = parseIndex(ownProperty<unknown>(entry, 'statusListIndex'));
  const messages = parseStatusMessages(ownProperty<unknown>(entry, 'statusMessage'));
  const value = list.get(index);
  const message =
    list.purpose === 'message'
      ? messages.findLast((m) => m.status === `0x${value.toString(16)}`)?.message
      : undefined;
  return {
    valid: value === 0,
    purpose: list.purpose,
    value,
    ...(message === undefined ? {} : { message }),
  };
}
