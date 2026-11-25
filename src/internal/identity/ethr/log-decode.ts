/**
 * did:ethr の ERC-1056 `eth_getLogs` 応答ログの検証と ABI デコード。
 *
 * 応答は信頼境界の外（RPC ノード）にあるため、デコードの前に `removed` / `address` / `topics` を検査する。
 * ネットワーク接続は持たない（ethers の `Interface` による純粋なデコードのみ）。
 *
 * セキュリティ上の注意: RPC の詳細・ログ本文・DID を VericertsError の message / context に伝播させない。
 */

import { Interface } from 'ethers';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { AttributeChangeEvent, OwnerChangeEvent } from './events.js';

/** 取得・デコード失敗（RPC の詳細・本文は伝播しない）。 */
export function notFound(): VericertsError {
  return new VericertsError(ErrorCodes.DID_NOT_FOUND);
}

/**
 * ERC-1056 EthereumDIDRegistry の ABI フラグメント（イベントのみ）。
 *
 * DIDOwnerChanged と DIDAttributeChanged のログを復号するための定義。
 */
const ERC1056_EVENT_ABI = [
  'event DIDOwnerChanged(address indexed identity, address owner, uint previousChange)',
  'event DIDAttributeChanged(address indexed identity, bytes32 name, bytes value, uint validTo, uint previousChange)',
] as const;

/** ABI デコード用の `Interface`（ネットワーク接続は持たない）。 */
export const ERC1056_INTERFACE = new Interface(ERC1056_EVENT_ABI);

export type ErcEventName = 'DIDOwnerChanged' | 'DIDAttributeChanged';

/** `eth_getLogs` が返すログ 1 件のうち、本モジュールが読むフィールド。 */
export interface RawLog {
  readonly address?: unknown;
  readonly removed?: unknown;
  readonly topics: readonly string[];
  readonly data: string;
  readonly blockNumber: string;
  readonly logIndex: string;
}

/** `0x` 付き hex の整数フィールド（blockNumber / logIndex）を数値にする。不正は取得失敗。 */
function hexInt(value: unknown): number {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{1,13}$/.test(value)) {
    throw notFound();
  }
  return Number.parseInt(value, 16);
}

/** 問い合わせた registry・identity（応答ログがこれと一致しなければノードの不整合）。 */
export interface ExpectedLog {
  readonly registry: string;
  readonly identityTopic: string;
}

/**
 * 生ログを検証して ABI デコードする。期待イベント以外・デコード不能・registry / identity の不一致は
 * 取得失敗（RPC の不整合。黙って捨てると「owner 不変」に読めて旧 owner の文書を返すため fail-closed）。
 * reorg で外れたログ（`removed: true`）は本文を読まずに null（無視）とする。
 */
function decodeLog(log: unknown, eventName: ErcEventName, expected: ExpectedLog) {
  if (typeof log !== 'object' || log === null) {
    throw notFound();
  }
  const { address, removed, topics, data, blockNumber, logIndex } = log as RawLog;
  if (removed === true) {
    return null;
  }
  if (removed !== undefined && removed !== false) {
    throw notFound();
  }
  if (!Array.isArray(topics) || typeof data !== 'string') {
    throw notFound();
  }
  // topics は [event signature, indexed identity] の 2 件ちょうど（topics[0] は parseLog と名前照合で検証）。
  if (
    typeof address !== 'string' ||
    address.toLowerCase() !== expected.registry.toLowerCase() ||
    topics.length !== 2 ||
    typeof topics[1] !== 'string' ||
    topics[1].toLowerCase() !== expected.identityTopic.toLowerCase()
  ) {
    throw notFound();
  }
  const parsed = ERC1056_INTERFACE.parseLog({ topics: [...topics], data });
  if (parsed === null || parsed.name !== eventName) {
    throw notFound();
  }
  return { args: parsed.args, blockNumber: hexInt(blockNumber), logIndex: hexInt(logIndex) };
}

/** DIDOwnerChanged ログを OwnerChangeEvent に変換する（無視対象は空配列）。 */
export function toOwnerChange(log: unknown, expected: ExpectedLog): OwnerChangeEvent[] {
  const decoded = decodeLog(log, 'DIDOwnerChanged', expected);
  if (decoded === null) {
    return [];
  }
  const { args, blockNumber, logIndex } = decoded;
  return [{ owner: String(args[1]), blockNumber, logIndex }];
}

/** DIDAttributeChanged ログを AttributeChangeEvent に変換する（無視対象は空配列）。 */
export function toAttributeChange(log: unknown, expected: ExpectedLog): AttributeChangeEvent[] {
  const decoded = decodeLog(log, 'DIDAttributeChanged', expected);
  if (decoded === null) {
    return [];
  }
  const { args, blockNumber, logIndex } = decoded;
  // name は bytes32（右パディングの UTF-8）。末尾のゼロを除いて文字列化する。
  return [
    {
      name: decodeBytes32(String(args[1])),
      value: String(args[2]),
      validTo: Number(args[3]),
      blockNumber,
      logIndex,
    },
  ];
}

/** bytes32（`0x` + 64 hex、右ゼロパディング）を UTF-8 文字列にデコードする。 */
function decodeBytes32(hex: string): string {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes: number[] = [];
  for (let i = 0; i < body.length; i += 2) {
    const byte = Number.parseInt(body.slice(i, i + 2), 16);
    if (byte === 0) {
      break;
    }
    bytes.push(byte);
  }
  return new TextDecoder('utf-8').decode(Uint8Array.from(bytes));
}
