/**
 * did:ethr レジストリテスト共通の JSON-RPC スタブ（`eth_getLogs` 応答の生成）。
 */

import { AbiCoder, Interface, zeroPadValue } from 'ethers';
import type { FetchLike } from '../../../fetch-di.js';
import { DEFAULT_REGISTRY_ADDRESS } from '../registry.js';

export const IDENTITY = '0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb';
export const OWNER = '0x1111111111111111111111111111111111111111';
export const CHAIN_ID = 1;
export const RPC_URL = 'http://localhost:8545';

const IFACE = new Interface([
  'event DIDOwnerChanged(address indexed identity, address owner, uint previousChange)',
  'event DIDAttributeChanged(address indexed identity, bytes32 name, bytes value, uint validTo, uint previousChange)',
]);

/** UTF-8 文字列を bytes32（`0x` + 64 hex、右ゼロパディング）へエンコードする。 */
export function toBytes32(value: string): string {
  const bytes = new TextEncoder().encode(value);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `0x${hex.padEnd(64, '0')}`;
}

/** `eth_getLogs` が返す生ログ 1 件（テストが欠落・改変できるよう緩い型）。 */
export type RawLogFixture = Record<string, unknown>;

/** DIDOwnerChanged の生ログ（`eth_getLogs` の要素）。既定の registry アドレスと `identity` の topic を持つ。 */
export function ownerLog(
  owner: string,
  blockNumber: number,
  logIndex: number,
  identity: string = IDENTITY,
): RawLogFixture {
  const topics = [
    IFACE.getEvent('DIDOwnerChanged')?.topicHash,
    zeroPadValue(identity, 32),
  ] as string[];
  const data = AbiCoder.defaultAbiCoder().encode(['address', 'uint'], [owner, 0]);
  return {
    address: DEFAULT_REGISTRY_ADDRESS,
    removed: false,
    topics,
    data,
    blockNumber: `0x${blockNumber.toString(16)}`,
    logIndex: `0x${logIndex.toString(16)}`,
  };
}

/** DIDAttributeChanged の生ログ。`name` は bytes32 hex をそのまま渡す。 */
export function attributeLog(
  nameBytes32: string,
  value: string,
  validTo: number,
  blockNumber: number,
  logIndex: number,
  identity: string = IDENTITY,
): RawLogFixture {
  const topics = [
    IFACE.getEvent('DIDAttributeChanged')?.topicHash,
    zeroPadValue(identity, 32),
  ] as string[];
  const data = AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'bytes', 'uint', 'uint'],
    [nameBytes32, value, validTo, 0],
  );
  return {
    address: DEFAULT_REGISTRY_ADDRESS,
    removed: false,
    topics,
    data,
    blockNumber: `0x${blockNumber.toString(16)}`,
    logIndex: `0x${logIndex.toString(16)}`,
  };
}

/** 問い合わせた identity の topic（`zeroPadValue(identity, 32)`）から応答ログ配列を作る関数。 */
export type LogsFor = (identityTopic: string) => unknown[];

/**
 * 要求の topic0 に応じて owner / attribute のログ配列を返す JSON-RPC スタブ。呼び出しも記録する。
 * ログは配列、または要求の identity topic（topics[1]）から作る関数で渡す（相異なる DID を引くテスト用）。
 */
export function rpcStub(logs: { owner?: unknown[] | LogsFor; attribute?: unknown[] | LogsFor }): {
  fetchImpl: FetchLike;
  requests: { url: string; body: { method: string; params: [Record<string, unknown>] } }[];
} {
  const requests: { url: string; body: { method: string; params: [Record<string, unknown>] } }[] =
    [];
  const ownerTopic = IFACE.getEvent('DIDOwnerChanged')?.topicHash;
  const fetchImpl: FetchLike = async (url, init) => {
    const body = JSON.parse(init.body);
    requests.push({ url, body });
    const [topic0, identityTopic] = body.params[0].topics as string[];
    const selected = (topic0 === ownerTopic ? logs.owner : logs.attribute) ?? [];
    const result = typeof selected === 'function' ? selected(identityTopic as string) : selected;
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  return { fetchImpl, requests };
}
