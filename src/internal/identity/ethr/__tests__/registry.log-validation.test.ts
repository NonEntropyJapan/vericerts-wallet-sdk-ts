/**
 * createEthersEventSource（registry.ts）の応答ログ検証。
 *
 * `eth_getLogs` の応答は信頼境界の外（RPC ノード）。reorg で外れたログ（`removed: true`）は無視し、
 * 問い合わせた registry・identity と一致しないログ（別 address / 別 identity / 余分な topic）は
 * 「owner 不変」に読めないよう黙って捨てず DID_NOT_FOUND（2003）で fail-closed にする。
 * 本テストは real ノードの挙動ではなく、非準拠・不正なノードへの防御を pin する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { createEthersEventSource, DEFAULT_REGISTRY_ADDRESS } from '../registry.js';
import {
  attributeLog,
  CHAIN_ID,
  IDENTITY,
  OWNER,
  ownerLog,
  type RawLogFixture,
  RPC_URL,
  rpcStub,
  toBytes32,
} from './rpc-stub.js';

const OTHER_IDENTITY = '0x2222222222222222222222222222222222222222';
const OVERRIDE_REGISTRY = '0x3333333333333333333333333333333333333333';
const NEW_OWNER = '0x4444444444444444444444444444444444444444';
const NAME = toBytes32('did/svc/Svc');

async function failureOf(promise: Promise<unknown>): Promise<VericertsError> {
  try {
    await promise;
  } catch (error) {
    return error as VericertsError;
  }
  throw new Error('should have thrown');
}

function fetchWith(
  logs: { owner?: unknown[]; attribute?: unknown[] },
  registryAddresses?: Record<number, string>,
) {
  const { fetchImpl } = rpcStub(logs);
  const source = createEthersEventSource({ [CHAIN_ID]: RPC_URL }, registryAddresses, fetchImpl);
  return source.fetchEvents(CHAIN_ID, IDENTITY);
}

async function expectNotFound(logs: { owner?: unknown[]; attribute?: unknown[] }): Promise<void> {
  const error = await failureOf(fetchWith(logs));
  expect(error.code).toBe(ErrorCodes.DID_NOT_FOUND);
}

/** owner / attribute の両経路に同じ改変を入れた不正ログを渡す。 */
const BOTH_PATHS: readonly [
  string,
  (log: RawLogFixture) => { owner?: unknown[]; attribute?: unknown[] },
][] = [
  ['DIDOwnerChanged', (log) => ({ owner: [log] })],
  ['DIDAttributeChanged', (log) => ({ attribute: [log] })],
];

function baseLog(kind: string, identity?: string): RawLogFixture {
  return kind === 'DIDOwnerChanged'
    ? ownerLog(NEW_OWNER, 20, 0, identity)
    : attributeLog(NAME, '0x01', 1, 20, 0, identity);
}

describe('removed ログ（reorg で外れたログ）', () => {
  it('removed:true のログは無視し、無い場合と同じ結果になる', async () => {
    const kept = {
      owner: [ownerLog(OWNER, 10, 0)],
      attribute: [attributeLog(NAME, '0x01', 1, 11, 0)],
    };
    const expected = await fetchWith(kept);
    const withRemoved = await fetchWith({
      owner: [ownerLog(OWNER, 10, 0), { ...ownerLog(NEW_OWNER, 20, 0), removed: true }],
      attribute: [
        attributeLog(NAME, '0x01', 1, 11, 0),
        { ...attributeLog(NAME, '0x02', 1, 21, 0), removed: true },
      ],
    });
    expect(withRemoved).toEqual(expected);
    expect(withRemoved.ownerChanges).toHaveLength(1);
  });

  it('removed:true なら本文が壊れていても（デコード不能・別 address でも）無視する', async () => {
    const events = await fetchWith({
      owner: [
        { ...ownerLog(OWNER, 10, 0), data: '0x1234', removed: true },
        { ...ownerLog(OWNER, 11, 0), address: OVERRIDE_REGISTRY, removed: true },
        { removed: true },
      ],
    });
    expect(events).toEqual({ ownerChanges: [], attributeChanges: [] });
  });

  it('removed フィールドが無い（キー欠落）ログは通常どおり受理する（undefined / false は受理）', async () => {
    for (const [kind, build] of BOTH_PATHS) {
      const { removed: _removed, ...withoutRemoved } = baseLog(kind);
      expect('removed' in withoutRemoved).toBe(false);
      const events = await fetchWith(build(withoutRemoved));
      expect(events.ownerChanges.length + events.attributeChanges.length).toBe(1);
    }
  });

  it.each([
    ['true', 'true'],
    ['1', 1],
    ['null', null],
    ['object', {}],
  ])('removed が真偽値でない（%s）ログは DID_NOT_FOUND', async (_label, removed) => {
    for (const [kind, build] of BOTH_PATHS) {
      await expectNotFound(build({ ...baseLog(kind), removed }));
    }
  });
});

describe('address（registry）の検証', () => {
  it('別 registry の address のログは DID_NOT_FOUND', async () => {
    for (const [kind, build] of BOTH_PATHS) {
      await expectNotFound(build({ ...baseLog(kind), address: OVERRIDE_REGISTRY }));
    }
  });

  it('address が無い・文字列でないログは DID_NOT_FOUND', async () => {
    for (const [kind, build] of BOTH_PATHS) {
      const { address: _address, ...withoutAddress } = baseLog(kind);
      await expectNotFound(build(withoutAddress));
      await expectNotFound(build({ ...baseLog(kind), address: 123 }));
    }
  });

  it('正しい registry の address は大文字小文字（EIP-55 チェックサム形）が違っても受理する', async () => {
    const checksum = '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b'.replace(/[a-f]/g, (c) =>
      c.toUpperCase(),
    );
    expect(checksum).not.toBe(DEFAULT_REGISTRY_ADDRESS);
    for (const [kind, build] of BOTH_PATHS) {
      const events = await fetchWith(build({ ...baseLog(kind), address: checksum }));
      expect(events.ownerChanges.length + events.attributeChanges.length).toBe(1);
    }
  });

  it('registryAddresses の上書きチェーンでは、上書き先のログを受理し既定 address のログを拒否する', async () => {
    const overrides = { [CHAIN_ID]: OVERRIDE_REGISTRY };
    const accepted = await fetchWith(
      { owner: [{ ...ownerLog(OWNER, 10, 0), address: OVERRIDE_REGISTRY }] },
      overrides,
    );
    expect(accepted.ownerChanges).toHaveLength(1);

    const error = await failureOf(fetchWith({ owner: [ownerLog(OWNER, 10, 0)] }, overrides));
    expect(error.code).toBe(ErrorCodes.DID_NOT_FOUND);
  });
});

describe('topics（identity）の検証', () => {
  it('別 identity（topics[1] 不一致）のログは DID_NOT_FOUND', async () => {
    for (const [kind, build] of BOTH_PATHS) {
      await expectNotFound(build(baseLog(kind, OTHER_IDENTITY)));
    }
  });

  it('topics が 3 件（余分な topic）のログは DID_NOT_FOUND', async () => {
    for (const [kind, build] of BOTH_PATHS) {
      const log = baseLog(kind);
      const topics = log.topics as string[];
      await expectNotFound(build({ ...log, topics: [...topics, topics[1]] }));
    }
  });

  it('topics が 1 件・topics[1] が文字列でないログは DID_NOT_FOUND', async () => {
    for (const [kind, build] of BOTH_PATHS) {
      const log = baseLog(kind);
      const [topic0] = log.topics as string[];
      await expectNotFound(build({ ...log, topics: [topic0] }));
      await expectNotFound(build({ ...log, topics: [topic0, 1] }));
    }
  });

  it('topics[1] は大文字小文字が違っても受理する', async () => {
    for (const [kind, build] of BOTH_PATHS) {
      const log = baseLog(kind);
      const [topic0, identityTopic] = log.topics as string[];
      const upper = `0x${(identityTopic as string).slice(2).toUpperCase()}`;
      const events = await fetchWith(build({ ...log, topics: [topic0, upper] }));
      expect(events.ownerChanges.length + events.attributeChanges.length).toBe(1);
    }
  });

  it('不正ログが 1 件でも混ざれば全体を DID_NOT_FOUND にする（有効ログがあっても黙って捨てない）', async () => {
    await expectNotFound({
      owner: [ownerLog(OWNER, 10, 0), ownerLog(NEW_OWNER, 20, 0, OTHER_IDENTITY)],
    });
  });
});

describe('ログの形の検証', () => {
  it('オブジェクトでないログ・topics が配列でない / data が文字列でない / blockNumber・logIndex が不正なログは DID_NOT_FOUND', async () => {
    for (const [kind, build] of BOTH_PATHS) {
      const log = baseLog(kind);
      await expectNotFound(build(null as never));
      await expectNotFound(build('log' as never));
      await expectNotFound(build({ ...log, topics: 'nope' }));
      await expectNotFound(build({ ...log, data: 1 }));
      await expectNotFound(build({ ...log, blockNumber: 'latest' }));
      await expectNotFound(build({ ...log, logIndex: undefined }));
    }
  });
});

describe('topics[0]（イベント署名）の検証', () => {
  it('owner 経路に DIDAttributeChanged、attribute 経路に DIDOwnerChanged のログが来たら DID_NOT_FOUND', async () => {
    // address・topics[1] は正しく、イベント名だけが経路と食い違う（名前照合でのみ拒否される形）。
    await expectNotFound({ owner: [baseLog('DIDAttributeChanged')] });
    await expectNotFound({ attribute: [baseLog('DIDOwnerChanged')] });
  });

  it('topics[0] が未知のイベント署名のログは DID_NOT_FOUND', async () => {
    for (const [kind, build] of BOTH_PATHS) {
      const log = baseLog(kind);
      const [, identityTopic] = log.topics as string[];
      const unknownTopic0 = `0x${'ab'.repeat(32)}`;
      await expectNotFound(build({ ...log, topics: [unknownTopic0, identityTopic] }));
    }
  });
});

describe('data の検証（parseLog の失敗）', () => {
  it('address・topics は正しいが data が切り詰められたログは DID_NOT_FOUND', async () => {
    for (const [kind, build] of BOTH_PATHS) {
      const log = baseLog(kind);
      const data = log.data as string;
      // owner は (address, uint) の 64 バイト、attribute は (bytes, uint, uint) の動的データ。
      // 32 バイト未満・本体が欠けた長さへ切り詰める（address・topics・removed は正しいまま）。
      for (const length of [2, 2 + 2 * 31, 2 + 2 * 32]) {
        await expectNotFound(build({ ...log, data: data.slice(0, length) }));
      }
    }
  });
});
