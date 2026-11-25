import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes } from '../../../errors.js';
import { encodeDagCbor } from '../dag-cbor.js';
import { MethodPlc } from '../method-plc.js';
import { didOfGenesisBytes, type PlcOperationData } from '../operation.js';
import {
  dataOf,
  directoryFor,
  documentOf,
  entry,
  expectVericertsError,
  genesis,
  makeKey,
  type TestKey,
} from './plc.fixtures.js';

const T0 = '2026-10-01T00:00:00.000Z';
const T1 = '2026-10-01T01:00:00.000Z';

// 外部で生成された操作は、SDK の生成 API より広い PLC の読取規則で検証する。
async function signExternalOperation(data: PlcOperationData, prev: string | null, key: TestKey) {
  const unsigned = { type: 'plc_operation' as const, ...data, prev };
  return { ...unsigned, sig: base64urlnopad.encode(await key.sign(encodeDagCbor(unsigned))) };
}

describe('MethodPlc.resolve — 既存ログの回転鍵', () => {
  it('回転鍵を空にした署名済み更新後も DID Document を解決できる', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const data = { ...g.data, rotationKeys: [] };
    const operation = await signExternalOperation(data, g.entries[0]?.cid as string, key);
    const dir = directoryFor(
      g.did,
      [...g.entries, entry(g.did, operation, T1)],
      documentOf(g.did, data),
    );
    const doc = await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did);
    expect(doc.id).toBe(g.did);
    expect(doc.verificationMethod).toHaveLength(1);
  });

  it('重複する回転鍵を持つ署名済みジェネシスを解決できる', async () => {
    const key = makeKey();
    const data = dataOf([key, key]);
    const operation = await signExternalOperation(data, null, key);
    const did = didOfGenesisBytes(encodeDagCbor(operation));
    const dir = directoryFor(did, [entry(did, operation, T0)], documentOf(did, data));
    expect((await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(did)).id).toBe(did);
  });

  it('回転鍵を空にした操作も、以前の上位鍵による回復で無効化できる', async () => {
    const recovery = makeKey();
    const key = makeKey();
    const g = await genesis(key, dataOf([recovery, key]));
    const previous = g.entries[0]?.cid as string;
    const empty = await signExternalOperation({ ...g.data, rotationKeys: [] }, previous, key);
    const restored = await signExternalOperation(g.data, previous, recovery);
    const dir = directoryFor(
      g.did,
      [
        ...g.entries,
        entry(g.did, empty, T1, true),
        entry(g.did, restored, '2026-10-01T02:00:00.000Z'),
      ],
      documentOf(g.did, g.data),
    );
    expect((await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did)).id).toBe(g.did);
  });

  it('回転鍵のないジェネシスは署名を検証できず拒否する', async () => {
    const data = dataOf([]);
    const operation = await signExternalOperation(data, null, makeKey());
    const did = didOfGenesisBytes(encodeDagCbor(operation));
    const dir = directoryFor(did, [entry(did, operation, T0)], documentOf(did, data));
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_signature_invalid',
    );
  });

  it('回転鍵を空にした操作への追記は署名を検証できず拒否する', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const data = { ...g.data, rotationKeys: [] };
    const operation = await signExternalOperation(data, g.entries[0]?.cid as string, key);
    const empty = entry(g.did, operation, T1);
    const next = await signExternalOperation(g.data, empty.cid, key);
    const dir = directoryFor(
      g.did,
      [...g.entries, empty, entry(g.did, next, '2026-10-01T02:00:00.000Z')],
      documentOf(g.did, g.data),
    );
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_signature_invalid',
    );
  });
});
