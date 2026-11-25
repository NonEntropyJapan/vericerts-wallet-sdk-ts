import { describe, expect, it } from 'bun:test';
import { encodeDagCbor } from '../dag-cbor.js';
import { createDidPlc } from '../lifecycle.js';
import { MethodPlc } from '../method-plc.js';
import { didOfGenesisBytes } from '../operation.js';
import { dataOf, directoryFor, documentOf, entry, makeKey } from './plc.fixtures.js';

describe('PLC の入力スナップショット', () => {
  it('own の __proto__ を検証鍵名・サービス名として署名に保持する', async () => {
    const key = makeKey();
    const data = {
      ...dataOf([key]),
      verificationMethods: { ['__proto__']: key.didKey },
      services: { ['__proto__']: { type: 'T', endpoint: 'https://example.com' } },
    };
    const { operation } = await createDidPlc({
      data,
      signer: key.sign,
      signerKey: key.didKey,
    });
    expect(Object.keys(operation.verificationMethods as object)).toEqual(['__proto__']);
    expect(Object.keys(operation.services as object)).toEqual(['__proto__']);
    expect(JSON.parse(JSON.stringify(operation)).services).toEqual(data.services);
  });

  it('サービス値は一度だけ読み、検査した値を署名する', async () => {
    const key = makeKey();
    let reads = 0;
    const { operation } = await createDidPlc({
      data: {
        ...dataOf([key]),
        services: {
          service: {
            type: 'T',
            get endpoint() {
              reads += 1;
              return reads === 1 ? 'https://expected.example' : 'https://changed.example';
            },
          },
        },
      },
      signer: key.sign,
      signerKey: key.didKey,
    });
    expect(reads).toBe(1);
    expect(operation.services).toEqual({
      service: { type: 'T', endpoint: 'https://expected.example' },
    });
  });

  it('監査ログの __proto__ 鍵・サービスと明示された検証関係を解決する', async () => {
    const key = makeKey();
    const data = {
      ...dataOf([key]),
      verificationMethods: { ['__proto__']: key.didKey },
      services: { ['__proto__']: { type: 'T', endpoint: 'https://example.com' } },
    };
    // 生成処理による欠落を隠さないよう、ディレクトリの操作は直接署名する。
    const unsigned = { type: 'plc_operation', ...data, prev: null };
    const operation = {
      ...unsigned,
      sig: Buffer.from(await key.sign(encodeDagCbor(unsigned))).toString('base64url'),
    };
    const did = didOfGenesisBytes(encodeDagCbor(operation));
    const directory = directoryFor(
      did,
      [entry(did, operation, '2026-10-01T00:00:00.000Z')],
      documentOf(did, data),
    );
    const doc = await new MethodPlc({
      fetchFn: directory.fetchFn,
      relationshipsForKeys: { ['__proto__']: ['assertionMethod'] },
    }).resolve(did);
    expect(doc.verificationMethod[0]?.id).toBe(`${did}#__proto__`);
    expect(doc.service?.[0]?.id).toBe('#__proto__');
    expect(doc.assertionMethod).toEqual([`${did}#__proto__`]);
  });
});
