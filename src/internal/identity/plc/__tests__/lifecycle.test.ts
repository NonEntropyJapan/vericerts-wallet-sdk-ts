/**
 * did:plc の操作生成（`createDidPlc` / `updateDidPlc` / `deactivateDidPlc`）。
 * 署名前の入力検査・返却前の自己検証・low-S 正規化を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes } from '../../../errors.js';
import { encodeDagCbor } from '../dag-cbor.js';
import { parseRotationKey, verifySignature } from '../keys.js';
import { createDidPlc } from '../lifecycle.js';
import { MAX_OPERATION_BYTES, type PlcOperationData, parseOperation } from '../operation.js';
import { dataOf, expectVericertsError, makeKey, type TestKey } from './plc.fixtures.js';

const _PREV = 'bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';

describe('createDidPlc', () => {
  it('署名済みジェネシスと DID を返し、DID はジェネシスの DAG-CBOR のハッシュから再計算できる', async () => {
    const key = makeKey();
    const { did, operation } = await createDidPlc({
      data: dataOf([key]),
      signer: key.sign,
      signerKey: key.didKey,
    });
    expect(did).toMatch(/^did:plc:[a-z2-7]{24}$/);
    expect(operation.type).toBe('plc_operation');
    expect(operation.prev).toBeNull();
    const parsed = parseOperation(operation);
    expect(verifySignature(parseRotationKey(key.didKey), parsed.unsigned, operation.sig)).toBe(
      true,
    );
    expect(parsed.cid).toStartWith('bafyrei');
  });

  it('P-256 の回転鍵でも署名できる', async () => {
    const key = makeKey('P-256');
    const { operation } = await createDidPlc({
      data: dataOf([key]),
      signer: key.sign,
      signerKey: key.didKey,
    });
    const parsed = parseOperation(operation);
    expect(verifySignature(parseRotationKey(key.didKey), parsed.unsigned, operation.sig)).toBe(
      true,
    );
  });

  it('署名器が High-S を返しても low-S・64 バイト・パディングなし base64url に正規化する', async () => {
    const key = makeKey('P-256');
    const { operation } = await createDidPlc({
      data: dataOf([key]),
      signer: key.signHighS,
      signerKey: key.didKey,
    });
    expect(operation.sig).not.toContain('=');
    expect(base64urlnopad.decode(operation.sig)).toHaveLength(64);
    const parsed = parseOperation(operation);
    expect(verifySignature(parseRotationKey(key.didKey), parsed.unsigned, operation.sig)).toBe(
      true,
    );
  });

  it('同じ入力から同じ署名対象（DAG-CBOR）を作り、署名器へはその sig 抜きのバイト列を渡す', async () => {
    const key = makeKey();
    let received: Uint8Array | undefined;
    const { operation } = await createDidPlc({
      data: dataOf([key]),
      signer: async (unsigned) => {
        received = unsigned;
        return key.sign(unsigned);
      },
      signerKey: key.didKey,
    });
    const { sig: _sig, ...unsignedOperation } = operation;
    expect(received).toEqual(encodeDagCbor(unsignedOperation));
  });

  describe('署名前の入力検査（署名器を呼ばない）', () => {
    const rejects = async (
      mutate: (data: PlcOperationData, key: TestKey) => unknown,
      code: string,
      reason?: string,
    ): Promise<void> => {
      const key = makeKey();
      let calls = 0;
      const data = mutate(dataOf([key]), key) as PlcOperationData;
      await expectVericertsError(
        () =>
          createDidPlc({
            data,
            signer: async (unsigned) => {
              calls += 1;
              return key.sign(unsigned);
            },
            signerKey: key.didKey,
          }),
        code as never,
        reason,
      );
      expect(calls).toBe(0);
    };

    it('rotationKeys が空 / 6 件 / 重複は 2001', async () => {
      await rejects(
        (d) => ({ ...d, rotationKeys: [] }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
      await rejects(
        (d) => ({ ...d, rotationKeys: Array.from({ length: 6 }, () => makeKey().didKey) }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
      await rejects(
        (d) => ({ ...d, rotationKeys: [d.rotationKeys[0], d.rotationKeys[0]] }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
    });

    it('5 件までは受理される', async () => {
      const keys = Array.from({ length: 5 }, () => makeKey());
      const first = keys[0] as TestKey;
      const { operation } = await createDidPlc({
        data: dataOf(keys),
        signer: first.sign,
        signerKey: first.didKey,
      });
      expect(operation.rotationKeys).toHaveLength(5);
    });

    it('Ed25519 の回転鍵・did:key でない回転鍵は 2001', async () => {
      const ed = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
      await rejects(
        (d) => ({ ...d, rotationKeys: [ed] }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
      await rejects(
        (d) => ({ ...d, rotationKeys: ['nope'] }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
    });

    it('署名鍵が rotationKeys に含まれない場合は 2001', async () => {
      const key = makeKey();
      const other = makeKey();
      await expectVericertsError(
        () => createDidPlc({ data: dataOf([key]), signer: other.sign, signerKey: other.didKey }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
    });

    it('verificationMethods は did:key 構文でなければ 2001、Ed25519 でもよい', async () => {
      await rejects(
        (d) => ({ ...d, verificationMethods: { atproto: 'did:web:example.com' } }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
      const key = makeKey();
      const ed = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
      const { operation } = await createDidPlc({
        data: { ...dataOf([key]), verificationMethods: { atproto: ed } },
        signer: key.sign,
        signerKey: key.didKey,
      });
      expect(operation.verificationMethods).toEqual({ atproto: ed });
    });

    it('サービスの endpoint が http(s) の URL でなければ 2001', async () => {
      await rejects(
        (d) => ({ ...d, services: { s: { type: 'T', endpoint: 'ftp://example.com' } } }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
      await rejects(
        (d) => ({ ...d, services: { s: { type: 'T', endpoint: 'not a url' } } }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
    });

    it('GDPR Art.9 属性を含む入力は 10601', async () => {
      await rejects(
        (d) => ({ ...d, services: { health: { type: 'T', endpoint: 'https://example.com' } } }),
        ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN,
      );
    });

    it('署名済み操作が DAG-CBOR で 7500 バイトを超える入力は 2001', async () => {
      await rejects(
        (d) => ({
          ...d,
          alsoKnownAs: Array.from({ length: 200 }, (_, i) => `at://${'a'.repeat(50)}${i}`),
        }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
    });

    it('7500 バイトちょうどの操作は署名され、1 バイト超えると 2001', async () => {
      const key = makeKey();
      const sizeWith = async (length: number): Promise<number> => {
        const { operation } = await createDidPlc({
          data: { ...dataOf([key]), alsoKnownAs: [`at://${'a'.repeat(length)}`] },
          signer: key.sign,
          signerKey: key.didKey,
        });
        return parseOperation(operation).signed.length;
      };
      // 文字列の長さヘッダが 2 バイトになる範囲（256 以上）で、1 文字 = 1 バイト増える。
      const base = await sizeWith(300);
      const exact = 300 + (MAX_OPERATION_BYTES - base);
      expect(await sizeWith(exact)).toBe(MAX_OPERATION_BYTES);
      await expectVericertsError(
        () => sizeWith(exact + 1),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
    });
  });

  describe('署名器の戻り値の検査', () => {
    it.each([
      'secp256k1',
      'P-256',
    ] as const)('%s の 64 バイトでも r / s が範囲外なら 2010', async (keyType) => {
      const key = makeKey(keyType);
      for (const byte of [0, 255]) {
        await expectVericertsError(
          () =>
            createDidPlc({
              data: dataOf([key]),
              signer: async () => new Uint8Array(64).fill(byte),
              signerKey: key.didKey,
            }),
          ErrorCodes.DID_DOC_INVALID,
          'plc_signature_invalid',
        );
      }
    });

    it('64 バイトでない署名は 2010（plc_signature_invalid）', async () => {
      const key = makeKey();
      await expectVericertsError(
        () =>
          createDidPlc({
            data: dataOf([key]),
            signer: async () => new Uint8Array(63),
            signerKey: key.didKey,
          }),
        ErrorCodes.DID_DOC_INVALID,
        'plc_signature_invalid',
      );
    });

    it('別の鍵で作った署名は返却前の自己検証で 2010', async () => {
      const key = makeKey();
      const other = makeKey();
      await expectVericertsError(
        () => createDidPlc({ data: dataOf([key]), signer: other.sign, signerKey: key.didKey }),
        ErrorCodes.DID_DOC_INVALID,
        'plc_signature_invalid',
      );
    });
  });
});
