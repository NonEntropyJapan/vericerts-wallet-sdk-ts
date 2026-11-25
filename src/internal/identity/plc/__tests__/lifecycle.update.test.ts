/**
 * did:plc の更新・失効操作の生成（`updateDidPlc` / `deactivateDidPlc`）。
 * `did` / `prev` の形式検査と署名前の GDPR Art.9 検査を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { parseRotationKey, verifySignature } from '../keys.js';
import { deactivateDidPlc, updateDidPlc } from '../lifecycle.js';
import { parseOperation } from '../operation.js';
import { dataOf, expectVericertsError, genesis, makeKey } from './plc.fixtures.js';

const PREV = 'bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';

describe('updateDidPlc / deactivateDidPlc', () => {
  it('prev に直前の CID を持つ plc_operation を署名する', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const operation = await updateDidPlc({
      did: g.did,
      prev: (g.entries[0] as { cid: string }).cid,
      data: { ...g.data, alsoKnownAs: ['at://bob.example.com'] },
      signer: key.sign,
      signerKey: key.didKey,
    });
    expect(operation.prev).toBe((g.entries[0] as { cid: string }).cid);
    expect(operation.alsoKnownAs).toEqual(['at://bob.example.com']);
    const parsed = parseOperation(operation);
    expect(verifySignature(parseRotationKey(key.didKey), parsed.unsigned, operation.sig)).toBe(
      true,
    );
  });

  it('deactivateDidPlc は plc_tombstone（type / prev / sig のみ）を作る', async () => {
    const key = makeKey();
    const operation = await deactivateDidPlc({
      did: 'did:plc:ewvi7nxzyoun6zhxrhs64oiz',
      prev: PREV,
      signer: key.sign,
      signerKey: key.didKey,
    });
    expect(Object.keys(operation).sort()).toEqual(['prev', 'sig', 'type']);
    expect(operation.type).toBe('plc_tombstone');
    expect(parseOperation(operation).kind).toBe('tombstone');
  });

  it('did の形式不正（大文字・長さ違い）・prev の CID 形式不正は 2001、署名器を呼ばない', async () => {
    const key = makeKey();
    let calls = 0;
    const signer = async (unsigned: Uint8Array) => {
      calls += 1;
      return key.sign(unsigned);
    };
    const data = dataOf([key]);
    await expectVericertsError(
      () =>
        updateDidPlc({
          did: 'did:plc:EWVI7NXZYOUN6ZHXRHS64OIZ',
          prev: PREV,
          data,
          signer,
          signerKey: key.didKey,
        }),
      ErrorCodes.INVALID_DID,
    );
    await expectVericertsError(
      () => updateDidPlc({ did: 'did:plc:short', prev: PREV, data, signer, signerKey: key.didKey }),
      ErrorCodes.INVALID_DID,
    );
    for (const prev of ['', 'Qm123', PREV.toUpperCase(), `${PREV}a`, `b${'a'.repeat(58)}`]) {
      await expectVericertsError(
        () =>
          updateDidPlc({
            did: 'did:plc:ewvi7nxzyoun6zhxrhs64oiz',
            prev,
            data,
            signer,
            signerKey: key.didKey,
          }),
        ErrorCodes.INVALID_DID,
        'plc_operation_invalid',
      );
    }
    await expectVericertsError(
      () =>
        deactivateDidPlc({
          did: 'did:plc:ewvi7nxzyoun6zhxrhs64oiz',
          prev: 'x',
          signer,
          signerKey: key.didKey,
        }),
      ErrorCodes.INVALID_DID,
    );
    expect(calls).toBe(0);
  });

  it('update も GDPR Art.9 属性を署名前に拒否する（10601）', async () => {
    const key = makeKey();
    await expectVericertsError(
      () =>
        updateDidPlc({
          did: 'did:plc:ewvi7nxzyoun6zhxrhs64oiz',
          prev: PREV,
          data: {
            ...dataOf([key]),
            services: { religion: { type: 'T', endpoint: 'https://example.com' } },
          },
          signer: key.sign,
          signerKey: key.didKey,
        }),
      ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN,
    );
  });
});
