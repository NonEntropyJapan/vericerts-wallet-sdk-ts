/**
 * `MethodPlc.resolve` の検証失敗（2010）: DID 再計算・署名・分岐規則・文書の一致。
 *
 * 取得は `fetchFn` 注入のモックで、実ネットワークには接続しない。
 */

import { describe, expect, it } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { ErrorCodes } from '../../../errors.js';
import { encodeDagCbor } from '../dag-cbor.js';
import { MethodPlc } from '../method-plc.js';
import { didOfGenesisBytes, parseOperation } from '../operation.js';
import {
  dataOf,
  directoryFor,
  documentOf,
  entry,
  expectVericertsError,
  genesis,
  makeKey,
  nextOperation,
} from './plc.fixtures.js';

const T0 = '2026-10-01T00:00:00.000Z';
const T1 = '2026-10-01T01:00:00.000Z';

describe('MethodPlc.resolve — 検証失敗（2010）', () => {
  it('別の DID の監査ログ（ジェネシスから再計算した DID が不一致）を拒否する', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const other = await genesis(makeKey());
    const dir = directoryFor(
      g.did,
      other.entries.map((e) => ({ ...e, did: g.did })),
      documentOf(g.did, g.data),
    );
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_did_mismatch',
    );
  });

  it('署名が改竄された操作は 2010（plc_signature_invalid）', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const op = {
      ...g.operation,
      sig: `${g.operation.sig.slice(0, -2)}${g.operation.sig.endsWith('AA') ? 'BB' : 'AA'}`,
    };
    // 署名を変えると CID も変わる。ディレクトリは変えた CID を返す（ジェネシスなので DID も変わる）。
    const did = didOfGenesisBytes(parseOperation(op).signed);
    const dir = directoryFor(did, [entry(did, op, T0)], documentOf(did, g.data));
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_signature_invalid',
    );
  });

  it('rotationKeys に無い鍵で署名された後続操作は 2010', async () => {
    const key = makeKey();
    const attacker = makeKey();
    const g = await genesis(key);
    const forged = await nextOperation(g.did, g.entries[0] as never, g.data, attacker).catch(
      () => undefined,
    );
    // `updateDidPlc` は署名鍵が直前の rotationKeys にあるかを SDK 側で知らないため、署名できてしまう。
    expect(forged).toBeDefined();
    const entries = [...g.entries, entry(g.did, forged as never, T1)];
    const dir = directoryFor(g.did, entries, documentOf(g.did, g.data));
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_signature_invalid',
    );
  });

  it('High-S の署名は拒否する（検証は low-S のみ）', async () => {
    const key = makeKey('P-256');
    const data = dataOf([key]);
    const base = (await genesis(key, data)).operation;
    const { sig: _sig, ...unsigned } = base;
    const bytes = encodeDagCbor(unsigned);
    // 同じ署名の s を n - s に反転して High-S 版を作る（数学的には有効な署名）。
    const lowS = p256.Signature.fromBytes(key.signRaw(bytes, true), 'compact');
    const high = new p256.Signature(lowS.r, p256.Point.Fn.ORDER - lowS.s).toBytes('compact');
    const op = { ...unsigned, sig: Buffer.from(high).toString('base64url') };
    const did = didOfGenesisBytes(parseOperation(op).signed);
    const dir = directoryFor(did, [entry(did, op, T0)], documentOf(did, data));
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_signature_invalid',
    );
  });

  it('旧形式 create の鍵が署名を検証できない種別（Ed25519）なら 2010（plc_signature_invalid）', async () => {
    const ed = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    const signer = makeKey();
    const unsigned = {
      type: 'create',
      signingKey: ed,
      recoveryKey: ed,
      handle: 'alice.example.com',
      service: 'pds.example.com',
      prev: null,
    };
    const sig = Buffer.from(await signer.sign(encodeDagCbor(unsigned))).toString('base64url');
    const operation = { ...unsigned, sig };
    const did = didOfGenesisBytes(parseOperation(operation).signed);
    const dir = directoryFor(did, [entry(did, operation, T0)], {});
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_signature_invalid',
    );
  });

  it('組み立てた文書とディレクトリの応答が不一致なら 2010（plc_document_mismatch）', async () => {
    const key = makeKey();
    const g = await genesis(key);
    for (const tampered of [
      { ...documentOf(g.did, g.data), alsoKnownAs: ['at://evil.example.com'] },
      documentOf(g.did, { ...g.data, verificationMethods: { atproto: makeKey().didKey } }),
      { ...documentOf(g.did, g.data), service: [] },
      { ...documentOf(g.did, g.data), id: 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa' },
      { ...documentOf(g.did, g.data), authentication: [`${g.did}#atproto`] },
    ]) {
      const dir = directoryFor(g.did, g.entries, tampered);
      await expectVericertsError(
        () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did),
        ErrorCodes.DID_DOC_INVALID,
        'plc_document_mismatch',
      );
    }
  });

  it('監査ログの構造不正（空・配列でない・did 不一致・cid 不一致・時刻不正）は 2010', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const doc = documentOf(g.did, g.data);
    const first = g.entries[0] as { cid: string };
    for (const [audit, reason] of [
      [[], 'plc_audit_log_invalid'],
      [{}, 'plc_audit_log_invalid'],
      [
        g.entries.map((e) => ({ ...e, did: 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa' })),
        'plc_audit_log_invalid',
      ],
      [
        g.entries.map((e) => ({
          ...e,
          cid: `${first.cid.slice(0, -1)}${first.cid.endsWith('a') ? 'b' : 'a'}`,
        })),
        'plc_cid_mismatch',
      ],
      [g.entries.map((e) => ({ ...e, createdAt: 'yesterday' })), 'plc_audit_log_invalid'],
      [g.entries.map((e) => ({ ...e, nullified: 'no' })), 'plc_audit_log_invalid'],
      [
        g.entries.map((e) => ({ ...e, operation: { ...(e.operation as object), extra: 'x' } })),
        'plc_audit_log_invalid',
      ],
    ] as const) {
      await expectVericertsError(
        () => new MethodPlc({ fetchFn: directoryFor(g.did, audit, doc).fetchFn }).resolve(g.did),
        ErrorCodes.DID_DOC_INVALID,
        reason,
      );
    }
  });

  it('先頭以外の prev: null・未知の prev・重複した CID は 2010', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const doc = documentOf(g.did, g.data);
    const second = entry(g.did, g.operation, T1);
    await expectVericertsError(
      () =>
        new MethodPlc({
          fetchFn: directoryFor(g.did, [...g.entries, second], doc).fetchFn,
        }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_audit_log_invalid',
    );
    const orphan = await nextOperation(
      g.did,
      { cid: 'bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi' } as never,
      g.data,
      key,
    );
    await expectVericertsError(
      () =>
        new MethodPlc({
          fetchFn: directoryFor(g.did, [...g.entries, entry(g.did, orphan, T1)], doc).fetchFn,
        }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_prev_invalid',
    );
  });
});
