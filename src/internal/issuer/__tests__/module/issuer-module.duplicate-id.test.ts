/**
 * `IssuerModule` の `vcId` 重複拒否の回帰テスト（実鍵・モック禁止）。
 *
 * 同じ `id` で 2 通発行すると 1 通目の Status List インデックスが `entries` から消え、`vcId` 経由では
 * 二度と失効できない孤児になる。`issueVC` / `importEntries` は重複を `3002` で拒否する。
 */

import { beforeEach, describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { IssuerModule } from '../../module/issuer-module.js';
import { createStatusList, type StatusListManager } from '../../token-status-list.js';

const ISSUER = 'did:key:z6MkIssuerDup';
const HOLDER_A = 'did:key:z6MkHolderA';
const HOLDER_B = 'did:key:z6MkHolderB';

describe('IssuerModule vcId 重複', () => {
  let revocation: StatusListManager;
  let issuer: IssuerModule;

  beforeEach(() => {
    revocation = createStatusList({
      uri: 'https://issuer.example/status/revocation',
      issuer: ISSUER,
      size: 64,
      purpose: 'revocation',
    });
    issuer = new IssuerModule({
      issuer: ISSUER,
      signer: createPrivateKeySigner(new Uint8Array(32).fill(59), 'ES256'),
      statusLists: { revocation },
      now: () => new Date('2026-08-28T00:00:00.000Z'),
    });
  });

  it('同一 id の 2 回目の issueVC は 3002 で拒否され、Status List の残容量を消費しない', async () => {
    await issuer.issueVC(HOLDER_A, { name: 'A' }, { id: 'urn:uuid:dup' });
    const remaining = revocation.remaining;

    await expect(issuer.issueVC(HOLDER_B, { name: 'B' }, { id: 'urn:uuid:dup' })).rejects.toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
    expect(revocation.remaining).toBe(remaining);

    // 1 通目は引き続き vcId 経由で失効できる。
    await issuer.setTokenStatus('urn:uuid:dup', 'revocation', 1);
    expect(revocation.isSet(0)).toBe(true);
  });

  it('credentialStatus: false の発行は entries を作らないため、同一 id でも拒否しない', async () => {
    await issuer.issueVC(
      HOLDER_A,
      { name: 'A' },
      { id: 'urn:uuid:nostatus', credentialStatus: false },
    );
    await expect(
      issuer.issueVC(HOLDER_B, { name: 'B' }, { id: 'urn:uuid:nostatus', credentialStatus: false }),
    ).resolves.toBeDefined();
  });

  it('importEntries: 同一内容の再 import は冪等、異なる indices の重複は拒否して何も取り込まない', async () => {
    // idx 5 を「払い出し済み」にして、衝突検査まで届く（割当カーソル超えの拒否は 別のテスト）。
    for (let i = 0; i < 5; i += 1) revocation.allocate();
    await issuer.issueVC(HOLDER_A, { name: 'A' }, { id: 'urn:uuid:a' });
    const exported = issuer.exportEntries();

    expect(() => issuer.importEntries(exported)).not.toThrow();
    expect(issuer.exportEntries()).toEqual(exported);

    expect(() =>
      issuer.importEntries([
        { vcId: 'urn:uuid:new', indices: { revocation: 5 } },
        { vcId: 'urn:uuid:a', indices: { revocation: 9 } },
      ]),
    ).toThrow(new VericertsError(ErrorCodes.VC_SCHEMA_INVALID));
    expect(issuer.exportEntries()).toEqual(exported);
  });

  it('importEntries: 入力内の vcId 重複（内容が異なる）も拒否する', () => {
    for (let i = 0; i < 3; i += 1) revocation.allocate();
    expect(() =>
      issuer.importEntries([
        { vcId: 'urn:uuid:x', indices: { revocation: 1 } },
        { vcId: 'urn:uuid:x', indices: { revocation: 2 } },
      ]),
    ).toThrow(new VericertsError(ErrorCodes.VC_SCHEMA_INVALID));
    expect(issuer.exportEntries()).toEqual([]);
  });
});

describe('IssuerModule.importEntries の形式検査', () => {
  let revocation: StatusListManager;
  let issuer: IssuerModule;

  beforeEach(() => {
    revocation = createStatusList({
      uri: 'https://issuer.example/status/revocation',
      issuer: ISSUER,
      size: 8,
      purpose: 'revocation',
    });
    // idx 0..2 は払い出し済み（取り込める idx は割当カーソル未満）。
    for (let i = 0; i < 3; i += 1) revocation.allocate();
    issuer = new IssuerModule({
      issuer: ISSUER,
      signer: createPrivateKeySigner(new Uint8Array(32).fill(59), 'ES256'),
      statusLists: { revocation },
      now: () => new Date('2026-08-28T00:00:00.000Z'),
    });
  });

  const schemaInvalid = new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);

  it('別 vcId が同一 purpose・同一 idx を指すバッチは何も取り込まず 3002', async () => {
    expect(() =>
      issuer.importEntries([
        { vcId: 'ok', indices: { revocation: 1 } },
        { vcId: 'a', indices: { revocation: 2 } },
        { vcId: 'b', indices: { revocation: 2 } },
      ]),
    ).toThrow(schemaInvalid);
    expect(issuer.exportEntries()).toEqual([]);
  });

  it('既存の別 vcId と同じ idx を指すエントリは 3002（既存の失効可否は変わらない）', async () => {
    issuer.importEntries([{ vcId: 'a', indices: { revocation: 2 } }]);
    expect(() => issuer.importEntries([{ vcId: 'b', indices: { revocation: 2 } }])).toThrow(
      schemaInvalid,
    );
    await issuer.setTokenStatus('a', 'revocation', 1);
    expect(revocation.isSet(2)).toBe(true);
    expect(issuer.exportEntries()).toEqual([{ vcId: 'a', indices: { revocation: 2 } }]);
  });

  it('同一 vcId の同一内容の再取り込みは冪等に受理される', () => {
    const entries = [{ vcId: 'a', indices: { revocation: 2 } }] as const;
    issuer.importEntries(entries);
    expect(() => issuer.importEntries(entries)).not.toThrow();
    expect(() => issuer.importEntries([entries[0], entries[0]])).not.toThrow();
  });

  it.each([
    ['範囲外 idx（size 以上）', { revocation: 8 }],
    ['負の idx', { revocation: -1 }],
    ['非整数 idx', { revocation: 1.5 }],
    ['NaN idx', { revocation: Number.NaN }],
    ['文字列 idx', { revocation: '1' }],
    ['未知の purpose', { bogus: 1 }],
    ['未設定の purpose（suspension）', { suspension: 1 }],
    ['Object.prototype 上のキー名', { constructor: 1 }],
  ])('%s は取り込み時点で 3002', (_name, indices) => {
    expect(() =>
      issuer.importEntries([
        { vcId: 'ok', indices: { revocation: 0 } },
        { vcId: 'bad', indices: indices as never },
      ]),
    ).toThrow(schemaInvalid);
    expect(issuer.exportEntries()).toEqual([]);
  });

  it('exportEntries の出力は往復で取り込める', async () => {
    await issuer.issueVC(HOLDER_A, { name: 'A' }, { id: 'urn:uuid:a' });
    await issuer.issueVC(HOLDER_B, { name: 'B' }, { id: 'urn:uuid:b' });
    const exported = issuer.exportEntries();
    const restored = new IssuerModule({
      issuer: ISSUER,
      signer: createPrivateKeySigner(new Uint8Array(32).fill(59), 'ES256'),
      statusLists: { revocation },
    });
    expect(() => restored.importEntries(exported)).not.toThrow();
    expect(restored.exportEntries()).toEqual(exported);
  });
});

describe('IssuerModule.importEntries は割当カーソル以上の idx を拒否する', () => {
  const schemaInvalid = new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  let revocation: StatusListManager;
  let issuer: IssuerModule;

  beforeEach(() => {
    revocation = createStatusList({
      uri: 'https://issuer.example/status/revocation',
      issuer: ISSUER,
      size: 8,
      purpose: 'revocation',
    });
    issuer = new IssuerModule({
      issuer: ISSUER,
      signer: createPrivateKeySigner(new Uint8Array(32).fill(59), 'ES256'),
      statusLists: { revocation },
      now: () => new Date('2026-08-28T00:00:00.000Z'),
    });
  });

  it('nextIndex 以上の idx は 3002 で拒否し、後続の issueVC の idx と衝突しない', async () => {
    expect(revocation.nextIndex).toBe(0);
    expect(() => issuer.importEntries([{ vcId: 'imported', indices: { revocation: 1 } }])).toThrow(
      schemaInvalid,
    );
    expect(issuer.exportEntries()).toEqual([]);

    await issuer.issueVC(HOLDER_A, { name: 'A' }, { id: 'a' });
    await issuer.issueVC(HOLDER_B, { name: 'B' }, { id: 'b' });
    expect(issuer.exportEntries()).toEqual([
      { vcId: 'a', indices: { revocation: 0 } },
      { vcId: 'b', indices: { revocation: 1 } },
    ]);
  });

  it('境界: idx === nextIndex は拒否、idx === nextIndex - 1 は受理', () => {
    revocation.allocate();
    revocation.allocate();
    expect(() => issuer.importEntries([{ vcId: 'x', indices: { revocation: 2 } }])).toThrow(
      schemaInvalid,
    );
    expect(() => issuer.importEntries([{ vcId: 'x', indices: { revocation: 1 } }])).not.toThrow();
  });
});
