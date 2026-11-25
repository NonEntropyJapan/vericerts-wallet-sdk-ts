/**
 * Wallet ファサード `updateDID`の統合テスト。
 *
 * 差分適用そのものの規則は `internal/identity/__tests__/did-document-patch.test.ts` が担う。
 * 本ファイルは `createWallet` 経由の配線 — 解決 → 差分適用 → Art.9 ガード → メソッドへの公開委譲
 * → ローカル控えの整合 — を検証する。
 *
 * - 更新を実装したカスタムメソッドには、差分適用済みの Document が `opts.document` で渡る。
 * - 不変メソッド（did:key 等）は `2002` で拒否され、`getDID` の控えは書き換わらない
 *   （`resolveDID` と食い違わせない）。
 * - GDPR Art.9 特別カテゴリ属性を含む差分は**公開前に** `10601` で止まる。
 * - 未登録メソッドは `2002`、DID 形式不正は `2001`、差分が空なら `2010`。
 * - 呼び出し側が `document` を直接指定しても、差分適用・Art.9 ガードを通った Document で上書き
 *   される（ガードの迂回を許さない）。メソッド固有の公開材料（did:ipid の `ipnsKeyBytes` 等）も
 *   プラグインへ転送しない。
 * - プラグインが別 DID の Document を返したら控えを書かずに `2010` で倒す。
 * - 控えのある DID だけ公開後に書き戻す（控えの無い DID を `listDIDs` に生やさない）。
 *
 * own アクセサの `opts`（読むたびに違う値を返す入力）に対する回帰は
 * `did/wallet.update-did-accessor-drift.test.ts` が持つ。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import type { DIDDocument, UpdateOptions } from '../../../internal/identity/did.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import { failureOf } from '../failure.fixtures.js';
import { CURRENT, DID, publishingMethod, TEST_MNEMONIC, unused } from './update-did.fixtures.js';

describe('Wallet.updateDID: 公開委譲', () => {
  it('差分適用済みの Document が opts.document でプラグインへ渡る', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    const { method, received } = publishingMethod();
    wallet.registerDIDMethod(method);

    const updated = await wallet.updateDID(DID, { addController: 'did:stub:controller' });

    expect(updated.controller).toEqual(['did:stub:controller']);
    expect(received).toHaveLength(1);
    expect(received[0]?.document?.controller).toEqual(['did:stub:controller']);
  });

  it('呼び出し側指定の document は差分適用後の Document で上書きされる', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    const { method, received } = publishingMethod();
    wallet.registerDIDMethod(method);

    // ガードを通っていない Document を直接公開させられないこと。
    const smuggled: DIDDocument = { ...CURRENT, controller: ['did:stub:attacker'] };
    await wallet.updateDID(DID, {
      addController: 'did:stub:controller',
      document: smuggled,
    } as UpdateOptions);

    expect(received[0]?.document?.controller).toEqual(['did:stub:controller']);
  });
});

describe('Wallet.updateDID: fail-closed', () => {
  it('不変メソッド（did:key）は METHOD_NOT_SUPPORTED(2002)', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const created = await wallet.createDID('key');

    await expect(
      wallet.updateDID(created.id, { addController: 'did:stub:controller' }),
    ).rejects.toThrow(new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED));
  });

  it('不変メソッドの更新失敗後もローカル控えは書き換わらない', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const created = await wallet.createDID('key');

    await failureOf(() => wallet.updateDID(created.id, { addController: 'did:stub:controller' }));

    // 控えが書き換わると `getDID` と `resolveDID` が恒久的に食い違う。
    const stored = await wallet.getDID(created.id);
    expect(stored).toEqual(created);
    expect(await wallet.resolveDID(created.id)).toEqual(created);
  });

  it('未登録メソッドは METHOD_NOT_SUPPORTED(2002)', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await expect(wallet.updateDID('did:unknown:abc', { addController: 'did:x:1' })).rejects.toThrow(
      new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED),
    );
  });

  it('DID 形式不正は INVALID_DID(2001)', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await expect(wallet.updateDID('not-a-did', { addController: 'did:x:1' })).rejects.toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });

  it('差分が 1 つも無い呼び出しは DID_DOC_INVALID(2010) で公開へ進まない', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    const { method, received } = publishingMethod();
    wallet.registerDIDMethod(method);

    expect(await failureOf(() => wallet.updateDID(DID, {}))).toEqual({
      code: ErrorCodes.DID_DOC_INVALID,
      reason: 'empty_update',
    });
    expect(received).toHaveLength(0);
  });
});

describe('Wallet.updateDID: GDPR Art.9 ガード', () => {
  it('特別カテゴリ属性を含む Service は公開前に 10601 で止まる', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    const { method, received } = publishingMethod();
    wallet.registerDIDMethod(method);

    await expect(
      wallet.updateDID(DID, {
        addService: {
          id: `${DID}#svc`,
          type: 'HealthRecords',
          // SDK が書き込みを拒否する特別カテゴリ属性名。DID Document は公開されると取り消せない。
          serviceEndpoint: { healthData: 'https://example.test/records' },
        },
      }),
    ).rejects.toThrow(new VericertsError(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN));
    // 公開委譲へは 1 度も進まない。
    expect(received).toHaveLength(0);
  });

  // 走査対象が次版 Document 全体だと、既に Art.9 属性を含む Document は**その属性を
  // 削除する更新まで** 10601 で弾かれ、恒久的に更新不能になる。
  // `current` はネットワーク由来なので、Issuer 側ホストの汚染で
  // 更新が永久に DoS されることにもなる。
  it('既存 Document が特別カテゴリ属性を含んでいても、それを削除する更新は通る', async () => {
    const tainted: DIDDocument = {
      ...CURRENT,
      service: [
        {
          id: `${DID}#svc`,
          type: 'HealthRecords',
          serviceEndpoint: { healthData: 'https://example.test' },
        },
      ],
    };
    const received: UpdateOptions[] = [];
    const wallet = await createWallet({ storage: new MemoryStorage() });
    wallet.registerDIDMethod({
      method: () => 'stub',
      create: unused,
      resolve: () => Promise.resolve(tainted),
      update: (_did, opts) => {
        received.push(opts);
        return Promise.resolve(opts.document ?? tainted);
      },
      deactivate: unused,
    });

    const updated = await wallet.updateDID(DID, { removeService: `${DID}#svc` });

    expect(updated.service ?? []).toEqual([]);
    expect(received).toHaveLength(1);
  });
});

describe('Wallet.updateDID: プラグインへ渡すオプション', () => {
  // `{ ...opts, document: next }` のスプレッドだと呼び出し側の own プロパティが
  // そのまま転送され、did:ipid の `MethodIpid.update` が `ipnsKeyBytes` の存在で「IPNS 公開モード」
  // と判定して `2002` を投げずに公開まで進む（fail-open）。しかも同メソッドは `opts.document` を
  // 見ないため、Art.9 ガードを通した次版 Document ではない別物が公開される。
  it('メソッド固有の公開材料は転送しない（UpdateDIDOptions + document に限定）', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    const { method, received } = publishingMethod();
    wallet.registerDIDMethod(method);

    await wallet.updateDID(DID, {
      addController: 'did:stub:controller',
      ipnsKeyBytes: new Uint8Array([1, 2, 3]),
      ipnsKeyName: 'self',
    } as UpdateOptions);

    const forwarded = received[0] as Record<string, unknown>;
    expect(Object.hasOwn(forwarded, 'ipnsKeyBytes')).toBe(false);
    expect(Object.hasOwn(forwarded, 'ipnsKeyName')).toBe(false);
    expect(forwarded.addController).toBe('did:stub:controller');
  });

  // 別 DID の Document を控えに書くと `getDID(didA)` が `id: didB` を返す破損になる。
  it('公開結果の id が対象 DID と一致しなければ 2010 で倒し、控えを書かない', async () => {
    const storage = new MemoryStorage();
    const wallet = await createWallet({ storage });
    wallet.registerDIDMethod({
      method: () => 'stub',
      create: unused,
      resolve: () => Promise.resolve(CURRENT),
      // 別 DID の Document を返す悪意ある / 壊れたプラグイン。
      update: () => Promise.resolve({ ...CURRENT, id: 'did:stub:other' }),
      deactivate: unused,
    });
    await storage.set(`did/${DID}`, new TextEncoder().encode(JSON.stringify(CURRENT)));

    expect(
      await failureOf(() => wallet.updateDID(DID, { addController: 'did:stub:controller' })),
    ).toEqual({
      code: ErrorCodes.DID_DOC_INVALID,
      reason: 'published_id_mismatch',
    });
    expect(await wallet.getDID(DID)).toEqual(CURRENT);
  });
});

describe('Wallet.updateDID: ローカル控えの整合', () => {
  it('控えの無い DID は公開後も控えを作らない', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    wallet.registerDIDMethod(publishingMethod().method);

    await wallet.updateDID(DID, { addController: 'did:stub:controller' });

    // `createDID` していない DID が `listDIDs` に現れないこと。
    expect(await wallet.getDID(DID)).toBeNull();
    expect(await wallet.listDIDs()).not.toContain(DID);
  });

  it('控えのある DID は公開後の Document で書き戻される', async () => {
    const storage = new MemoryStorage();
    const wallet = await createWallet({ storage });
    wallet.registerDIDMethod(publishingMethod().method);
    // `createDID('key')` と同じ経路で控えを作れないため、storage へ直接置いた状態を作る。
    await storage.set(`did/${DID}`, new TextEncoder().encode(JSON.stringify(CURRENT)));

    const updated = await wallet.updateDID(DID, { addController: 'did:stub:controller' });

    expect(await wallet.getDID(DID)).toEqual(updated);
  });
});
