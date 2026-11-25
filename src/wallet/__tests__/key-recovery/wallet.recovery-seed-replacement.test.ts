/**
 * seed を別ニーモニックへ差し替える復旧経路で、旧 seed 由来のペルソナ・ウォレット id を掃除する
 * 回帰テスト。
 *
 * 残すと `resolveActiveSigner` が新 seed の鍵で署名しつつ旧 seed の DID（保存済み `persona.did`）を名乗り、
 * 検証側で原因不明の署名不一致になる。
 */

import { describe, expect, it } from 'bun:test';
import { KDF_TIMEOUT_MS } from '../../../internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import type { KdfParams } from '../../../internal/keymanager/kdf.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

const MNEMONIC_A =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const MNEMONIC_B = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const OLD_PASSWORD = 'old wallet password';
const NEW_PASSWORD = 'new wallet password';
const MIN_ARGON2ID: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };

async function walletWithPersonaOf(mnemonic: string) {
  const storage = new MemoryStorage();
  const wallet = await createWallet({ storage, kdf: MIN_ARGON2ID });
  await wallet.importMnemonic(mnemonic, undefined, undefined, { persistPassword: OLD_PASSWORD });
  const persona = await wallet.createPersona({ index: 0 });
  await wallet.setActivePersona(persona.id);
  return { storage, wallet, persona };
}

/** MNEMONIC_B を新規ウォレットへ入れて `createPersona({ index: 0 })` した場合の DID（期待値）。 */
async function expectedDidOf(mnemonic: string): Promise<string> {
  const fresh = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
  await fresh.importMnemonic(mnemonic);
  return (await fresh.createPersona({ index: 0 })).did;
}

describe('importRecoveredWallet の旧 seed 状態掃除', () => {
  it(
    'overwriteExisting で旧ペルソナ・アクティブ指定・ウォレット id を捨て、新 seed から再作成する',
    async () => {
      const { storage, wallet, persona } = await walletWithPersonaOf(MNEMONIC_A);
      const oldRecord = await storage.get('wallet/metadata');
      expect(oldRecord).not.toBeNull();

      const result = await wallet.importRecoveredWallet(MNEMONIC_B, {
        walletPassword: NEW_PASSWORD,
        newPin: '123456',
        newPasskey: false,
        overwriteExisting: true,
      });

      // 旧 seed 由来のペルソナとアクティブ指定は残らない。
      const personas = await wallet.listPersonas();
      expect(personas.map((p) => p.did)).not.toContain(persona.did);
      expect(await wallet.getActivePersona()).toBeNull();
      expect(await storage.get(`persona/${persona.id}`)).toBeNull();
      // ウォレット id は採番し直される。
      const newRecord = JSON.parse(
        new TextDecoder().decode((await storage.get('wallet/metadata')) as Uint8Array),
      ) as { id: string };
      const oldId = (
        JSON.parse(new TextDecoder().decode(oldRecord as Uint8Array)) as { id: string }
      ).id;
      expect(newRecord.id).not.toBe(oldId);
      expect(result.walletId).toBe(newRecord.id);

      // 新 seed から作るペルソナは、新規ウォレットに B を入れた場合と同じ DID になる。
      const recreated = await wallet.createPersona({ index: 0 });
      expect(recreated.did).toBe(await expectedDidOf(MNEMONIC_B));
    },
    KDF_TIMEOUT_MS,
  );
});

describe('recoverFromShamirShares の旧 seed 状態掃除', () => {
  it(
    '成功時は旧ペルソナを捨て、シェア不足では何も変えない',
    async () => {
      const donor = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
      await donor.importMnemonic(MNEMONIC_B, undefined, undefined, {
        persistPassword: OLD_PASSWORD,
      });
      const { shares } = await donor.createShamirShares(2, 3);

      const { wallet, persona } = await walletWithPersonaOf(MNEMONIC_A);

      const insufficient = await wallet.recoverFromShamirShares([shares[0] as string], {
        persistPassword: NEW_PASSWORD,
        overwriteExisting: true,
      });
      expect(insufficient.status).toBe('insufficient_shares');
      expect((await wallet.listPersonas()).map((p) => p.did)).toContain(persona.did);

      const ok = await wallet.recoverFromShamirShares(shares.slice(0, 2), {
        persistPassword: NEW_PASSWORD,
        overwriteExisting: true,
      });
      expect(ok.status).toBe('success');
      expect(await wallet.listPersonas()).toEqual([]);
      expect(await wallet.getActivePersona()).toBeNull();
      const recreated = await wallet.createPersona({ index: 0 });
      expect(recreated.did).toBe(await expectedDidOf(MNEMONIC_B));
    },
    KDF_TIMEOUT_MS,
  );
});

describe('Wallet.importMnemonic の旧 seed 状態掃除', () => {
  it(
    '別ニーモニックへの差し替えで旧ペルソナ・アクティブ指定・ウォレット id を捨て、新 seed から再作成する',
    async () => {
      const { storage, wallet, persona } = await walletWithPersonaOf(MNEMONIC_A);
      const oldId = (
        JSON.parse(
          new TextDecoder().decode((await storage.get('wallet/metadata')) as Uint8Array),
        ) as { id: string }
      ).id;

      await wallet.importMnemonic(MNEMONIC_B);

      expect((await wallet.listPersonas()).map((p) => p.did)).not.toContain(persona.did);
      expect(await wallet.getActivePersona()).toBeNull();
      expect(await storage.get(`persona/${persona.id}`)).toBeNull();
      // ウォレット id は採番し直される（掃除後に作られた場合のみ旧 id と異なる）。
      const newRecordBytes = await storage.get('wallet/metadata');
      if (newRecordBytes !== null) {
        const newId = (JSON.parse(new TextDecoder().decode(newRecordBytes)) as { id: string }).id;
        expect(newId).not.toBe(oldId);
      }
      const recreated = await wallet.createPersona({ index: 0 });
      expect(recreated.did).toBe(await expectedDidOf(MNEMONIC_B));
    },
    KDF_TIMEOUT_MS,
  );

  it(
    '同じニーモニックの再 import（再起動後の再読込）ではペルソナとウォレット id を保つ',
    async () => {
      const { storage, wallet, persona } = await walletWithPersonaOf(MNEMONIC_A);
      const idOf = async (): Promise<string> =>
        (
          JSON.parse(
            new TextDecoder().decode((await storage.get('wallet/metadata')) as Uint8Array),
          ) as { id: string }
        ).id;
      const before = await idOf();

      await wallet.importMnemonic(MNEMONIC_A);

      expect((await wallet.listPersonas()).map((p) => p.did)).toEqual([persona.did]);
      expect((await wallet.getActivePersona())?.did).toBe(persona.did);
      expect(await idOf()).toBe(before);
    },
    KDF_TIMEOUT_MS,
  );

  it(
    '同じニーモニックでもパスフレーズが違えば別 seed として旧ペルソナを捨てる',
    async () => {
      const { wallet, persona } = await walletWithPersonaOf(MNEMONIC_A);

      await wallet.importMnemonic(MNEMONIC_A, 'another passphrase');

      expect((await wallet.listPersonas()).map((p) => p.did)).not.toContain(persona.did);
      expect(await wallet.getActivePersona()).toBeNull();
    },
    KDF_TIMEOUT_MS,
  );

  it(
    '不正な persistPassword（空文字）は seed 差し替え前に 1031 で拒否され、ペルソナも残る',
    async () => {
      const { wallet, persona } = await walletWithPersonaOf(MNEMONIC_A);

      await expect(
        wallet.importMnemonic(MNEMONIC_B, undefined, undefined, { persistPassword: '' }),
      ).rejects.toMatchObject({ code: '1031' });

      expect((await wallet.listPersonas()).map((p) => p.did)).toEqual([persona.did]);
    },
    KDF_TIMEOUT_MS,
  );
});
