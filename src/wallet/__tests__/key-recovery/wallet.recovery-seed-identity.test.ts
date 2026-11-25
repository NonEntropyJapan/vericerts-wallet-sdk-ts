/**
 * 復旧 3 経路（importRecoveredWallet / recoverFromShamirShares / importMnemonic）の seed 差し替え判定の
 * 回帰テスト。
 *
 * - 同一 seed の再復旧ではペルソナ・アクティブ指定・Pseudonym 破棄マーカー・ウォレット id を保つ。
 * - ペルソナメタデータが破損していても、別 seed への差し替えでは中断せず旧状態を掃除する。
 * - 不正ニーモニック（1001）は Passkey 作成・PIN 設定より前に拒否する。
 * - seed 差し替えで EudiFacade のメモリ保持 PID/EAA/WUA も破棄する。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { createRecordCatalogueSource, PID_VCT } from '../../../internal/eudi/pid/index.js';
import { makeWuaJwt } from '../../../internal/eudi/wua/__tests__/wua-fixtures.js';
import { KDF_TIMEOUT_MS } from '../../../internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import type { KdfParams } from '../../../internal/keymanager/kdf.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { Wallet } from '../../types.js';
import {
  buildSdJwtVc,
  CATALOGUE_ENTRY,
  createStub,
  EAA_CLAIMS,
  EAA_VCT,
  offerURI,
  requestURI,
  VALID_PID_CLAIMS,
} from '../eudi/eudi-fixtures.js';
import {
  codeOf,
  nowSeconds,
  PROVIDER_JWK,
  PROVIDER_KEY,
  WUA_ENDPOINT,
  wuaRoutes,
} from '../eudi/wua-fixtures.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const MNEMONIC_A =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const MNEMONIC_B = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const PASSWORD = 'wallet password';
const MIN_ARGON2ID: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };
const MARKER_KEY = 'pseudonym-discarded/marker';

async function walletWithPersonaOf(mnemonic: string) {
  const storage = new MemoryStorage();
  const wallet = await createWallet({ storage, kdf: MIN_ARGON2ID });
  await wallet.importMnemonic(mnemonic, undefined, undefined, { persistPassword: PASSWORD });
  const persona = await wallet.createPersona({ index: 0 });
  await wallet.setActivePersona(persona.id);
  await storage.set(MARKER_KEY, new TextEncoder().encode('{}'));
  return { storage, wallet, persona };
}

async function walletIdOf(storage: MemoryStorage): Promise<string> {
  const bytes = await storage.get('wallet/metadata');
  const record: unknown = JSON.parse(new TextDecoder().decode(bytes ?? new Uint8Array()));
  if (typeof record !== 'object' || record === null || !('id' in record)) {
    throw new Error('wallet/metadata has no id');
  }
  return String(record.id);
}

async function sharesOf(mnemonic: string) {
  const donor = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
  await donor.importMnemonic(mnemonic, undefined, undefined, { persistPassword: PASSWORD });
  return (await donor.createShamirShares(2, 3)).shares;
}

describe('同一 seed の再復旧ではペルソナ等を保つ', () => {
  it('importRecoveredWallet(同一ニーモニック, overwriteExisting)', async () => {
    const { storage, wallet, persona } = await walletWithPersonaOf(MNEMONIC_A);
    const before = await walletIdOf(storage);

    const result = await wallet.importRecoveredWallet(MNEMONIC_A, {
      walletPassword: PASSWORD,
      newPin: '123456',
      newPasskey: false,
      overwriteExisting: true,
    });

    expect((await wallet.listPersonas()).map((p) => p.did)).toEqual([persona.did]);
    expect((await wallet.getActivePersona())?.did).toBe(persona.did);
    expect(await storage.get(MARKER_KEY)).not.toBeNull();
    expect(await walletIdOf(storage)).toBe(before);
    expect(result.walletId).toBe(before);
  });

  it('recoverFromShamirShares(同一 seed のシェア, overwriteExisting)', async () => {
    const { storage, wallet, persona } = await walletWithPersonaOf(MNEMONIC_A);
    const before = await walletIdOf(storage);
    const shares = await sharesOf(MNEMONIC_A);

    const result = await wallet.recoverFromShamirShares(shares.slice(0, 2), {
      persistPassword: PASSWORD,
      overwriteExisting: true,
    });

    expect(result.status).toBe('success');
    expect((await wallet.listPersonas()).map((p) => p.did)).toEqual([persona.did]);
    expect((await wallet.getActivePersona())?.did).toBe(persona.did);
    expect(await storage.get(MARKER_KEY)).not.toBeNull();
    expect(await walletIdOf(storage)).toBe(before);
  });

  it('別 seed のシェアではペルソナを掃除する', async () => {
    const { storage, wallet } = await walletWithPersonaOf(MNEMONIC_A);
    const shares = await sharesOf(MNEMONIC_B);

    await wallet.recoverFromShamirShares(shares.slice(0, 2), {
      persistPassword: PASSWORD,
      overwriteExisting: true,
    });

    expect(await wallet.listPersonas()).toEqual([]);
    // 回帰テスト: Pseudonym 破棄マーカーは残す。キーは RP 単位で seed を含まず、GDPR の
    // 同意撤回の記録である。消すとパスフレーズの打ち間違いのような取り消せるはずの操作で撤回が
    // 巻き戻り、撤回した RP 向けの Pseudonym が再び提示可能になる。残しても拒否側にしか倒れない。
    expect(await storage.get(MARKER_KEY)).not.toBeNull();
  });
});

// 回帰テスト: パスフレーズの打ち間違いは別ウォレットへの差し替えとして扱われるが、
// `importMnemonic` には上書きガードが無く、取り消せる操作のはずである。Pseudonym 破棄マーカーまで
// 消すと、正しいニーモニックで入れ直しても GDPR の同意撤回が戻らず、撤回した RP 向けの Pseudonym
// （seed + RP から決定的に導出される）が再び提示可能になる。
describe('パスフレーズの打ち間違いで同意撤回を失わない', () => {
  it('打ち間違い → 正しい入れ直しのあとも Pseudonym 破棄マーカーが残る', async () => {
    const { storage, wallet } = await walletWithPersonaOf(MNEMONIC_A);

    // パスフレーズ違いは別 seed として扱われ、ペルソナは掃除される。
    await wallet.importMnemonic(MNEMONIC_A, 'typo', undefined, { persistPassword: PASSWORD });
    expect(await wallet.listPersonas()).toEqual([]);
    expect(await storage.get(MARKER_KEY)).not.toBeNull();

    // 正しく入れ直す。
    await wallet.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PASSWORD });

    expect(await storage.get(MARKER_KEY)).not.toBeNull();
  });
});

describe('破損ペルソナメタデータでも seed 差し替えの掃除を中断しない', () => {
  it('importMnemonic(別ニーモニック) が resolve し、persona/ 配下が空になる', async () => {
    const { storage, wallet, persona } = await walletWithPersonaOf(MNEMONIC_A);
    await storage.set(`persona/${persona.id}`, new TextEncoder().encode('{broken'));
    await expect(wallet.listPersonas()).rejects.toMatchObject({ code: '2005' });

    await wallet.importMnemonic(MNEMONIC_B);

    expect(await storage.list('persona/')).toEqual([]);
    expect(await wallet.getActivePersona()).toBeNull();
  });
});

describe('不正ニーモニックは副作用より前に 1001 で拒否する', () => {
  it('createPasskey / setPin が一度も呼ばれない', async () => {
    const { wallet } = await walletWithPersonaOf(MNEMONIC_A);
    const calls: string[] = [];

    await expect(
      wallet.importRecoveredWallet('not a valid mnemonic at all', {
        walletPassword: PASSWORD,
        newPin: '123456',
        overwriteExisting: true,
        createPasskey: async () => {
          calls.push('createPasskey');
        },
        setPin: async () => {
          calls.push('setPin');
        },
      }),
    ).rejects.toMatchObject({ code: '1001' });
    expect(calls).toEqual([]);
  });
});

describe('seed 差し替えで EudiFacade のメモリ保持 Credential を破棄する', () => {
  const seedReplacements: ReadonlyArray<[string, (wallet: Wallet) => Promise<unknown>]> = [
    [
      'importRecoveredWallet',
      (wallet) =>
        wallet.importRecoveredWallet(MNEMONIC_B, {
          walletPassword: PASSWORD,
          newPin: '123456',
          newPasskey: false,
          overwriteExisting: true,
        }),
    ],
    [
      'recoverFromShamirShares',
      async (wallet) =>
        wallet.recoverFromShamirShares((await sharesOf(MNEMONIC_B)).slice(0, 2), {
          persistPassword: PASSWORD,
          overwriteExisting: true,
        }),
    ],
    ['importMnemonic(別 seed)', (wallet) => wallet.importMnemonic(MNEMONIC_B)],
  ];

  async function walletHoldingPidAndWua() {
    const now = nowSeconds();
    const jwt = makeWuaJwt(PROVIDER_KEY, { iat: now - 60, exp: now + 3_600 });
    const stub = createStub(
      buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS),
      wuaRoutes(() => jwt),
    );
    const storage = new MemoryStorage();
    const wallet = await createWallet({
      storage,
      kdf: MIN_ARGON2ID,
      eudiFetchImpl: stub.fetchImpl,
      walletProviderJwk: PROVIDER_JWK,
    });
    await wallet.importMnemonic(MNEMONIC_A);
    const persona = await wallet.createPersona({ index: 0 });
    await wallet.setActivePersona(persona.id);
    await wallet.receivePID(offerURI());
    await wallet.obtainWalletAttestation(WUA_ENDPOINT);
    return { wallet, stub };
  }

  it.each(seedReplacements)('%s: 旧 PID と WUA を提示・返却しない', async (_name, replace) => {
    const { wallet, stub } = await walletHoldingPidAndWua();
    expect(wallet.getWalletAttestation()).not.toBeNull();

    await replace(wallet);

    expect(wallet.getWalletAttestation()).toBeNull();
    const callsBefore = stub.calls.length;
    expect(await codeOf(() => wallet.presentPID(requestURI(), ['family_name']))).toBe('8035');
    expect(stub.calls).toHaveLength(callsBefore);
  });

  it.each(seedReplacements)('%s: 旧 (Q)EAA を提示しない', async (_name, replace) => {
    const stub = createStub(buildSdJwtVc(EAA_VCT, EAA_CLAIMS));
    const wallet = await createWallet({
      storage: new MemoryStorage(),
      kdf: MIN_ARGON2ID,
      eudiFetchImpl: stub.fetchImpl,
      eudiCatalogue: createRecordCatalogueSource({ [EAA_VCT]: CATALOGUE_ENTRY }),
    });
    await wallet.importMnemonic(MNEMONIC_A);
    const persona = await wallet.createPersona({ index: 0 });
    await wallet.setActivePersona(persona.id);
    await wallet.receiveEAA(offerURI(EAA_VCT));

    await replace(wallet);
    // 掃除でアクティブペルソナも消えるため、提示依存の解決（2005）に阻まれないよう作り直す。
    await wallet.setActivePersona((await wallet.createPersona({ index: 0 })).id);

    expect(await codeOf(() => wallet.presentEAA(requestURI(), EAA_VCT))).toBe('8035');
  });

  it('同一 seed の importMnemonic では保持 PID を残す', async () => {
    const { wallet } = await walletHoldingPidAndWua();

    await wallet.importMnemonic(MNEMONIC_A);

    expect(wallet.getWalletAttestation()).not.toBeNull();
  });
});
