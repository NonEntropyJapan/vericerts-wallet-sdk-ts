/**
 * `WalletOptions.onWarning`の結線。Wallet が作る Dashboard ログの失敗が、指定した `onWarning` に届く。
 * 未指定のときは従来どおり何も出ない。
 */

import { describe, expect, it } from 'bun:test';
import { createWallet, MemoryStorage, type SdkWarning, type WalletOptions } from '../../index.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

class AnchorWriteFailingStorage extends MemoryStorage {
  override async set(key: string, value: Uint8Array): Promise<void> {
    if (key.startsWith('anchor/')) {
      throw new Error('anchor write failed');
    }
    return super.set(key, value);
  }
}

async function disputeOnce(options: WalletOptions = { storage: new AnchorWriteFailingStorage() }) {
  const wallet = await createWallet(options);
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  await wallet.storeCredential({
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id: 'vc-1',
  });
  await wallet.markCredentialDisputed('vc-1', '氏名が誤っている');
}

describe('createWallet({ onWarning })', () => {
  it('Dashboard ログの末尾アンカーが書けなかったとき onWarning が呼ばれ、操作は成功する', async () => {
    const warnings: SdkWarning[] = [];

    await disputeOnce({
      storage: new AnchorWriteFailingStorage(),
      onWarning: (warning) => warnings.push(warning),
    });

    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings.every((w) => w.code === 'dashboard_log.tail_anchor_write_failed')).toBe(true);
  });

  it('onWarning を指定しなければ従来どおり（操作は成功し、何も出ない）', async () => {
    await expect(disputeOnce()).resolves.toBeUndefined();
  });

  it('prototype メソッドを元 options の receiver で呼ぶ', async () => {
    class Options implements WalletOptions {
      readonly storage = new AnchorWriteFailingStorage();
      readonly #warnings: SdkWarning[] = [];
      onWarning(warning: SdkWarning): void {
        this.#warnings.push(warning);
      }
      get warnings(): readonly SdkWarning[] {
        return this.#warnings;
      }
    }
    const options = new Options();
    await disputeOnce(options);
    expect(options.warnings.length).toBeGreaterThan(0);
  });

  it('onWarning getter は 1 回だけ読み、受け口の receiver と戻り値を保持する', async () => {
    let reads = 0;
    const warnings: SdkWarning[] = [];
    const options = {
      storage: new AnchorWriteFailingStorage(),
      get onWarning() {
        reads += 1;
        if (reads > 1) throw new Error('getter read twice');
        return function (this: WalletOptions, warning: SdkWarning) {
          expect(this).toBe(options);
          warnings.push(warning);
          return Promise.reject(new Error('async sink failed'));
        };
      },
    };
    await disputeOnce(options);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(reads).toBe(1);
    expect(warnings.length).toBeGreaterThan(0);
  });

  it('own undefined は prototype の callback を覆い隠す', async () => {
    let calls = 0;
    const options = Object.assign(
      Object.create({
        onWarning() {
          calls += 1;
        },
      }),
      {
        storage: new AnchorWriteFailingStorage(),
        onWarning: undefined,
      },
    );
    await disputeOnce(options);
    expect(calls).toBe(0);
  });

  it('Object.prototype の callback getter は読まず採用もしない', async () => {
    let reads = 0;
    const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'onWarning');
    try {
      Object.defineProperty(Object.prototype, 'onWarning', {
        configurable: true,
        get() {
          reads += 1;
          return () => {
            throw new Error('polluted sink');
          };
        },
      });
      await disputeOnce();
      expect(reads).toBe(0);
    } finally {
      if (descriptor) Object.defineProperty(Object.prototype, 'onWarning', descriptor);
      else Reflect.deleteProperty(Object.prototype, 'onWarning');
    }
  });
});
