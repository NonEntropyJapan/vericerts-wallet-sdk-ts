/**
 * seed 差し替え系の回帰テスト共有ヘルパ。
 *
 * 実時間に依存せず、ストレージ操作の失敗・保留をカウンタ / ゲートで決定的に制御する。
 */

import { MemoryStorage } from '../../../../storage/storage.js';
import { KeyManager } from '../../keymanager.js';

export const MNEMONIC_A =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
export const MNEMONIC_B =
  'legal winner thank year wave sausage worth useful legal winner thank yellow';
export const PW_A = 'pw-A-correct';
export const PW_B = 'pw-B-correct';
export const ETH_PATH = "m/44'/60'/0'/0/0";
/** 最小許可 argon2id（テスト高速化）。 */
export const MIN_ARGON2ID = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 } as const;

export type StorageOp = 'set' | 'delete';

/** 操作ログ・失敗注入・保留（ゲート）を備えたメモリ storage。 */
export class ControlledStorage extends MemoryStorage {
  /** 実行を開始した書込系操作（`set:<key>` / `delete:<key>`）の履歴。 */
  readonly started: string[] = [];
  /** 真を返した操作は reject する（quota 超過の模擬）。 */
  failWhen: (op: StorageOp, key: string, nth: number) => boolean = () => false;
  /** 設定中は書込系操作がこの Promise の解決まで保留される。 */
  gate: Promise<void> | null = null;
  private writeCount = 0;

  override async set(key: string, value: Uint8Array): Promise<void> {
    await this.beforeWrite('set', key);
    await super.set(key, value);
  }

  override async delete(key: string): Promise<void> {
    await this.beforeWrite('delete', key);
    await super.delete(key);
  }

  private async beforeWrite(op: StorageOp, key: string): Promise<void> {
    this.started.push(`${op}:${key}`);
    this.writeCount += 1;
    if (this.gate !== null) {
      await this.gate;
    }
    if (this.failWhen(op, key, this.writeCount)) {
      throw new Error('quota exceeded');
    }
  }

  /** 条件に最初に一致した書込 1 回だけを失敗させる（ロールバック書込は成功する）。 */
  failOnce(match: (op: StorageOp, key: string) => boolean): void {
    let fired = false;
    this.failWhen = (op, key) => {
      if (fired || !match(op, key)) {
        return false;
      }
      fired = true;
      return true;
    };
  }

  /** 書込カウンタ・履歴を初期化する（失敗注入の起点をそろえる）。 */
  resetCounters(): void {
    this.started.length = 0;
    this.writeCount = 0;
  }
}

export function newKeyManager(storage: ControlledStorage = new ControlledStorage()): {
  km: KeyManager;
  storage: ControlledStorage;
} {
  return { km: new KeyManager({ kdf: MIN_ARGON2ID, storage }), storage };
}

/** 外から解決できる Promise。 */
export function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** microtask / macrotask を十分に回し、保留中の非同期処理を進める（ゲート解放前の状態確認用）。 */
export async function settle(): Promise<void> {
  for (let i = 0; i < 20; i += 1) {
    await new Promise<void>((r) => setTimeout(r, 0));
  }
}

export function allZero(bytes: Uint8Array): boolean {
  return bytes.every((b) => b === 0);
}
