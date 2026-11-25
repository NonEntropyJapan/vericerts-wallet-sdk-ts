/**
 * ニーモニックの暗号化永続化と「アンロック状態」を管理する内部ボールト。
 *
 * `exportMnemonic()` を成立させるための最小基盤。KeyManager 本体（facade）から
 * ファイルを分離し、行数上限（CI 規約: 1 ファイル 300 行以下）に対応する。
 *
 * 保管時とアンロック時の扱い:
 * - 平文ニーモニックは永続化しない。パスワード由来鍵（KeyManager の KDF: 既定 argon2id）で
 *   AES-256-GCM 暗号化した V2 エンベロープのみを `Storage` に保管する。暗号化・復号は KeyManager の
 *   `encrypt` / `decrypt` へ委譲し（本モジュールは鍵材料を持たない）、エンベロープの永続化とアンロック
 *   状態の一貫性のみを担う。
 * - 「アンロック状態」はアンロック基盤（PIN + 生体認証）の概念を SDK 内で表す。
 *   アンロック = パスワードで復号済みの平文ニーモニックをメモリ保持している状態。`lock()` で平文を
 *   `zeroize`（文字列は GC 任せだが参照を手放す）し施錠する。Service Worker evict / 明示 lock 後は
 *   施錠に倒れる（安全側）。
 * - `exportMnemonic()` は未アンロックなら 1005、ニーモニック未永続なら 1042 を投げる。露出は必ず
 *   アンロックゲート（1005）を通過した後に限る（認証なしの半端な露出を作らない）。
 *
 * セキュリティ上の注意:
 * - 平文ニーモニック / seed / password を例外 message / context / cause に一切含めない。
 * - 例外は KeyManager が正規化した `VericertsError` をそのまま伝播する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { Storage } from '../../storage-port.js';
import { timingSafeEqualString } from '../../timing-safe.js';

/** ボールトが暗号化エンベロープを保存する storage キー。 */
export const MNEMONIC_VAULT_KEY = 'keymanager/mnemonic-vault';

/**
 * BIP-39 パスフレーズ（"25 番目の語"）を使って import されたウォレットかを記録する storage キー。
 *
 * SLIP-0039 シェアにはパスフレーズを埋め込めないため、パスフレーズ付きウォレットを分割すると
 * 復旧時に別ウォレットへ着地する。これを検知するフラグで、`createShamirShares` が参照する。
 *
 * セッション状態（マスターシード）ではなく永続値にするのは、「再起動 → アンロックのみ」という
 * 正規フローでも判定できるようにするためである（マスターシードは `importMnemonic` でしか設定
 * されないので、アンロックだけの状態では突合できない）。
 *
 * パスフレーズ**の有無**だけを平文で持つ（値は保存しない）。エンベロープの機密性には影響しない。
 */
const MNEMONIC_PASSPHRASE_FLAG_KEY = 'keymanager/mnemonic-vault/uses-bip39-passphrase';
/** フラグ値: パスフレーズ使用あり / なし（`usesBip39Passphrase` が `'1'` を真として読む）。 */
const FLAG_USED = new TextEncoder().encode('1');
const FLAG_UNUSED = new TextEncoder().encode('0');

/**
 * `persist` / `clearPersisted` の書込が途中で失敗し、storage を元の状態へ戻すことにも失敗した。
 * storage の内容が呼び出し側のメモリ状態と一致する保証がないため、呼び出し側は秘密を破棄して
 * 施錠する（fail-closed）。`original` は最初の失敗の原因。
 */
export class VaultRollbackError extends Error {
  constructor(readonly original: unknown) {
    super('mnemonic vault rollback failed');
    this.name = 'VaultRollbackError';
  }
}

/** `key` を退避値へ戻す（`null` なら削除）。失敗しても例外にせず結果で返す。 */
async function restoreKey(
  storage: Storage,
  key: string,
  previous: Uint8Array | null,
): Promise<boolean> {
  try {
    if (previous === null) {
      await storage.delete(key);
    } else {
      await storage.set(key, previous);
    }
    return true;
  } catch {
    return false;
  }
}

/** KeyManager から委譲される暗号化・復号関数（AES-256-GCM V2 エンベロープ）。 */
export interface EnvelopeCipher {
  encrypt(plaintext: Uint8Array, password: string): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array, password: string): Promise<Uint8Array>;
}

/**
 * 暗号化ニーモニックの永続化とアンロック状態を管理するボールト。
 *
 * インスタンスはステートフル（アンロック中のみ平文ニーモニックを保持）。`storage` 未設定の場合は
 * 永続化不可のため `persist` / `exportMnemonic` は 1042 に倒れる（永続化なしでは export できない）。
 */
export class MnemonicVault {
  /** アンロック中のみ保持する平文ニーモニック。施錠 / 未アンロック時は null。 */
  private unlockedMnemonic: string | null = null;

  /**
   * @param cipher AES-256-GCM の暗号化・復号（KeyManager へ委譲）。
   * @param storage 暗号化エンベロープの永続化先。未設定時は永続化不可。
   */
  constructor(
    private readonly cipher: EnvelopeCipher,
    private readonly storage?: Storage,
  ) {}

  /** アンロック中か（メモリ上に平文ニーモニックを保持しているか）。 */
  isUnlocked(): boolean {
    return this.unlockedMnemonic !== null;
  }

  /**
   * アンロック中のニーモニックが `mnemonic` と同一か。
   *
   * 永続化なしの `importMnemonic` が、**同じウォレットの再読込**なのか**別ウォレットへの差し替え**
   * なのかを区別するために使う。前者でエンベロープを消すと、再起動後に鍵を導出するための正規フロー
   * （unlock → export → import）だけでウォレットの unlock 手段が失われる。
   *
   * 未アンロック時は `false`（判定材料が無いので「別物かもしれない」側に倒す）。比較は
   * {@link timingSafeEqualString} で行う（平文ニーモニック同士の比較なので、先頭一致長を
   * 実行時間から推測されないようにする）。
   */
  matchesUnlocked(mnemonic: string): boolean {
    return this.unlockedMnemonic !== null && timingSafeEqualString(this.unlockedMnemonic, mnemonic);
  }

  /**
   * 永続エンベロープが既に存在するか（別ウォレットで上書きしようとしていないかの判定用）。
   *
   * アンロック状態とは独立に storage を見る。復旧系 API は「既にウォレットがある端末で、別の
   * ニーモニックを無警告で流し込む」ことを防ぐためにこれを確認する。
   */
  async hasPersisted(): Promise<boolean> {
    return (await this.loadEnvelope()) !== null;
  }

  /**
   * ニーモニックを暗号化して永続化する（アンロック状態は変えない）。
   *
   * `importMnemonic`（`persistPassword` 指定時）から呼ばれ、平文を AES-256-GCM で暗号化した
   * V2 エンベロープと passphrase フラグを storage へコミットする。複数キーの書込は
   * {@link MnemonicVault.commit} の規約（ロールバック・保守的フラグ先行）に従う。成功後に呼び出し側が
   * {@link MnemonicVault.markUnlocked} で seed 切替と同じ同期区間でアンロック状態にする。
   *
   * @param mnemonic 永続化するニーモニック。
   * @param password 暗号化パスワード（PIN 等）。
   * @throws storage 未設定の場合（VericertsError、code `1042`）、暗号化失敗の場合（code `1051`）。
   *         書込失敗時は storage の元の状態へ戻して原因をそのまま投げる。戻せなかった場合は
   *         {@link VaultRollbackError}。
   */
  async persist(mnemonic: string, password: string, usesBip39Passphrase = false): Promise<void> {
    if (this.storage === undefined) {
      // 永続化先がなければ export を成立させられないため、永続化を要求された時点で 1042 とする。
      throw new VericertsError(ErrorCodes.MNEMONIC_NOT_FOUND);
    }
    const envelope = await this.cipher.encrypt(new TextEncoder().encode(mnemonic), password);
    await this.commit(this.storage, { envelope, usesBip39Passphrase });
  }

  /** 永続化済みの平文ニーモニックをアンロック状態として保持する（`persist` 成功直後の同期区間で呼ぶ）。 */
  markUnlocked(mnemonic: string): void {
    this.unlockedMnemonic = mnemonic;
  }

  /**
   * 永続化されたウォレットが BIP-39 パスフレーズ付きで import されたか。
   *
   * @returns フラグが記録されていない場合（フラグ導入前に永続化されたウォレット）は `undefined`。
   */
  async usesBip39Passphrase(): Promise<boolean | undefined> {
    if (this.storage === undefined) {
      return undefined;
    }
    const stored = await this.storage.get(MNEMONIC_PASSPHRASE_FLAG_KEY);
    if (stored === null) {
      return undefined;
    }
    return new TextDecoder().decode(stored) === '1';
  }

  /**
   * 永続化済みエンベロープをパスワードで復号し、平文ニーモニックを返す（アンロック状態は変えない）。
   *
   * アンロック基盤（PIN + 生体認証）に相当する SDK 内のアンロック操作の前半。復号を待つ間に
   * 施錠される場合があるため、アンロック状態にするかは呼び出し側が復号後に判断し
   * {@link MnemonicVault.markUnlocked} で反映する。
   *
   * @param password 永続化時と同一のパスワード。
   * @returns 復号した平文ニーモニック。
   * @throws ニーモニック未永続の場合（VericertsError、code `1042`）、
   *         誤パスワード・改ざんの場合（code `1050`）。
   */
  async decrypt(password: string): Promise<string> {
    const envelope = await this.loadEnvelope();
    if (envelope === null) {
      throw new VericertsError(ErrorCodes.MNEMONIC_NOT_FOUND);
    }
    const plaintext = await this.cipher.decrypt(envelope, password);
    const mnemonic = new TextDecoder().decode(plaintext);
    // 復号済みバイト列は文字列化後に消去する（メモリ滞留を最小化）。
    plaintext.fill(0);
    return mnemonic;
  }

  /**
   * アンロック中のニーモニックを返す（exportMnemonic の実体）。
   *
   * @returns アンロック中の平文ニーモニック。
   * @throws 未アンロックの場合（VericertsError、code `1005`）、
   *         ニーモニック未永続の場合（VericertsError、code `1042`）。
   */
  async export(): Promise<string> {
    // 露出は必ずアンロックゲート（1005）を先に通す。認証なしの半端な露出を作らない。
    if (this.unlockedMnemonic === null) {
      // 永続化されていない（1042）と未アンロック（1005）を区別する: 永続エンベロープが無ければ
      // そもそも export 対象が存在しないため 1042 を優先する。
      if ((await this.loadEnvelope()) === null) {
        throw new VericertsError(ErrorCodes.MNEMONIC_NOT_FOUND);
      }
      throw new VericertsError(ErrorCodes.KEY_LOCKED);
    }
    return this.unlockedMnemonic;
  }

  /** 施錠する。メモリ上の平文ニーモニック参照を手放す。永続エンベロープには影響しない。 */
  lock(): void {
    this.unlockedMnemonic = null;
  }

  /**
   * 永続エンベロープと BIP-39 パスフレーズ使用フラグを削除する（storage 未設定なら何もしない）。
   *
   * 永続化しない `importMnemonic` が旧ウォレットの残骸を残さないために使う。アンロック状態は変更しない。
   * 削除の途中で失敗した場合は元の状態へ戻す（`persist` と同じ規約）。
   */
  async clearPersisted(): Promise<void> {
    if (this.storage === undefined) {
      return;
    }
    await this.commit(this.storage, null);
  }

  /**
   * エンベロープとフラグ（2 キー）を「全て反映されるか、元のまま」へ寄せて書き込む。`Storage` に
   * 複数キーのトランザクションは無いため、次の規約で原子性を近似する。
   *
   * - 書込前に両キーの現在値を退避し、途中で失敗したら退避値へ戻してから元の例外を投げる。
   * - 戻す書込も失敗した場合は、storage と呼び出し側のメモリ状態を突合できないため
   *   {@link VaultRollbackError} を投げる（呼び出し側は fail-closed でメモリを破棄する）。
   * - クラッシュ（ロールバック不能）に備え、フラグは「使用あり」を先に書き、エンベロープ書込後に
   *   正しい値へ更新する。どの時点で途切れても、フラグは新旧どちらかの値か「使用あり」であり、
   *   パスフレーズ付きウォレットが SLIP-0039 分割を通る（「使用なし」のまま新 envelope が見える）窓が無い。
   *
   * @param next `null` なら両キーを削除する。
   */
  private async commit(
    storage: Storage,
    next: { envelope: Uint8Array; usesBip39Passphrase: boolean } | null,
  ): Promise<void> {
    const previousEnvelope = await storage.get(MNEMONIC_VAULT_KEY);
    const previousFlag = await storage.get(MNEMONIC_PASSPHRASE_FLAG_KEY);
    try {
      if (next === null) {
        await storage.delete(MNEMONIC_VAULT_KEY);
        await storage.delete(MNEMONIC_PASSPHRASE_FLAG_KEY);
        return;
      }
      await storage.set(MNEMONIC_PASSPHRASE_FLAG_KEY, FLAG_USED);
      await storage.set(MNEMONIC_VAULT_KEY, next.envelope);
      if (!next.usesBip39Passphrase) {
        await storage.set(MNEMONIC_PASSPHRASE_FLAG_KEY, FLAG_UNUSED);
      }
    } catch (error) {
      const restored = await restoreKey(storage, MNEMONIC_VAULT_KEY, previousEnvelope);
      const restoredFlag = await restoreKey(storage, MNEMONIC_PASSPHRASE_FLAG_KEY, previousFlag);
      if (!(restored && restoredFlag)) {
        throw new VaultRollbackError(error);
      }
      throw error;
    }
  }

  /** 永続エンベロープを取得する。storage 未設定 / 未永続なら null。 */
  private async loadEnvelope(): Promise<Uint8Array | null> {
    if (this.storage === undefined) {
      return null;
    }
    return this.storage.get(MNEMONIC_VAULT_KEY);
  }
}
