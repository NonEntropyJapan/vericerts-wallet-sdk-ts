/**
 * `KeyManager` クラス facade。
 *
 * BIP-39 ニーモニック・BIP-32 / BIP-44 HD 鍵導出（secp256k1）・SLIP-0010 P-256 鍵導出（slip10.ts）・署名・
 * AES-256-GCM 暗号化を単一のステートフルなクラスへ統合する。暗号プリミティブは各純粋関数モジュールが担い、
 * 本クラスは「マスターシード保持」「鍵レジストリ管理」「パスワード由来鍵導出＋暗号化エンベロープ」「ゼロ化」だけを
 * 持つ薄い facade に徹する。導出済み鍵はインメモリの `keys` レジストリに保持する。
 *
 * セキュリティ上の注意: seed / privateKey / password / 平文などの秘密は例外の
 * message / context / cause に一切含めない。@noble / @scure / Web Crypto 由来の例外はメッセージに秘密を
 * 含み得るため `cause` を渡さず `VericertsError` に正規化する。`zeroize()` および seed 切替
 * （`importMnemonic` / `recoverFromShamirShares`）時は、保持していた秘密（旧 seed・旧 seed 由来の導出
 * 済み鍵）を `fill(0)` で消去する。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { KeyLock } from '../primitives/key-lock.js';
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';
import type { Storage } from '../storage-port.js';
import type { CredentialSigningKey } from './credential-signer.js';
import { mnemonicToSeed } from './hd.js';
import { DEFAULT_KDF, type KdfParams } from './kdf.js';
import { canonicalizeKdfParams } from './kdf-policy.js';
import { deriveAndRegister, deriveAndRegisterP256, zeroizeRegistry } from './key-registry.js';
import { credentialSignerFor, signDigestFor, signerFor } from './live-signers.js';
import type { MnemonicLanguage, WordCount } from './mnemonic.js';
import { assertValidMnemonic, generateMnemonic as generateMnemonicFn } from './mnemonic.js';
import type { ShamirRecoveryResult, ShamirSharesResult } from './shamir/index.js';
import { createSharesResult, recoverSharesInto } from './shamir/index.js';
import {
  assertNoBip39Passphrase,
  assertOverwriteAllowed,
  readRecoveryOptions,
} from './shamir/keymanager-ops.js';
import type { RecoverableSignature } from './signer.js';
import type { KeyPair, P256KeyPair, RegisteredKeyPair, Signer } from './types.js';
import { decryptEnvelope, encryptEnvelope } from './vault/envelope-cipher.js';
import { MnemonicVault, VaultRollbackError } from './vault/mnemonic-vault.js';
import { readPersistPassword } from './vault/password-policy.js';

export type { CredentialSigningKey } from './credential-signer.js';
export type { ShamirRecoveryResult, ShamirSharesResult } from './shamir/index.js';
export type { KeyPair, P256KeyPair, Signer } from './types.js';

/** seed 切替を直列化する `KeyLock` のキー（インスタンス内で単一）。 */
const SEED_LOCK_KEY = 'seed';

/**
 * 鍵管理 facade。マスターシードを保持し、HD 鍵導出・署名・暗号化を統合提供する。
 *
 * インスタンスはステートフル（`masterSeed` と導出済み `keys` を保持）。秘密のライフサイクルを
 * 終える際は `zeroize()` を呼び、保持中の秘密をメモリから消去すること。
 */
export class KeyManager {
  /** インポート済みマスターシード（64 バイト）。未初期化時は null。 */
  private masterSeed: Uint8Array | null = null;
  /** 導出済み鍵のレジストリ（key id → 鍵ペア。secp256k1 / P-256）。 */
  private readonly keys = new Map<string, RegisteredKeyPair>();
  /** seed を切り替える全経路（import / 復旧 / unlock / バックアップ作成）を直列化するロック。 */
  private readonly seedLock = new KeyLock();
  /** `zeroize()` の実行回数。seed 切替の永続化待ちの間に zeroize されたかの検知に使う。 */
  private zeroizeCount = 0;
  /** 施錠（`zeroize()` / `lockMnemonic()`）の回数。`unlock` の復号待ち中の施錠の検知に使う。 */
  private lockCount = 0;
  /** encrypt で使用する KDF パラメータ（K4 既定は argon2id）。テスト等で注入できる DI seam。 */
  private readonly kdf: KdfParams;
  /** ニーモニックの暗号化永続化・アンロック状態を管理するボールト。 */
  private readonly vault: MnemonicVault;

  /**
   * @param options.kdf encrypt 時の KDF パラメータ。省略時は K4 既定（argon2id）。decrypt はエンベロープ内の KDF を使うため影響を受けない。
   * @param options.storage ニーモニック暗号化エンベロープの永続化先（`exportMnemonic` に必要。未設定時は永続化不可で 1042 に倒れる）。
   */
  constructor(options?: { kdf?: KdfParams; storage?: Storage }) {
    // 不正 KDF（余剰キー・範囲外・version 違反）は構築時に 1051 拒否し、
    // 正規化済みコピーを保持（外部 mutable 参照を断つ＝TOCTOU 防御）。
    // 構築時オプションも自身のプロパティに限って読む。継承した `storage` は
    // BIP-39 ニーモニックの暗号化エンベロープを**攻撃者のストレージへ書き込ませる**。
    // `storage` はメソッドを prototype に持つクラス実装が正当なため own 限定にはしない。
    const optionsObject: object = options ?? {};
    const kdfOption = ownProperty<KdfParams>(optionsObject, 'kdf');
    const storageOption = nonObjectPrototypeProperty<Storage>(optionsObject, 'storage');
    this.kdf = canonicalizeKdfParams(kdfOption ?? DEFAULT_KDF, ErrorCodes.ENCRYPT_FAILED);
    // ボールトへは暗号化・復号のみを委譲する（鍵材料はボールトに渡さない）。
    this.vault = new MnemonicVault(
      {
        encrypt: (plaintext, password) => this.encrypt(plaintext, password),
        decrypt: (ciphertext, password) => this.decrypt(ciphertext, password),
      },
      storageOption,
    );
  }

  /**
   * 新規 BIP-39 ニーモニックを生成する（状態は変更しない）。
   *
   * @param wordCount 生成する語数（12 または 24）。
   * @param language 使用する言語。省略時は英語。
   * @returns 空白区切りのニーモニック。
   */
  generateMnemonic(wordCount: WordCount, language?: MnemonicLanguage): string {
    return generateMnemonicFn(wordCount, language);
  }

  /**
   * ニーモニックを検証し、導出したマスターシードを本インスタンスに設定する。
   *
   * 永続化を**先に**コミットし、成功した場合にだけ seed を切り替える。失敗時は seed・導出済み鍵・
   * アンロック状態・永続化が元のまま reject する。切替時は旧 seed と旧 seed 由来の導出済み鍵を `fill(0)` で
   * 消去し、seed を切り替える他経路と直列化される。`persistPassword` 指定時は
   * ニーモニックを暗号化永続化してアンロック状態にする。
   *
   * @param mnemonic インポートするニーモニック。
   * @param passphrase 任意のパスフレーズ（BIP-39 の "25 番目の語"）。
   * @param language ニーモニックの言語。省略時は自動判定。
   * @param options `persistPassword` 指定時に暗号化永続化＋アンロックを行う（書込待ちの間に `lockMnemonic()` されたら施錠のまま）。
   * @throws ニーモニック不正（`1001`）、`persistPassword` が空文字・非文字列（`1031`）、永続化要求時に storage 未設定（`1042`）、永続化待ちの間に `zeroize()` された（`1005`）。
   */
  async importMnemonic(
    mnemonic: string,
    passphrase?: string,
    language?: MnemonicLanguage,
    options?: { persistPassword?: string },
  ): Promise<void> {
    assertValidMnemonic(mnemonic, language);
    // own 限定で読み、空文字・非文字列は何も変える前に拒否する。
    const persistPassword = readPersistPassword(options);
    const before = [this.zeroizeCount, this.lockCount] as const;
    await this.seedLock.run(SEED_LOCK_KEY, () =>
      this.replaceSeed(mnemonic, passphrase, language, persistPassword, before),
    );
  }

  /** `importMnemonic` の実体。`seedLock` を保持した状態で呼ぶ（ロックは再入不可）。施錠の検知は `seedLock` 取得前の回数で行う。 */
  private async replaceSeed(
    mnemonic: string,
    passphrase: string | undefined,
    language: MnemonicLanguage | undefined,
    persistPassword: string | undefined,
    [zeroizedBefore, lockedBefore]: readonly [number, number],
  ): Promise<void> {
    const seed = mnemonicToSeed(mnemonic, passphrase, language);
    try {
      if (persistPassword !== undefined) {
        // パスフレーズ使用の有無も永続化し、`createShamirShares` が分割を拒否できるようにする（SLIP-0039 は
        // パスフレーズを埋め込めない）。seed 導出（`passphrase ?? ''`）と同じ正規化で決める。
        await this.vault.persist(mnemonic, persistPassword, (passphrase ?? '') !== '');
      } else if (!this.vault.matchesUnlocked(mnemonic)) {
        // 永続化しない import は旧ウォレットのエンベロープ・フラグを残さない（旧ニーモニックの
        // 取り違え）。ただし**アンロック中の同一ニーモニックを読み直しただけ**なら消さない
        // 再起動後に鍵を導出する正規フローは unlock → export → import であり、ここで
        // 消すと同じウォレットを読み直しただけで unlock / export / Shamir 分割の手段が失われる。
        await this.vault.clearPersisted();
      }
    } catch (error) {
      seed.fill(0);
      if (error instanceof VaultRollbackError) {
        // storage を元に戻せずメモリ状態との一致を保証できない。全て破棄して施錠する（fail-closed）。
        this.zeroize();
        throw error.original;
      }
      throw error;
    }
    if (zeroizedBefore !== this.zeroizeCount) {
      // 永続化待ちの間に zeroize された。seed を復活させず施錠のままにする（永続化は完了済み）。
      seed.fill(0);
      throw new VericertsError(ErrorCodes.KEY_LOCKED);
    }
    // 永続化成功後は await を挟まず切り替える（有効 seed・鍵・アンロック露出を常に一致させる）。待ちの間の lockMnemonic は施錠を維持する。
    this.masterSeed?.fill(0);
    this.masterSeed = seed;
    zeroizeRegistry(this.keys);
    if (persistPassword !== undefined && lockedBefore === this.lockCount) {
      this.vault.markUnlocked(mnemonic);
    } else {
      this.vault.lock();
    }
  }

  /**
   * ニーモニックの暗号化エンベロープをパスワードで復号し、アンロック状態にする。
   * アンロック基盤（PIN + 生体認証）に相当する SDK 内のアンロック操作。
   *
   * @param password 永続化時と同一のパスワード。
   * @throws ニーモニック未永続の場合（VericertsError、code `1042`）、誤パスワード・改ざんの場合（code `1050`）、
   *         復号待ちの間に施錠された場合（code `1005`。平文を保持せず施錠のまま）。
   */
  async unlock(password: string): Promise<void> {
    const lockedBefore = this.lockCount;
    await this.seedLock.run(SEED_LOCK_KEY, async () => {
      const mnemonic = await this.vault.decrypt(password);
      if (lockedBefore !== this.lockCount) throw new VericertsError(ErrorCodes.KEY_LOCKED);
      this.vault.markUnlocked(mnemonic);
    });
  }

  /** ニーモニック露出用のアンロック状態を施錠する（永続エンベロープには影響しない）。 */
  lockMnemonic(): void {
    this.lockCount += 1;
    this.vault.lock();
  }

  /** ニーモニック露出用にアンロック済みか。 */
  isMnemonicUnlocked(): boolean {
    return this.vault.isUnlocked();
  }

  /**
   * アンロック済みニーモニックを一時表示用に取り出す。
   *
   * @returns 平文ニーモニック。
   * @throws 未アンロックの場合（VericertsError、code `1005`）、ニーモニック未永続の場合（code `1042`）。
   */
  async exportMnemonic(): Promise<string> {
    return this.vault.export();
  }

  /**
   * マスターシードから BIP-32 パスで secp256k1 鍵を導出し、KeyPair を組み立ててレジストリに登録する。
   *
   * @param path BIP-32 導出パス（例: `m/44'/60'/0'/0/0`）。
   * @returns レジストリ所有の KeyPair（再導出は同一オブジェクト）。`privateKey` は消去しないこと（必要ならコピーを消去する）。列挙不可の own プロパティで、JSON・列挙・`structuredClone`・Node / Bun の `util.inspect` には出ないので `.privateKey` を明示して読む。ブラウザの DevTools（`console.log`）は非列挙の own プロパティも展開しうるので、鍵ペアをそのままログへ渡さないこと。
   * @throws マスターシード未設定の場合（code `1041`）、パスが不正な場合（code `1040`）。
   */
  async deriveKey(path: string): Promise<KeyPair> {
    return deriveAndRegister(this.keys, this.masterSeed, path);
  }

  /**
   * SLIP-0010（"Nist256p1 seed"）の hardened パスで P-256 鍵（ES256）を導出し、レジストリに登録する（`slip10.ts`）。
   *
   * @param path 全 hardened の SLIP-0010 パス（`p256DidPath(index)`。本ウォレットの方針で通常の導出は拒否する）。
   * @returns レジストリ所有の P-256 鍵ペア（再導出は同一オブジェクト）。`privateKey` は消去しないこと。列挙不可の own プロパティで、JSON・列挙・`structuredClone`・Node / Bun の `util.inspect` には出ないので `.privateKey` を明示して読む。ブラウザの DevTools（`console.log`）は非列挙の own プロパティも展開しうるので、鍵ペアをそのままログへ渡さないこと。
   * @throws マスターシード未設定（code `1041`）、パスが不正・非 hardened（code `1040`）。
   */
  async deriveP256Key(path: string): Promise<P256KeyPair> {
    return deriveAndRegisterP256(this.keys, this.masterSeed, path);
  }

  /**
   * 登録済みの secp256k1 鍵（`deriveKey` が返した KeyPair の id）の Signer を返す。
   *
   * @throws 鍵 ID が未登録の場合（code `1004`）、P-256 鍵の場合（code `1030`）。
   */
  getSigner(keyId: string): Signer {
    return signerFor(this.keys, keyId);
  }

  /**
   * 登録済み鍵で「ハッシュ済みダイジェスト」に直接 recoverable 署名する（`getSigner().sign` と異なり keccak256 を
   * 再適用しない。UserOpHash 等の用途向け）。鍵 ID が未登録なら `1004`、P-256 鍵なら `1030`。
   */
  signRawDigest(keyId: string, digest: Uint8Array): RecoverableSignature {
    return signDigestFor(this.keys, keyId, digest);
  }

  /**
   * 登録済み鍵に紐づく JWS 署名鍵（`CredentialSigningKey`）を、生 privateKey を渡さずに返す。
   * secp256k1 鍵は `ES256K`、P-256 鍵は `ES256`（`live-signers.ts`）。
   *
   * @throws 鍵 ID（`deriveKey` / `deriveP256Key` が返した鍵ペアの id）が未登録の場合（code `1004`）。
   */
  getCredentialSigner(keyId: string): CredentialSigningKey {
    // 署名鍵の構築・signing-input の SHA-256 署名は credential-signer.ts へ委譲する。
    return credentialSignerFor(this.keys, keyId);
  }

  /** パスワード由来の鍵で平文を AES-256-GCM 暗号化し、自己完結な V2 エンベロープを返す（詳細: {@link encryptEnvelope}）。失敗は `1051`。 */
  async encrypt(plaintext: Uint8Array, password: string): Promise<Uint8Array> {
    return encryptEnvelope(this.kdf, plaintext, password);
  }

  /** `encrypt` が生成した V2 エンベロープをパスワードで復号する（詳細: {@link decryptEnvelope}）。失敗は `1050`。 */
  async decrypt(ciphertext: Uint8Array, password: string): Promise<Uint8Array> {
    return decryptEnvelope(ciphertext, password);
  }

  /**
   * K1 を SLIP-0039 でシェア分割する。
   * パスフレーズ付きは別ウォレットへ復元されるため拒否する（判定は shamir/keymanager-ops.ts）。
   */
  async createShamirShares(threshold: number, total: number): Promise<ShamirSharesResult> {
    return this.seedLock.run(SEED_LOCK_KEY, async () => {
      const mnemonic = await this.vault.export();
      await assertNoBip39Passphrase(mnemonic, this.vault, this.masterSeed);
      return createSharesResult(mnemonic, threshold, total);
    });
  }

  /** 既存ウォレットを無警告で置き換えていないかを確かめる（復旧系 API 共通のガード。理由は shamir/keymanager-ops.ts）。`1043` を投げ得る。 */
  async assertMnemonicOverwriteAllowed(overwriteExisting: boolean | undefined): Promise<void> {
    await this.seedLock.run(SEED_LOCK_KEY, () =>
      assertOverwriteAllowed(this.vault, overwriteExisting),
    );
  }

  /**
   * SLIP-0039 シェアから K1 を再構成する。
   * `persistPassword` 未指定なら復旧結果は `masterSeed` にしか残らない。既存エンベロープがあるのに
   * `overwriteExisting` が真でなければ `1043`（検査から seed 切替までを `seedLock` 下の同一区間で行う）。
   */
  async recoverFromShamirShares(
    shares: readonly string[],
    options?: { persistPassword?: string; overwriteExisting?: boolean },
  ): Promise<ShamirRecoveryResult> {
    const { persistPassword, overwriteExisting } = readRecoveryOptions(options);
    const before = [this.zeroizeCount, this.lockCount] as const;
    return this.seedLock.run(SEED_LOCK_KEY, async () => {
      await assertOverwriteAllowed(this.vault, overwriteExisting);
      return recoverSharesInto(shares, (mnemonic) => {
        assertValidMnemonic(mnemonic);
        const password = readPersistPassword({ persistPassword });
        return this.replaceSeed(mnemonic, undefined, undefined, password, before);
      });
    });
  }

  /**
   * 保持中の秘密（マスターシード・全 KeyPair の秘密鍵・アンロック中ニーモニック）をメモリから
   * 消去し、レジストリを空にする。永続エンベロープ（storage）は消さない。
   */
  zeroize(): void {
    this.zeroizeCount += 1;
    this.masterSeed?.fill(0);
    this.masterSeed = null;
    zeroizeRegistry(this.keys);
    // アンロック中の平文ニーモニック参照を手放す（施錠）。
    this.lockMnemonic();
  }
}
