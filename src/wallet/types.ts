/**
 * Wallet ファサードの公開型定義。
 *
 * 実装（`WalletImpl` / `createWallet`）は `wallet.ts`。本ファイルは `Wallet` interface のみを持つ。
 * 外部利用者向けの型の集約は `index.ts`（barrel）が担う。
 */

import type { IssueCredentialOptions, VerifiableCredential } from '../internal/credential/index.js';
import type { KeyPair } from '../internal/keymanager/keymanager.js';
import type { MnemonicLanguage, WordCount } from '../internal/keymanager/mnemonic.js';
import type {
  CreatePersonaOptions,
  ListPersonasOptions,
  PersonaMetadata,
} from '../internal/persona/types.js';
import type { AaApi } from './aa-api.js';
import type { PresentationApi } from './credential/index.js';
import type { DidApi } from './did/index.js';
import type { EudiApi } from './eudi/index.js';
import type { GdprApi } from './gdpr/index.js';
import type { MnemonicApi } from './mnemonic-api.js';
import type { ImportMnemonicOptions } from './options.js';
import type { RecoveryApi } from './recovery-api.js';
import type { ShamirApi } from './shamir-api.js';
import type { StatusApi } from './status/index.js';

/**
 * `Wallet.deriveKey` が返す公開鍵と鍵の識別情報。秘密鍵は SDK 内に保持し、
 * 署名時はこの鍵の ID を `Wallet.sign(keyID, …)` に渡す。
 */
export type WalletKeyPair = Omit<KeyPair, 'privateKey'>;

/**
 * SDK 公開ファサード。鍵管理・DID 管理・ペルソナ管理の入口を提供する。
 * `PresentationApi` で VP / SD-JWT、`DidApi` で DID の生成・解決と controller 操作を行う。
 * GDPR の権利行使は `GdprApi`、ニーモニックの取り出しは `MnemonicApi`、
 * EUDI PID / (Q)EAA は `EudiApi`、Token Status List の解決器生成は `StatusApi` が提供する。
 * `ShamirApi` で SLIP-0039 によるバックアップと復旧、`AaApi` で Validator の緊急失効、
 * `RecoveryApi` でウォレットの完全復旧を行う。
 */
export interface Wallet
  extends PresentationApi,
    DidApi,
    GdprApi,
    MnemonicApi,
    EudiApi,
    StatusApi,
    ShamirApi,
    AaApi,
    RecoveryApi {
  /**
   * 新規 BIP-39 ニーモニックを生成する（状態は変更しない。language 省略時は英語）。
   *
   * @returns 空白区切りのニーモニック文字列。
   */
  generateMnemonic(wordCount: WordCount, language?: MnemonicLanguage): string;
  /**
   * ニーモニックを検証し、導出したマスターシードを内部に設定する。
   * `options.persistPassword` 指定時は暗号化・永続化し、`exportMnemonic` で取り出せるようアンロックする。
   *
   * @param passphrase 任意のパスフレーズ（BIP-39 の "25 番目の語"）。
   * @param language ニーモニックの言語。省略時は自動判定。
   * @param options `persistPassword` 指定時に暗号化永続化＋アンロックを行う。
   * @throws ニーモニック不正（`1001`）/ 永続化要求時 storage 未設定（`1042`）の場合。
   */
  importMnemonic(
    mnemonic: string,
    passphrase?: string,
    language?: MnemonicLanguage,
    options?: ImportMnemonicOptions,
  ): Promise<void>;
  /**
   * マスターシードから BIP-32 パスで鍵を導出する。
   *
   * @param path BIP-32 導出パス（例: `m/44'/60'/0'/0/0`）。
   * @returns 導出された鍵情報（`privateKey` は含まない。署名は `sign(keyID, …)` を使う）。
   * @throws マスターシード未設定の場合（VericertsError、code `1041`）、
   *         パスが不正な場合（VericertsError、code `1040`）。
   */
  deriveKey(path: string): Promise<WalletKeyPair>;
  /**
   * 登録済み鍵で data に署名する。
   *
   * 受け取った data を keccak256 でハッシュしてから署名する。
   *
   * @param keyID 署名に使う鍵の ID。
   * @param data 署名対象データ。
   * @returns 65 バイトの recoverable 署名。
   * @throws 鍵 ID が未登録の場合（VericertsError、code `1004`）。
   */
  sign(keyID: string, data: Uint8Array): Promise<Uint8Array>;
  /**
   * パスワード由来の鍵で平文を AES-256-GCM 暗号化する。
   *
   * @param plaintext 暗号化対象の平文。
   * @param password 暗号化パスワード。
   * @returns 復号に必要な情報を内包したエンベロープ。
   */
  encrypt(plaintext: Uint8Array, password: string): Promise<Uint8Array>;
  /**
   * `encrypt` が生成したエンベロープをパスワードで復号する。
   *
   * @param ciphertext `encrypt` の出力エンベロープ。
   * @param password 暗号化時と同一のパスワード。
   * @returns 復号された平文。
   * @throws 誤パスワード・改ざん・形式不正の場合（VericertsError、code `1050`）。
   */
  decrypt(ciphertext: Uint8Array, password: string): Promise<Uint8Array>;
  /**
   * 新しいペルソナを作成する。HD 鍵をペルソナ単位の派生パスで導出し、did:key を生成・永続化する。
   *
   * @param opts 作成オプション（index 省略時は既存最大 +1 を採番、label は任意）。
   * @returns 作成されたペルソナのメタデータ。
   * @throws マスターシード未設定の場合（VericertsError、code `1041`）、
   *         同一 index のペルソナが既存の場合（VericertsError、code `2008`）。
   */
  createPersona(opts?: CreatePersonaOptions): Promise<PersonaMetadata>;
  /**
   * アクティブペルソナを切り替え、永続化する。
   *
   * @param id 切り替え先ペルソナの ID（DID 文字列）。
   * @returns 切替後のペルソナのメタデータ（`lastUsedAt` 更新済み）。
   * @throws 指定ペルソナが未存在の場合（VericertsError、code `2005`）。
   */
  setActivePersona(id: string): Promise<PersonaMetadata>;
  /**
   * 現在のアクティブペルソナを返す。
   *
   * @returns アクティブペルソナのメタデータ。未設定なら `null`。
   */
  getActivePersona(): Promise<PersonaMetadata | null>;
  /**
   * 保存済みペルソナの一覧を返す。
   *
   * @param opts フィルタ（label）・ソート（createdAt / lastUsedAt / label）オプション。
   * @returns ペルソナメタデータの配列（該当なしは空配列）。
   */
  listPersonas(opts?: ListPersonasOptions): Promise<PersonaMetadata[]>;
  /**
   * W3C VC を JWT-VC（コンパクト JWS）として発行する。
   *
   * 署名は `keyID` の登録済み鍵で行う。鍵は keymanager 内に保持したまま署名するため、
   * 生 privateKey は外部へ露出しない（`getCredentialSigner` 経由で credential に委譲）。
   *
   * @param vc 発行する W3C VC（`issuer` は発行者 DID）。
   * @param keyID 署名に使う鍵の ID（`deriveKey` が返した KeyPair の id）。
   * @param opts `iat`（発行時刻）の基準時刻。省略時は現在時刻。
   * @returns コンパクト JWT-VC 文字列（`header.payload.signature`）。
   * @throws 鍵 ID が未登録の場合（VericertsError、code `1004`）、
   *         issuanceDate / expirationDate が解釈不能な場合（code `3002`）、署名失敗の場合（code `1020`）。
   */
  issueCredential(
    vc: VerifiableCredential,
    keyID: string,
    opts?: IssueCredentialOptions,
  ): Promise<string>;
  /**
   * 保持中の秘密（マスターシード・全 KeyPair の秘密鍵）をメモリから消去する。
   *
   * storage 上の DID Document は公開情報のため消去しない。
   */
  zeroize(): void;
}
