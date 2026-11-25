/**
 * ウォレット完全復旧の公開 API。
 *
 * ニーモニックの妥当性は Passkey 作成・PIN 設定より前に検証する。Passkey を作成する場合、
 * 呼び出し側が WebAuthn の処理を `options.createPasskey` で渡す。WUA は `options.wuaProviderEndpoint`
 * 指定時に再発行する。Validator の入替（AA UserOp）、PID / (Q)EAA の再発行、Device Attestation は別途行う。
 */

/** `importRecoveredWallet` のオプション。 */
export interface ImportRecoveredWalletOptions {
  /**
   * 新しいウォレットパスワード。復元したニーモニックを封じる vault の暗号化鍵（K4）の導出元。
   *
   * **`newPin` と別に受け取るのは仕様上の要請である。** アンロック用 PIN は独立した salt を持つ
   * 検証子（verifier）専用で、K4 の導出には関与しない（代替の導出元シークレットとして読んでは
   * ならない）。
   * 6 文字の PIN を KDF 入力にすると探索空間が 10^6 程度に落ち、ストレージを入手した攻撃者の
   * オフライン総当たりの射程に入る。
   */
  readonly walletPassword: string;
  /** 新 PIN（6 文字以上、英数記号可）。検証子の設定は `setPin` に委ねる（KDF には使わない）。 */
  readonly newPin: string;
  /**
   * PIN 検証子の設定実体（SDK スコープ外のため呼び出し側が注入する。`createPasskey` と同じ方針）。
   * 省略時は PIN の形式検証のみ行い、検証子の永続化は呼び出し側の責務になる。
   */
  readonly setPin?: (pin: string) => Promise<void>;
  /**
   * 既存ウォレットを置き換える場合は `true` が必要（`recoverFromShamirShares` と同じ規律）。
   *
   * 本 API は Passkey 作成と PIN 検証子の設定を、取り消せない vault の上書きより**前**に実行する。
   * 既にウォレットが永続化されている端末で誤って呼ぶと、旧ウォレットのエンベロープだけでなく
   * PIN 検証子まで書き換わる。明示指定が無い限り `1043` で拒否する。
   */
  readonly overwriteExisting?: boolean;
  /** 新 Passkey を自動作成するか（既定 true）。 */
  readonly newPasskey?: boolean;
  /**
   * 新 Passkey 作成の実体（WebAuthn。SDK スコープ外のため呼び出し側が注入する）。
   * `newPasskey !== false` の場合は必須（未指定は Passkey 作成失敗として扱う）。
   */
  readonly createPasskey?: () => Promise<void>;
  /**
   * WUA 再発行に使う Wallet Provider Backend のエンドポイント。省略時は再発行をスキップする。
   *
   * 指定時は、ニーモニック復元後に既定ペルソナ（index 0、P-256 の did:key）を再導出してアクティブ化してから再発行する
   * （WUA 発行はアクティブペルソナの holder DID を要求するため、復元しないと新端末では必ず失敗する）。
   */
  readonly wuaProviderEndpoint?: string;
}

/** `importRecoveredWallet` の結果。 */
export interface ImportRecoveredWalletResult {
  /** ウォレットルートエンティティの ID。 */
  readonly walletId: string;
  /**
   * 復元後のウォレットが持つ EOA アドレス（EIP-55）。secp256k1 の旧ペルソナ（この端末に残っているレコード）だけが持つ。
   * 新規に作る DID は P-256 で EOA を持たないため、新しい端末へのニーモニック復旧では空配列。
   */
  readonly addresses: readonly string[];
  /** WUA を再発行したか。 */
  readonly wuaRenewed: boolean;
}

/** ウォレット完全復旧の公開 API。 */
export interface RecoveryApi {
  /**
   * ニーモニックから Wallet を再構築する。
   *
   * @param mnemonic BIP-39 12 / 24 語ニーモニック。
   * @param options ウォレットパスワード・新 PIN・Passkey 作成・WUA 再発行のオプション。
   * @throws ニーモニック検証失敗（code `1001`）、PIN ポリシー不適合（code `1031`）、
   *         Passkey 作成失敗（code `1032`）、WUA 再発行失敗（code `1033`）、
   *         `walletPassword` 欠落・非文字列（code `1031`）の場合。
   *         WUA 再発行の失敗理由が呼び出し側で対処可能なもの（ペルソナ未解決 `2005` /
   *         Wallet Provider 未設定 `10102` 等）であれば、`1033` へ潰さずそのまま伝播する。
   */
  importRecoveredWallet(
    mnemonic: string,
    options: ImportRecoveredWalletOptions,
  ): Promise<ImportRecoveredWalletResult>;
}
