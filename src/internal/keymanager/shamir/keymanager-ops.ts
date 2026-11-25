/**
 * `KeyManager` の SLIP-0039 バックアップ・復旧オペレーション。
 *
 * `keymanager.ts` の行数上限（CI 規約: 1 ファイル 300 行以下）に対応するための分離で、
 * KeyManager の private 状態（vault / masterSeed）は引数で受け取る。シェアのエンコード・
 * デコード自体は `shamir/index.ts` が担い、本ファイルは「分割してよいかの判定」と
 * 「復旧結果をどう永続化するか」の判断だけを持つ。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { mnemonicToSeed } from '../hd.js';

/** 判定に必要な vault の読み取り面（`MnemonicVault` の部分型）。 */
export interface ShamirVaultView {
  usesBip39Passphrase(): Promise<boolean | undefined>;
  hasPersisted(): Promise<boolean>;
}

/**
 * SLIP-0039 で分割してよいニーモニックかを検証する。
 *
 * SLIP-0039 バックアップは BIP-39 パスフレーズ（"25 番目の語"）を保持できない（シェアには
 * エントロピー＋言語タグのみを埋め込む）。パスフレーズ付きのウォレットを分割すると復旧時に
 * 別ウォレットへ着地するため、シェア作成そのものを拒否する。
 *
 * 判定は永続フラグ（`vault.usesBip39Passphrase`）を優先する。セッション上の `masterSeed` との
 * 突合だけに頼ると、「再起動 → アンロックのみ」という正規フロー（`masterSeed` は `importMnemonic`
 * でしか設定されない）で必ず失敗し、パスフレーズを使っていないウォレットでも分割できなくなる。
 * `masterSeed` が無ければフラグだけで判定する（フラグも無い旧データは拒否）。`masterSeed` があれば、
 * フラグ値に関わらず `masterSeed` と vault のニーモニックを突合し、食い違えば拒否する。
 *
 * @throws パスフレーズ使用中、判定できない場合、または有効 seed と不一致の場合（code `1011`）。
 */
export async function assertNoBip39Passphrase(
  mnemonic: string,
  vault: ShamirVaultView,
  masterSeed: Uint8Array | null,
): Promise<void> {
  const flagged = await vault.usesBip39Passphrase();
  if (flagged === true) {
    throw new VericertsError(ErrorCodes.SHAMIR_ENCODE_FAILED);
  }
  if (masterSeed === null) {
    // セッションの seed が無い（再起動後にアンロックしただけ）。フラグが「使用なし」と記録していれば
    // それを信じる。フラグ未記録（旧データ）は判定材料が無い。分割してよいか確かめられない以上、
    // 拒否する（fail-closed）。
    if (flagged === false) {
      return;
    }
    throw new VericertsError(ErrorCodes.SHAMIR_ENCODE_FAILED);
  }
  // seed があるときはフラグ値に関わらず、vault のニーモニック（パスフレーズ無し導出）と有効 seed の
  // 一致を確かめる。両者が食い違った状態（永続化の部分失敗など）で、有効 seed と無関係な
  // ニーモニックのバックアップを発行しない。
  const seedWithoutPassphrase = mnemonicToSeed(mnemonic);
  const matches =
    masterSeed.length === seedWithoutPassphrase.length &&
    masterSeed.every((byte, i) => byte === seedWithoutPassphrase[i]);
  seedWithoutPassphrase.fill(0);
  if (!matches) {
    throw new VericertsError(ErrorCodes.SHAMIR_ENCODE_FAILED);
  }
}

/** `recoverFromShamirShares` のオプションを own 限定で読んだ結果。 */
export interface ShamirRecoveryOptions {
  readonly persistPassword: string | undefined;
  readonly overwriteExisting: boolean | undefined;
}

/**
 * 復旧オプションを own 限定で読む。
 *
 * 鎖読みだと、上書きを**要求していない**呼び出しでも汚染値が `overwriteExisting` を満たし、
 * 既存ウォレットの暗号化エンベロープが攻撃者の選んだシェア由来のニーモニックで置き換わる。
 */
export function readRecoveryOptions(options?: {
  persistPassword?: string;
  overwriteExisting?: boolean;
}): ShamirRecoveryOptions {
  return {
    persistPassword:
      options === undefined ? undefined : ownProperty<string>(options, 'persistPassword'),
    overwriteExisting:
      options === undefined ? undefined : ownProperty<boolean>(options, 'overwriteExisting'),
  };
}

/**
 * 既存ウォレットを無警告で上書きしていないか確かめる。
 *
 * 旧エンベロープを残したまま `masterSeed` だけ入れ替えると、再起動時に旧ウォレットへ無警告で
 * 戻る（復旧が無かったことになる）。
 *
 * @throws 既存エンベロープがあるのに `overwriteExisting` が真でない場合（code `1043`）。
 */
export async function assertOverwriteAllowed(
  vault: ShamirVaultView,
  overwriteExisting: boolean | undefined,
): Promise<void> {
  if (overwriteExisting !== true && (await vault.hasPersisted())) {
    throw new VericertsError(ErrorCodes.MNEMONIC_ALREADY_PERSISTED);
  }
}
