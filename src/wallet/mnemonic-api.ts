/**
 * ニーモニックを取り出すためのアンロック・施錠・状態確認を提供する。
 */

/**
 * ニーモニック露出とアンロック状態の公開 API。
 *
 * `exportMnemonic` は必ずアンロックゲート（1005）を通過した後に限りニーモニックを返す（認証なしの
 * 半端な露出を作らない）。クリップボード禁止・60 秒自動非表示・スクショ警告は UI 層責務（SDK スコープ外）。
 */
export interface MnemonicApi {
  /**
   * パスワードで永続化したニーモニックを復号し、`exportMnemonic` で取り出せるようにする。
   *
   * @param password `importMnemonic`（`persistPassword`）で永続化した際と同一のパスワード。
   * @throws ニーモニック未永続（code `1042`）/ 誤パスワード・改ざん（code `1050`）/ 復号待ちの間に
   *         `lockMnemonic` 等で施錠された（code `1005`、施錠のまま）場合（VericertsError）。
   */
  unlockMnemonic(password: string): Promise<void>;
  /** ニーモニック露出用のアンロック状態を施錠する（永続エンベロープには影響しない）。 */
  lockMnemonic(): void;
  /** ニーモニック露出用にアンロック済みか。 */
  isMnemonicUnlocked(): boolean;
  /**
   * アンロック済みの BIP-39 ニーモニックを一時表示用に取り出す。
   *
   * 前提: `unlockMnemonic` でアンロック済み。クリップボード禁止・60 秒自動非表示・スクショ警告は UI 層責務。
   *
   * @returns 平文ニーモニック文字列。
   * @throws 未アンロック（code `1005`）/ ニーモニック非存在（code `1042`）の場合（VericertsError）。
   */
  exportMnemonic(): Promise<string>;
}
