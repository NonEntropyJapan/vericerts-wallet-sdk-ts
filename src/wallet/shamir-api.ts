/**
 * SLIP-0039 Shamir 秘密分散によるバックアップ・復旧の公開 API。
 *
 * `Wallet` interface（`types.ts`）が継承する。K1（アンロック中のニーモニック）を
 * `threshold`-of-`total` の SLIP-0039 シェアへ分割・復元する 2 関数の対を提供する
 * （同一ライブラリ・型を共有するため 1 スコープとして扱う）。
 */

import type {
  ShamirRecoveryResult,
  ShamirSharesResult,
} from '../internal/keymanager/keymanager.js';

export type {
  ShamirRecoveryResult,
  ShamirSharesResult,
} from '../internal/keymanager/keymanager.js';

/**
 * SLIP-0039 バックアップ・復旧の公開 API。
 *
 * `createShamirShares` は `exportMnemonic` と同じアンロックゲート（1005）を認証境界として使う
 * （PIN + 生体認証の多要素認証自体は extension 層の責務で SDK スコープ外）。
 * `recoverFromShamirShares` は成功時に K1 を再構成し、本インスタンスのアクティブなマスター
 * シードへ再投入する（`importMnemonic` 相当の状態変更）。
 */
export interface ShamirApi {
  /**
   * K1 を SLIP-0039 で `threshold`-of-`total` シェアへ分割する。
   *
   * @param threshold 復旧に必要なシェア数。`2 <= threshold <= total <= 16`。
   * @param total 発行するシェア総数。
   * @throws 未アンロック（code `1005`）/ ニーモニック非存在（code `1042`）の場合、
   *         `threshold` / `total` が制約を満たさない場合（code `1015`）、
   *         SLIP-0039 エンコードに失敗した場合（code `1011`）。
   */
  createShamirShares(threshold: number, total: number): Promise<ShamirSharesResult>;
  /**
   * SLIP-0039 シェアから K1 を再構成する。
   *
   * シェア数不足・シェア不整合・チェックサム不正は例外ではなく `status` で返す
   * （`insufficient_shares` / `invalid_share`）。
   *
   * `options.persistPassword` を渡すと、再構成したニーモニックをそのパスワードで暗号化して
   * 永続化し、アンロック状態にする。**渡さない場合、復旧結果はメモリ上のマスターシードにしか
   * 残らない**（`exportMnemonic` は使えず、次回起動で復旧は失われる）。
   *
   * 既に別のニーモニックが永続化されている端末では、`options.overwriteExisting: true` が無いと
   * `1043` で拒否する。旧エンベロープを残したままマスターシードだけ入れ替えると、再起動で
   * 旧ウォレットへ無警告で戻る（復旧が無かったことになる）ため。
   *
   * @param shares 閾値以上のシェアリスト。
   * @param options 永続化パスワードと既存ウォレットの上書き許可。
   * @throws 既存エンベロープがあるのに `overwriteExisting` が真でない場合（code `1043`）、
   *         永続化要求時に storage 未設定の場合（code `1042`）。
   */
  recoverFromShamirShares(
    shares: readonly string[],
    options?: { readonly persistPassword?: string; readonly overwriteExisting?: boolean },
  ): Promise<ShamirRecoveryResult>;
}
