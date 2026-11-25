/**
 * Wallet で Token Status List を解決し、Fail-open 判定を監査ログに記録するための API。
 */

import type { StatusListResolver } from '../../internal/credential/index.js';
import type { StatusListResolverOptions } from '../../internal/issuer/index.js';

/**
 * `StatusApi.createStatusListResolver` のオプション。
 *
 * `StatusListResolverOptions` のうち、Wallet では `onPolicyEvent` の指定を省略できる。
 * 既定の記録先は Wallet の Dashboard ログ。独自の監査記録先を使う場合は `onPolicyEvent` を指定する。
 */
export type CreateStatusListResolverOptions = Omit<StatusListResolverOptions, 'onPolicyEvent'> & {
  readonly onPolicyEvent?: StatusListResolverOptions['onPolicyEvent'];
};

/** Token Status List の解決器を生成する API。 */
export interface StatusApi {
  /**
   * `StatusListResolver` を生成する。
   *
   * `onPolicyEvent` を省略すると、Fail-open 判定（FO-1 / FO-2）をアクティブペルソナの鍵で
   * 署名し、Wallet の Dashboard ログに追記する。署名鍵は解決器の生成時に取得するため、
   * アクティブペルソナが未設定の場合は生成時に `2005`（`PERSONA_NOT_FOUND`）で失敗する。
   *
   * @param opts `fetchToken` / `issuerPublicKey` / `purpose` 等（`onPolicyEvent` のみ任意）。
   * @returns 生成済みの `StatusListResolver`。
   */
  createStatusListResolver(opts: CreateStatusListResolverOptions): Promise<StatusListResolver>;
}
