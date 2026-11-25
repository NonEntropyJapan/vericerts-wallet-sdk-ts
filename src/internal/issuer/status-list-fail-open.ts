/**
 * Status List Token の取得失敗時の Fail-open 判定（`resolveFailOpen` ゲートへの唯一の本番配線）。
 *
 * `status-list-resolver.ts` から切り出している。ここは fail-open ゲートを呼ぶ唯一の経路であり、
 * オプションの読み取り方（own 限定かプロトタイプ鎖か）が判定結果を左右する。行数上限を圧迫
 * せずに根拠を残すため独立モジュールにした。
 */

import type { FailOpenId, FailOpenWindow, FailSafeWarning } from '../failsafe-policy/index.js';
import { resolveFailOpen } from '../failsafe-policy/index.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { StatusListResolverOptions } from './status-list-resolver.js';

/** 取得失敗時の Fail-open 判定の結果（`token` があれば stale な実データを使う FO-2）。 */
export interface FetchFailureOutcome {
  /** FO-2 で再利用する stale な Token。FO-1（stale 無し）では undefined。 */
  readonly token?: string;
  /** 検証結果へ添える警告。 */
  readonly warning: FailSafeWarning;
}

/**
 * Status List Token の取得に失敗したときの Fail-open 判定を行う。
 *
 * stale なキャッシュを持っているかで FO-1 / FO-2 を出し分けるだけで、判定そのもの（override /
 * 時間上限 / 同意 / 監査記録）は `resolveFailOpen` に委ねる。
 *
 * @param opts 解決器のオプション（ポリシー・同意・監査記録先）。
 * @param window Fail-open の時間上限を管理するウィンドウ。
 * @param uri Status List URI（計時キー。監査レコードには出さない）。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @param staleToken TTL 切れのキャッシュ済み Token（無ければ undefined）。
 * @returns 許可された場合の判定結果。許可されなければ undefined（呼び出し側は元の失敗を伝播する）。
 */
export async function decideFetchFailure(
  opts: StatusListResolverOptions,
  window: FailOpenWindow,
  uri: string,
  nowSeconds: number,
  staleToken: string | undefined,
): Promise<FetchFailureOutcome | undefined> {
  const policyEvent: FailOpenId = staleToken === undefined ? 'FO-1' : 'FO-2';
  // 任意プロパティは自身のプロパティに限って読む。ここは `resolveFailOpen` を
  // 呼ぶ**唯一の本番経路**であり、継承値を素朴に読んで新しいオブジェクトリテラルへ詰め直すと、
  // 継承値が own プロパティに化けてゲート側（`failsafe-policy/gate.ts`）の own 限定読み取りを
  // 無意味にしてしまう（`own-property.ts` の JSDoc が警告する失敗様式）。その結果、
  // fail-safe オプションを一切渡していない解決器でも Status List 取得失敗が
  // **失効未確認のまま通過**し、監査レコードが攻撃者のシンクへ渡る。
  //
  // 「未設定ならプロパティ自体を生やさない」を保つため、undefined のキーは条件付き展開で落とす。
  const policy = ownProperty<StatusListResolverOptions['failSafePolicy']>(opts, 'failSafePolicy');
  const requestConsent = ownProperty<StatusListResolverOptions['requestConsent']>(
    opts,
    'requestConsent',
  );
  const onPolicyEvent = ownProperty<StatusListResolverOptions['onPolicyEvent']>(
    opts,
    'onPolicyEvent',
  );
  const auditContext = ownProperty<StatusListResolverOptions['auditContext']>(opts, 'auditContext');
  const warning = await resolveFailOpen({
    policyEvent,
    window,
    key: uri,
    nowSeconds,
    ...(policy !== undefined ? { policy } : {}),
    ...(requestConsent !== undefined ? { requestConsent } : {}),
    ...(onPolicyEvent !== undefined ? { onPolicyEvent } : {}),
    ...(auditContext !== undefined ? { auditContext } : {}),
  });
  if (warning === undefined) {
    return undefined;
  }
  return staleToken === undefined ? { warning } : { token: staleToken, warning };
}
