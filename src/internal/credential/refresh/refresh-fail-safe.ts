/**
 * リフレッシュ失敗時に旧 VC を返せるかを `resolveFailOpen` で判定する（FO-9）。
 * 時間上限と監査記録を確認し、`refreshFailure` が `prompt`（既定）の場合はユーザーの同意も求める。
 * 条件を満たさない場合と `discard` の場合は元のエラーを送出する。
 */

import {
  type FailOpenWindow,
  type FailSafeAuditContext,
  type FailSafeAuditRecord,
  type FailSafeDecision,
  type FailSafePolicy,
  resolveFailOpen,
} from '../../failsafe-policy/index.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../vc/vc.js';
import type { RefreshDependencies, RefreshOptions, RefreshResult } from './refresh.js';

/**
 * FO-9 の時間上限を数えるキーを求める（VC ID を優先し、無ければ refreshService の URL）。
 *
 * 同じ VC の失敗が同じ計時ウィンドウに入るように、VC 自身の文字列の ID を使う。
 * ID がなければサービス自身の URL を使う。どちらからもキーを取得できなければ
 * この関数は `undefined` を返す。呼び出し元は FO-9 の時間上限（60秒）を管理できないため、元のエラーを送出する。
 *
 * @returns 計時キー。own 限定で文字列として取得できない場合は `undefined`。
 */
export function resolveRefreshFailSafeKey(
  vc: VerifiableCredential,
  service: RefreshServiceConfig,
): string | undefined {
  const url = ownProperty<string>(service, 'url');
  const key = ownProperty<string>(vc, 'id') ?? url;
  return typeof key === 'string' ? key : undefined;
}

/**
 * `deps.failOpenWindow` を検証して取得する。
 *
 * window はクラスインスタンスであり得るため `Object.prototype` 由来だけを弾く（共通の
 * 規律）。形状（`allow` / `clear` が関数か）も検証する。`clear` の検証を欠くと、成功パスの
 * `clearRefreshFailSafeWindow` が無検証で `window.clear(key)` を呼んだ瞬間に生の `TypeError` を
 * 投げ、リフレッシュ成功という正常系そのものを丸ごと落としてしまう
 * （`entity-configuration-fail-open.ts` の `createEntityConfigurationFailOpen` と同じ規律）。
 *
 * `deps.failOpenWindow` 自体は `nonObjectPrototypeProperty` で読むが、そこで得た `window` の
 * `allow` / `clear` を素のドットアクセスで検証すると、own の allow/clear を持たない不正な形状
 * （`failOpenWindow: {}`）を渡す呼び出しに対して `Object.prototype.allow` / `.clear` の汚染を
 * 拾ってしまう（`etsi-tsl/fail-open.ts` の FO-5 で見つかったのと同一のバグクラス）。
 * `window.allow` / `window.clear` の参照にも `nonObjectPrototypeProperty` を使う。
 *
 * @returns 形状を満たす window。未注入 / 形状不正なら `undefined`（FO-9 を評価するまでもなく
 *          Fail-closed。`entity-configuration-fail-open.ts` と同じ明示的オプトイン）。
 */
function resolveWindow(deps: RefreshDependencies): FailOpenWindow | undefined {
  const window = nonObjectPrototypeProperty<FailOpenWindow>(deps, 'failOpenWindow');
  if (
    window === null ||
    typeof window !== 'object' ||
    typeof nonObjectPrototypeProperty(window, 'allow') !== 'function' ||
    typeof nonObjectPrototypeProperty(window, 'clear') !== 'function'
  ) {
    return undefined;
  }
  return window;
}

/**
 * リフレッシュ成功時に FO-9 の計時ウィンドウを破棄する。
 *
 * 破棄しないと、一度リフレッシュに失敗した VC は復旧後も計時が残り続け、次の障害で直ちに
 * 時間上限超過（Fail-closed）と判定されるうえ、キーが共有 `FailOpenWindow` の `maxKeys` 枠を
 * 永久に占有し他事象（FO-6 等）を誤って Fail-closed へ倒しかねない。
 *
 * `failOpenWindow` が未注入 / 形状不正なら何もしない（FO-9 自体が発動していないため破棄すべき
 * 計時も無い）。
 */
export function clearRefreshFailSafeWindow(key: string, deps: RefreshDependencies): void {
  resolveWindow(deps)?.clear(key);
}

/**
 * リフレッシュ失敗時のフォールバック（FO-9）を `resolveFailOpen` で判定する。
 *
 * - `refreshFailure: 'discard'`: `decideFailSafe` が `deny` に倒す（`policy.ts` の
 *   `deniedByOption`）。`resolveFailOpen` は監査記録なしで `undefined` を返し、本関数は元の
 *   エラーをそのまま再送出する（Fail-closed。「旧 VC を継続させない」）。
 * - `keep-old`: `decideFailSafe` が同意プロンプトを省く（`promptRequired: false`）。監査ログ記録は
 *   必須のため、`deps.onPolicyEvent` が無ければ `resolveFailOpen` 自体が `undefined` を返し
 *   Fail-closed に倒れる。
 * - 未指定 / `prompt`: 同意プロンプトを要求する。`deps.requestFailSafeConsent` が無い、または
 *   同意が得られない場合も `resolveFailOpen` が `undefined` を返し Fail-closed に倒れる。
 *
 * FO-9 を使うには、複数回の呼び出しで共有する `deps.failOpenWindow` を指定する。
 *
 * @param oldVc フォールバック対象の旧 VC。警告通過時にそのまま返す。監査レコードの `vc_id`
 *   （Wallet 内識別子）は呼び出し側が `opts.auditContext.vc_id` で明示すること。SDK 側では
 *   `vc.id`（VC の URI）から自動導出しない。
 * @param key 時間上限を数えるキー（VC ID、無ければ refreshService の URL。監査レコードには出さない）。
 * @param nowMs 現在時刻（エポックミリ秒）。
 * @throws FO-9 が成立しない場合、元の `error` をそのまま再送出する。
 */
export async function applyRefreshFailSafe(
  oldVc: VerifiableCredential,
  key: string,
  nowMs: number,
  opts: RefreshOptions,
  deps: RefreshDependencies,
  error: unknown,
): Promise<RefreshResult> {
  const window = resolveWindow(deps);
  if (window === undefined) {
    throw error;
  }
  // 任意プロパティは自身のプロパティに限って読む。継承値を拾うと、これらを
  // **省略した**正当な呼び出しが fail-open 側へ反転する（`resolveFailOpen` 自体が課す規律と同じ）。
  const policy = ownProperty<FailSafePolicy>(opts, 'failSafePolicy');
  // `auditContext`（`vc_id` を含む）は呼び出し側が用意した識別子をそのまま透過し、SDK 側では
  // 補完・導出しない。FO-1 / FO-2 / FO-6 と同じく、呼び出し側が用意した識別子をそのまま渡す。`vc.id` は
  // W3C VC の URI であり Wallet 内識別子ではないため、これを `vc_id` に代用しない。
  const auditContext = ownProperty<FailSafeAuditContext>(opts, 'auditContext');
  // 関数値 DI（own-property.ts の JSDoc）は own 限定で読んでは
  // ならない。`class Deps { onPolicyEvent(r) {…} }` のようにプロトタイプメソッドとして実装した
  // クラスベース deps を own 限定で読むと「未指定」に化け、FO-9 が無言で不活性化する。取り出した
  // 関数は元の `deps` をレシーバとして束ね直す（`this` 参照つきクラス DI を
  // 壊さないため）。
  const requestFailSafeConsentFn = nonObjectPrototypeProperty<
    RefreshDependencies['requestFailSafeConsent']
  >(deps, 'requestFailSafeConsent');
  const requestConsent =
    typeof requestFailSafeConsentFn === 'function'
      ? (decision: FailSafeDecision) => requestFailSafeConsentFn.call(deps, decision)
      : undefined;
  const onPolicyEventFn = nonObjectPrototypeProperty<RefreshDependencies['onPolicyEvent']>(
    deps,
    'onPolicyEvent',
  );
  const onPolicyEvent =
    typeof onPolicyEventFn === 'function'
      ? (record: FailSafeAuditRecord) => onPolicyEventFn.call(deps, record)
      : undefined;
  const warning = await resolveFailOpen({
    policyEvent: 'FO-9',
    window,
    key,
    nowSeconds: Math.floor(nowMs / 1000),
    ...(policy !== undefined ? { policy } : {}),
    ...(requestConsent !== undefined ? { requestConsent } : {}),
    ...(onPolicyEvent !== undefined ? { onPolicyEvent } : {}),
    ...(auditContext !== undefined ? { auditContext } : {}),
  });
  if (warning === undefined) {
    throw error;
  }
  return { credential: oldVc, refreshed: false, warning };
}
