/**
 * Entity Configuration 取得失敗時の Fail-open 判定（FO-6。`resolveFailOpen` ゲートへの唯一の配線）。
 *
 * `status-list-fail-open.ts` と同じ構造・同じオプション読み取り規律（own 限定）で、
 * 判定そのもの（override / 時間上限 / 同意 / 監査記録）は `resolveFailOpen` に委ねる。
 *
 * ## FO-1 に相当する分岐を持たない
 *
 * Status List は「ビットを確認できなくても失効していないとみなす」既定があるため、キャッシュを
 * 一切持たない取得失敗にも FO-1 という通過経路がある。Entity Configuration にはそれが無い
 * （Statement が無ければ信頼してよいクレームが 1 つも無い）。したがって stale なキャッシュが
 * 無い場合は `resolveFailOpen` を**呼ばない**。監査記録も時間上限ウィンドウの消費も発生させず、
 * 元の取得失敗（`5011 FEDERATION_FETCH_FAILED`）をそのまま伝播する。
 *
 * ## 適用範囲は Entity Configuration だけ
 *
 * 本モジュールを使うのは `entity-configuration.ts` のみである。Subordinate Statement の取得失敗
 * （`subordinate.ts`）は鍵無効化宣言 `revoked_keys` を運ぶため fail-closed のままとする
 * （FC-11 / `5012 FEDERATION_KEY_REVOKED`）。古い Subordinate Statement を stale
 * キャッシュから差し戻せるようにすると、鍵漏洩後の宣言伝播をそのまま止めてしまう。
 */

import type {
  FailOpenWindow,
  FailSafeAuditContext,
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafePolicy,
  FailSafeWarning,
} from '../../../failsafe-policy/index.js';
import { resolveFailOpen } from '../../../failsafe-policy/index.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../../prototype-safety/own-property.js';
import type { StatementFetchFailure, StatementFetchFailureHook } from './fetch-failure.js';

/**
 * FO-6 に関わる依存注入（すべて任意）。`ResolveEntityConfigurationDeps` がこれを継承する。
 *
 * `failOpenWindow` を渡さない限り FO-6 は一切発動しない（従来と同じ fail-closed）。
 */
export interface EntityConfigurationFailOpenDeps {
  /** FO-6 の override。未指定時は同意・監査の条件を満たせば警告付きで続行できる。 */
  readonly failSafePolicy?: FailSafePolicy;
  /** UI 警告と同意取得のコールバック。未指定なら同意不能 ＝ fail-closed。 */
  readonly requestConsent?: (decision: FailSafeDecision) => boolean | Promise<boolean>;
  /** 監査ログの記録先。未指定なら記録を残せないため FO-6 は成立しない。 */
  readonly onPolicyEvent?: (record: FailSafeAuditRecord) => void | Promise<void>;
  /** 監査レコードへ付与する相関情報。 */
  readonly auditContext?: FailSafeAuditContext;
  /**
   * FO-6 の時間上限を管理するウィンドウ。**未指定なら FO-6 は発動しない。**
   *
   * `createFailOpenWindow()` で生成し、複数回の `resolveEntityConfiguration` / `buildTrustChain`
   * 呼び出しにまたがって**同じインスタンスを注入する**こと。`resolveEntityConfiguration` は
   * 呼び出しごとに完結する関数であり自前で計時を保持できないため、呼び出しごとに生成すると
   * 失敗のたびに新しい猶予期間が開き、時間上限が実質無効化される。
   */
  readonly failOpenWindow?: FailOpenWindow;
}

/** 1 回の `resolveEntityConfiguration` に配線する FO-6 の一式。 */
export interface EntityConfigurationFailOpen {
  /** `resolveCachedStatement` のリクエストへ混ぜるフック（FO-6 無効時は空オブジェクト）。 */
  readonly hook: { readonly onFetchFailure?: StatementFetchFailureHook };
  /**
   * 取得関数を包み、成功したら計時ウィンドウを破棄する。FO-6 無効時は素通しする。
   *
   * 破棄しないと、一度 fail-open を許した対象は障害から復旧しても古い計時を持ち続け、次の障害で
   * 直ちに上限超過（fail-closed）と判定されてしまう。
   */
  trackFetch(fetchJwt: () => Promise<string>): () => Promise<string>;
  /** FO-6 で通過した場合の警告（成立しなければ `undefined`）。 */
  warning(): FailSafeWarning | undefined;
}

/**
 * Entity Configuration の取得失敗に対して FO-6 を許可してよいか判定する。
 *
 * @param deps ポリシー・同意・監査記録先（呼び出し側が渡した依存）。
 * @param window 時間上限を管理するウィンドウ。
 * @param key well-known URL（計時キー。監査レコードには出さない）。
 * @param failure 取得失敗の文脈（stale な JWT の有無と現在時刻）。
 * @returns 許可された場合の警告。stale な JWT が無い / 許可されない場合は `undefined`。
 */
async function decideFetchFailure(
  deps: EntityConfigurationFailOpenDeps,
  window: FailOpenWindow,
  key: string,
  failure: StatementFetchFailure,
): Promise<FailSafeWarning | undefined> {
  if (failure.staleJwt === undefined) {
    // 再利用できる実データが無い。FO-1 相当の通過経路は Entity Configuration には存在しない。
    return undefined;
  }
  // 任意プロパティは自身のプロパティに限って読む。継承値を新しいオブジェクト
  // リテラルへ詰め直すと own プロパティに化け、ゲート側（`failsafe-policy/gate.ts`）の own 限定
  // 読み取りが無意味になる。その結果、fail-safe オプションを一切渡していない呼び出しでも
  // Entity Configuration の取得失敗が stale なキャッシュで通過し、監査レコードが攻撃者の
  // シンクへ渡る。未設定のキーはプロパティ自体を生やさないよう条件付き展開で落とす。
  const policy = ownProperty<FailSafePolicy>(deps, 'failSafePolicy');
  const requestConsent = ownProperty<EntityConfigurationFailOpenDeps['requestConsent']>(
    deps,
    'requestConsent',
  );
  const onPolicyEvent = ownProperty<EntityConfigurationFailOpenDeps['onPolicyEvent']>(
    deps,
    'onPolicyEvent',
  );
  const auditContext = ownProperty<FailSafeAuditContext>(deps, 'auditContext');
  return resolveFailOpen({
    policyEvent: 'FO-6',
    window,
    key,
    nowSeconds: failure.nowSeconds,
    ...(policy !== undefined ? { policy } : {}),
    ...(requestConsent !== undefined ? { requestConsent } : {}),
    ...(onPolicyEvent !== undefined ? { onPolicyEvent } : {}),
    ...(auditContext !== undefined ? { auditContext } : {}),
  });
}

/**
 * 1 回の Entity Configuration 解決に対する FO-6 の配線を生成する。
 *
 * `failOpenWindow` が注入されていなければフックを生やさない。フックが無ければ
 * `resolveCachedStatement` は従来どおり取得失敗をそのまま送出するため、FO-6 は完全に不活性で
 * ある。同意取得と監査記録のコールバックも明示的に指定する必要がある。
 *
 * @param deps FO-6 に関わる依存注入。
 * @param key well-known URL（計時キー）。
 * @returns フック・ウィンドウ破棄・警告取得をまとめた配線。
 */
export function createEntityConfigurationFailOpen(
  deps: EntityConfigurationFailOpenDeps,
  key: string,
): EntityConfigurationFailOpen {
  // ウィンドウはクラスインスタンスであり得るため `Object.prototype` 由来だけを弾く
  // （`failsafe-policy/gate.ts` と同じ読み方。汚染値で FO-6 が無言で有効化されるのを防ぐ）。
  // 形状も検証する（`schema-validation/fail-safe.ts` の `resolveWindow` と同じ規律）。
  // `allow` / `clear` を関数として持たない注入は、成功パスの `trackFetch` が
  // 無検証で `window.clear(key)` を呼んだ瞬間に生の `TypeError` を投げ、Entity Configuration
  // 取得が成功した正常系そのものを丸ごと落としてしまう。
  //
  // `deps.failOpenWindow` 自体は `nonObjectPrototypeProperty` で読むが、そこで得た `window` の
  // `allow` / `clear` を素のドットアクセスで検証すると、「読み取った後のプロパティアクセス」で
  // `Object.prototype.allow` / `.clear` の汚染を拾ってしまう（`etsi-tsl/fail-open.ts` の FO-5 で
  // 見つかったのと同一のバグクラス）。own の allow/clear を持たない不正な形状
  // （`failOpenWindow: {}`）を渡す呼び出しがあると、汚染された `Object.prototype.allow` が常に
  // `true` を返す攻撃者実装のとき fail-open の時間上限チェックが無効化される。`window.allow` /
  // `window.clear` の参照にも `nonObjectPrototypeProperty` を使う。
  const window = nonObjectPrototypeProperty<FailOpenWindow>(deps, 'failOpenWindow');
  if (
    window === null ||
    typeof window !== 'object' ||
    typeof nonObjectPrototypeProperty(window, 'allow') !== 'function' ||
    typeof nonObjectPrototypeProperty(window, 'clear') !== 'function'
  ) {
    return { hook: {}, trackFetch: (fetchJwt) => fetchJwt, warning: () => undefined };
  }
  let warning: FailSafeWarning | undefined;
  return {
    hook: {
      onFetchFailure: async (failure: StatementFetchFailure): Promise<string | undefined> => {
        warning = await decideFetchFailure(deps, window, key, failure);
        // 許可されたときだけ stale な JWT を差し出す。差し出した JWT も呼び出し元で必ず
        // 再検証される（署名・`iss`/`sub`・`exp`）ため、期限切れの Statement は通らない。
        return warning === undefined ? undefined : failure.staleJwt;
      },
    },
    trackFetch: (fetchJwt) => async (): Promise<string> => {
      const jwt = await fetchJwt();
      window.clear(key);
      return jwt;
    },
    warning: (): FailSafeWarning | undefined => warning,
  };
}
