/**
 * ETSI TSL / LOTL 取得失敗時の Fail-open 判定（FO-5。`resolveFailOpen` ゲートへの唯一の配線）。
 *
 *
 * `federation/fail-open/entity-configuration-fail-open.ts`（FO-6）と同じ構造・同じオプション読み取り
 * 規律（own 限定）。判定そのもの（override / 時間上限 / 同意 / 監査記録）は
 * `resolveFailOpen` に委ねる。
 *
 * ## LOTL（EU 全体の Trust Anchor 一覧）を FO-6 のように除外しない理由（現行実装限定の条件付き）
 *
 * FO-6 は Trust Anchor 自身の Entity Configuration を対象外にする（無効化を宣言する「上位」が
 * Trust Anchor には存在しないため、stale なアンカーの EC を fail-open で受理すると漏洩鍵の検証を
 * そのまま許してしまう）。
 *
 * **注意**: ETSI TS 119 612 のモデル自体では LOTL の `ServiceDigitalIdentity` が各国 TSL 署名鍵の
 * 証明書を保持し、LOTL 自体が Trust Anchor として機能し得る。したがって「LOTL は加盟国 TSL の
 * 場所を指すだけで QTSP 判定を持たない」という理解は ETSI モデルの記述として不正確である
 *
 * 現行実装で LOTL を除外しなくても安全な理由は、ETSI モデルの性質ではなく**未実装であることに
 * よる**: `tsl.ts` の `extractTslPointers` は `OtherTSLPointer` から `TSLLocation` /
 * `SchemeTerritory` のみを抽出し、`ServiceDigitalIdentity`（各国 TSL 署名鍵の証明書）を一切
 * 取り出していない。署名者アンカリング（`signing-anchor/index.ts`）も
 * アンカーを**呼び出し側から受け取る**形であり LOTL 本文からは導出しない。つまり LOTL 文書は
 * 署名鍵の信頼判断に一切寄与しておらず、stale な LOTL を FO-5 で通しても影響しない。
 *
 * **`extractTslPointers` が `ServiceDigitalIdentity` を読み、LOTL 本文から各国 TSL の署名者
 * アンカーを導出するようにした時点で本節の前提は崩れる。その際は FO-6 と同様に LOTL を除外対象と
 * すべきか再判定すること。**
 *
 * ## FO-6 との違い: 「有効期限内」のキャッシュだけを対象にする
 *
 * FO-6 は Entity Statement 自身の `exp` で再検証できるため、TTL 切れの stale なキャッシュを対象に
 * する。ETSI TSL には Statement 相当の署名対象 `exp` が無く、キャッシュの TTL 自体が TSL 自身の
 * `NextUpdate` をそのまま採用している（`cache.ts`）。したがって「TTL が有効期限内」であることが
 * そのまま「TSL 自身がまだ最新だと宣言している」ことを意味し、TTL 切れのエントリまで対象に含めると
 * TSL が自ら更新を予告した期限を過ぎた情報を使い続けることになる。よって本モジュールが判定対象に
 * するのは `readTrustedListCache`（TTL 内のときだけ値を返す）で得られたエントリに限る。呼び出し側
 * （`etsi-tsl.ts`）が TTL 切れ・未格納を判別済みであることを前提とし、本モジュール自身はキャッシュの
 * 有無を問わない（呼ばれた時点で「有効期限内のキャッシュがある」ことは確定している）。
 *
 * ## キャッシュが無い/期限切れの場合は resolveFailOpen を呼ばない（呼び出し側の責務）
 *
 * FO-6 と同じ理由（Statement/TSL が無ければ信頼できるクレームが無い）。`etsi-tsl.ts` は
 * `readTrustedListCache` が `undefined` を返した時点で本モジュールを呼ばずに fail-closed とするため、
 * 監査記録もウィンドウの消費も発生しない。
 */

import type {
  FailOpenWindow,
  FailSafeAuditContext,
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafePolicy,
  FailSafeWarning,
} from '../../failsafe-policy/index.js';
import { resolveFailOpen } from '../../failsafe-policy/index.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';

/**
 * FO-5 に関わる依存注入（すべて任意）。`LoadTrustedListOptions` がこれを継承する。
 *
 * `failOpenWindow` を渡さない限り FO-5 は一切発動しない（従来と同じ fail-closed）。
 */
export interface TrustedListFailOpenDeps {
  /** FO-5 の override。未指定時は同意・監査の条件を満たせば警告付きで続行できる。 */
  readonly failSafePolicy?: FailSafePolicy;
  /** UI 警告と同意取得のコールバック。未指定なら同意不能 ＝ fail-closed。 */
  readonly requestConsent?: (decision: FailSafeDecision) => boolean | Promise<boolean>;
  /** 監査ログの記録先。未指定なら記録を残せないため FO-5 は成立しない。 */
  readonly onPolicyEvent?: (record: FailSafeAuditRecord) => void | Promise<void>;
  /** 監査レコードへ付与する相関情報。 */
  readonly auditContext?: FailSafeAuditContext;
  /**
   * FO-5 の時間上限を管理するウィンドウ。**未指定なら FO-5 は発動しない。**
   *
   * `createFailOpenWindow()` で生成し、複数回の `loadTrustedList` 呼び出しにまたがって
   * **同じインスタンスを注入する**こと。呼び出しごとに生成すると失敗のたびに新しい猶予期間が
   * 開き、時間上限が実質無効化される。
   */
  readonly failOpenWindow?: FailOpenWindow;
}

/**
 * `deps.failOpenWindow` が有効な形状（`allow` / `clear` を関数として持つ）かを検証して返す。
 *
 * ウィンドウはクラスインスタンスであり得るため `Object.prototype` 由来だけを弾く
 * （`entity-configuration-fail-open.ts` と同じ規律）。形状も検証する
 * （`schema-validation/fail-safe.ts` の `resolveWindow` と同じ規律）。
 * `allow` / `clear` を関数として持たない注入を無検証で使うと、成功パスでの `window.clear(key)`
 * 呼び出しが無検証の生の `TypeError` を投げ、TSL 取得が成功した正常系そのものを丸ごと落としてしまう。
 *
 * `deps.failOpenWindow` 自体は `nonObjectPrototypeProperty` で読むが、そこで得た `window` の
 * `allow` / `clear` を素のドットアクセスで検証すると、値の読み取りだけ `Object.prototype` 汚染を
 * 弾いても「読み取った後のプロパティアクセス」で `Object.prototype.allow` / `.clear` の汚染を
 * 拾ってしまう（`cache.ts` の `isValidTrustedListCache` と同じバグクラス）。own
 * プロパティを持たない不正な形状（`failOpenWindow: {}`）を渡す呼び出しがあると、汚染された
 * `Object.prototype.allow` が常に `true` を返す攻撃者実装のとき、時間上限チェックが
 * 無効化されたまま FO-5 が無制限に成立し続ける。`window.allow` / `window.clear` の参照にも
 * `nonObjectPrototypeProperty` を使う。
 *
 * @param deps FO-5 に関わる依存注入。
 * @returns 有効な形状のウィンドウ。未注入・不正な形状なら `undefined`。
 */
function validFailOpenWindow(deps: TrustedListFailOpenDeps): FailOpenWindow | undefined {
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
 * 取得に成功したときに FO-5 の計時ウィンドウを破棄する。
 *
 * 破棄しないと、一度 fail-open を許した対象は障害から復旧しても古い計時を持ち続け、次の障害で
 * 直ちに上限超過（fail-closed）と判定されてしまう。ウィンドウが未注入・不正な形状なら何もしない。
 *
 * @param deps FO-5 に関わる依存注入。
 * @param key well-known URL（計時キー。監査レコードには出さない）。
 */
export function clearTrustedListFailOpenWindow(deps: TrustedListFailOpenDeps, key: string): void {
  validFailOpenWindow(deps)?.clear(key);
}

/**
 * TSL / LOTL の取得失敗に対して FO-5 を許可してよいか判定する。
 *
 * 呼び出し側（`etsi-tsl.ts`）は `readTrustedListCache` で有効期限内のキャッシュが見つかった場合に
 * 限って本関数を呼ぶ。見つからない場合（未格納・期限切れ）は本関数を呼ばずに fail-closed とする
 * （FO-6 と同じく、判定対象自体が無ければ監査記録もウィンドウの消費も発生させない）。
 *
 * @param deps ポリシー・同意・監査記録先・ウィンドウ（呼び出し側が渡した依存）。
 * @param key well-known URL（計時キー。監査レコードには出さない）。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @returns 許可された場合の警告。ウィンドウ未注入・不正な形状 / 許可されない場合は `undefined`。
 */
export async function decideTrustedListFetchFailure(
  deps: TrustedListFailOpenDeps,
  key: string,
  nowSeconds: number,
): Promise<FailSafeWarning | undefined> {
  const window = validFailOpenWindow(deps);
  if (window === undefined) {
    return undefined;
  }
  // 任意プロパティは自身のプロパティに限って読む。継承値を新しいオブジェクト
  // リテラルへ詰め直すと own プロパティに化け、ゲート側（`failsafe-policy/gate.ts`）の own 限定
  // 読み取りが無意味になる。その結果、fail-safe オプションを一切渡していない呼び出しでも
  // TSL の取得失敗が stale なキャッシュで通過し、監査レコードが攻撃者のシンクへ渡る。未設定の
  // キーはプロパティ自体を生やさないよう条件付き展開で落とす。
  const policy = ownProperty<FailSafePolicy>(deps, 'failSafePolicy');
  const requestConsent = ownProperty<TrustedListFailOpenDeps['requestConsent']>(
    deps,
    'requestConsent',
  );
  const onPolicyEvent = ownProperty<TrustedListFailOpenDeps['onPolicyEvent']>(
    deps,
    'onPolicyEvent',
  );
  const auditContext = ownProperty<FailSafeAuditContext>(deps, 'auditContext');
  return resolveFailOpen({
    policyEvent: 'FO-5',
    window,
    key,
    nowSeconds,
    ...(policy !== undefined ? { policy } : {}),
    ...(requestConsent !== undefined ? { requestConsent } : {}),
    ...(onPolicyEvent !== undefined ? { onPolicyEvent } : {}),
    ...(auditContext !== undefined ? { auditContext } : {}),
  });
}
