/**
 * Fail-safe ポリシーの判定ロジックと Fail-open の時間上限管理。
 *
 * 本モジュールが提供するのは判定プリミティブのみで、UI 警告と監査ログの永続化は
 * 呼び出し側（Extension / SDK 利用者）の責務とする。
 *
 * ## 既定は Fail-open
 *
 * 許容事象は同意・時間上限・監査の条件が揃えば処理を続けられる。
 * `FailSafePolicy.escalate` に挙げた ID では拒否する。
 *
 * セキュリティ上の注意:
 * - 判定に使うキー（`FailOpenWindow` の `key`）はプロセス内のメモリにしか置かず、監査レコードや
 *   例外メッセージへ出さない。
 */

import { DEFAULT_CACHE_MAX_ENTRIES, resolveMaxTtlSeconds } from '../cache/ttl-cache.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { FailOpenId, FailSafeDecision, FailSafePolicy } from './types.js';

/**
 * `policy` の 1 フィールドを own 限定（`Object.prototype` 鎖を辿らない）で読む。
 *
 * `policy` 自体は呼び出し側が用意した正当なオブジェクトリテラルであり `Object.prototype` を継承する。
 * そのフィールドを `policy?.field` で読むと、`Object.prototype` が汚染された環境では**未指定の
 * フィールドについて継承値を拾ってしまう**。`policy` が `undefined`（override 自体が
 * 未指定）の場合は当然 `undefined` を返す。
 */
function ownPolicyField<K extends keyof FailSafePolicy>(
  policy: FailSafePolicy | undefined,
  key: K,
): FailSafePolicy[K] | undefined {
  return policy === undefined ? undefined : ownProperty<FailSafePolicy[K]>(policy, key);
}

/**
 * FO-ID から Dashboard の監査ログで使うイベント名を引く。
 * 値は Dashboard ログの項目名と 1:1 対応するため、仕様表の文字列をそのまま写す。
 */
export const FAIL_OPEN_AUDIT_EVENTS: Readonly<Record<FailOpenId, string>> = {
  'FO-1': 'status_check_unreachable',
  'FO-2': 'status_list_stale',
  'FO-3': 'schema_fetch_failed',
  'FO-4': 'schema_optional_invalid',
  'FO-5': 'tsl_fetch_failed_cache_ok',
  'FO-6': 'federation_fetch_failed_cache_ok',
  'FO-7': 'did_config_missing',
  'FO-8': 'vc_expiring_soon',
  'FO-9': 'refresh_failed',
  'FO-10': 'mediator_unreachable',
  'FO-11': 'passkey_provider_substantial',
  'FO-12': 'evidence_fetch_failed',
};

/** Fail-open 許容事象の ID 一覧。 */
export const FAIL_OPEN_IDS: readonly FailOpenId[] = Object.keys(
  FAIL_OPEN_AUDIT_EVENTS,
) as FailOpenId[];

/**
 * 未知の `policyEvent` に対する監査イベント名。
 *
 * 未知 ID は必ず fail-closed（`deny`）に倒れるため、この名前が 監査ログに載ることはない
 * （`resolveFailOpen` は `deny` を記録せずに拒否する）。診断のためだけの値。
 */
export const UNKNOWN_POLICY_EVENT_AUDIT = 'unknown_policy_event';

/**
 * 挙動変更オプションが Fail-closed を指示しているかを判定する。
 *
 * 現状は FO-9（refreshService リフレッシュ失敗）の `refreshFailure: 'discard'` のみ。旧 VC を破棄する
 * 選択は「旧 VC で通過させない」ことを意味するため `deny` に倒す。
 */
function deniedByOption(policyEvent: FailOpenId, policy?: FailSafePolicy): boolean {
  return policyEvent === 'FO-9' && ownPolicyField(policy, 'refreshFailure') === 'discard';
}

/**
 * 同意プロンプトを省いてよいかを判定する。
 *
 * - `suppressPrompt` に挙げた ID（CI / バッチ用途）。
 * - FO-9 で `refreshFailure: 'keep-old'` を明示した場合（「旧 VC 継続」を利用者が既定として宣言済み）。
 * - FO-11 で `allowSubstantialPasskey: true` を明示した場合（非 LoA High Passkey の許容を宣言済み）。
 *
 * いずれも SDK 利用者の明示的なオプトインで、未指定時は 同意を要求する
 * （`refreshFailure: 'prompt'` / `allowSubstantialPasskey: false` は未指定と同じ既定挙動）。
 */
function promptSuppressed(policyEvent: FailOpenId, policy?: FailSafePolicy): boolean {
  if (ownPolicyField(policy, 'suppressPrompt')?.includes(policyEvent) === true) {
    return true;
  }
  if (policyEvent === 'FO-9' && ownPolicyField(policy, 'refreshFailure') === 'keep-old') {
    return true;
  }
  return policyEvent === 'FO-11' && ownPolicyField(policy, 'allowSubstantialPasskey') === true;
}

/**
 * Fail-open 許容事象に対する挙動を判定する。
 *
 * 既定は Fail-open（`warn`）で、次のいずれかに当たる場合のみ Fail-closed（`deny`）に倒す:
 *
 * - `policy.escalate` に含まれる ID。
 * - 挙動変更オプションが破棄を指示している（FO-9 の `refreshFailure: 'discard'`）。
 * - 未登録の ID（型 cast や JS からの呼び出しで `FC-*` 等が渡された場合）。
 *   fail-safe モジュールの倒れ方向は常に安全側とし、`FC-*` は override 不可の
 *   Fail-closed として扱う。
 *
 * `warn` の場合は 既定で同意プロンプトを要求し、`promptSuppressed`
 * に該当する ID のみプロンプトを省く（同意事実を事前に記録する責務は SDK 利用者に移る）。
 *
 * @param policyEvent 判定対象の FO-ID。
 * @param policy SDK 利用者の override（未指定なら既定ポリシー）。
 * @returns 重大度・監査イベント名・同意プロンプト要否。
 */
export function decideFailSafe(policyEvent: FailOpenId, policy?: FailSafePolicy): FailSafeDecision {
  if (!FAIL_OPEN_IDS.includes(policyEvent)) {
    return {
      policyEvent,
      severity: 'deny',
      auditEvent: UNKNOWN_POLICY_EVENT_AUDIT,
      promptRequired: false,
    };
  }
  const auditEvent = FAIL_OPEN_AUDIT_EVENTS[policyEvent];
  const denied =
    ownPolicyField(policy, 'escalate')?.includes(policyEvent) === true ||
    deniedByOption(policyEvent, policy);
  if (denied) {
    return { policyEvent, severity: 'deny', auditEvent, promptRequired: false };
  }
  return {
    policyEvent,
    severity: 'warn',
    auditEvent,
    promptRequired: !promptSuppressed(policyEvent, policy),
  };
}

/**
 * Fail-open を継続してよい最大秒数の既定値。
 *
 *
 * 超過後は許可を取り消して Fail-closed に戻し、**`clear()`（＝取得成功）でウィンドウを破棄するまで**
 * 許可しない。上限超過だけでウィンドウを作り直すと、失敗が続く限り
 * 上限ごとに 1 回拒否するだけで Fail-open が無期限に継続してしまうため、破棄条件は成功時のみとする。
 */
export const DEFAULT_FAIL_OPEN_MAX_SECONDS = 60;

/**
 * Fail-open の継続時間を対象キー単位で制限するウィンドウ。
 *
 * 「最初に Fail-open を許可した時刻」から `maxSeconds` の間だけ許可を継続し、超過したら許可を
 * 取り消す。実装はプロセス内メモリのみで、永続化しない。
 */
export interface FailOpenWindow {
  /**
   * このキーに対して Fail-open を許可してよいかを判定する。
   *
   * 初回は現在時刻を開始時刻として記録し許可する。以降は開始時刻から `maxSeconds` 以内なら許可を
   * 継続し、超過したら不許可を返す。開始時刻は保持したままなので、`clear()`（取得成功）でウィンドウを
   * 破棄するまで以降の呼び出しも不許可のままになる。
   *
   * @param key 対象を識別するキー（Status List URI など。監査レコードには出さない）。
   * @param nowSeconds 現在時刻（エポック秒）。
   * @returns 許可してよければ true。
   */
  allow(key: string, nowSeconds: number): boolean;
  /**
   * このキーのウィンドウを破棄する。
   *
   * 取得に成功したときに呼ぶことで、次に失敗したとき新しい 60 秒のウィンドウが始まる。
   *
   * @param key 対象を識別するキー。
   */
  clear(key: string): void;
}

/**
 * `FailOpenWindow` が同時に計時できるキー数の既定上限。
 *
 * 開始時刻はキー（Status List URI など）ごとに保持するため、キーが呼び出し側の入力由来である
 * 以上、上界を与えないとプロセス寿命に比例してメモリが伸びる。キャッシュ層と同じ既定値を使う。
 */
export const DEFAULT_FAIL_OPEN_MAX_KEYS = DEFAULT_CACHE_MAX_ENTRIES;

/**
 * 値が計時キー数の上限として妥当（有限の非負整数）かを検証する。
 *
 * 未検証のまま `size >= keyLimit` に渡すと、`NaN` では比較が常に false になり上界が恒久的に
 * 無効化される（メモリ安全性の防御が外れる）。負値では逆に最初のキーすら計時できない。
 */
function assertKeyLimit(value: number): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
}

/**
 * `FailOpenWindow` を生成する。
 *
 * `maxSeconds` の上限は `DEFAULT_FAIL_OPEN_MAX_SECONDS`（60 秒）。これを超える指定は拒否する。
 *
 * ## 計時キー数の上界は「溢れたら拒否」で与える
 *
 * 計時中のキー数が `maxKeys` に達した状態で**新しいキー**が来た場合は、開始時刻を記録せず
 * `allow` が `false` を返す（＝ Fail-closed）。キャッシュ層のように古いエントリを追い出さないのは、
 * ここでの追い出しが**そのキーの計時リセットと同義**だからである。追い出す実装にすると、攻撃者は
 * 相異なるキーを `maxKeys` 個ぶん流し込んで自分のキーの開始時刻を捨てさせるだけで 60 秒上限を
 * 何度でも巻き戻せてしまう。上界超過という異常時に倒れる方向は、fail-safe モジュールの規律どおり
 * 常に安全側（拒否）とする。
 *
 * @param maxSeconds Fail-open を継続できる最大秒数（既定 `DEFAULT_FAIL_OPEN_MAX_SECONDS`）。
 * @param maxKeys 同時に計時できるキー数の上限（既定 `DEFAULT_FAIL_OPEN_MAX_KEYS`）。
 * @returns キー単位で継続時間を管理するウィンドウ。
 * @throws `maxSeconds` が非負整数でない、または 60 秒を超える場合（VericertsError、code `3002`）。
 * @throws `maxKeys` が非負整数でない場合（VericertsError、code `3002`）。
 */
export function createFailOpenWindow(maxSeconds?: number, maxKeys?: number): FailOpenWindow {
  const limit = resolveMaxTtlSeconds(maxSeconds, DEFAULT_FAIL_OPEN_MAX_SECONDS);
  const keyLimit = maxKeys ?? DEFAULT_FAIL_OPEN_MAX_KEYS;
  assertKeyLimit(keyLimit);
  const startedAt = new Map<string, number>();
  return {
    allow(key: string, nowSeconds: number): boolean {
      const start = startedAt.get(key);
      if (start === undefined) {
        if (startedAt.size >= keyLimit) {
          // 計時できない ＝ 上限を担保できないため、記録せず拒否する（上の注記を参照）。
          return false;
        }
        startedAt.set(key, nowSeconds);
        return true;
      }
      // 上限超過後も開始時刻を残し、clear()（取得成功）まで拒否し続ける。
      return nowSeconds - start <= limit;
    },
    clear(key: string): void {
      startedAt.delete(key);
    },
  };
}
