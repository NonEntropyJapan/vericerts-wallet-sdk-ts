/**
 * Fail-open の許可判定を 1 本にまとめたゲート（判定 → 時間上限 → 同意 → 監査記録）。
 *
 * 1. `decideFailSafe` で既定 / override を評価する（`deny` なら即 Fail-closed）。
 * 2. Fail-open の時間上限（既定 60 秒）を `FailOpenWindow` で確認する。
 * 3. 同意プロンプトが要る場合はユーザー同意を取る（同意コールバックが無ければ同意不能）。
 * 4. 同意または拒否の結果を監査ログへ記録する。
 *
 * 監査の記録先（`onPolicyEvent`）がなければ許可しない。署名付き Dashboard ログを使う場合は
 * `createDashboardLogAuditRecorder` を渡す。
 *
 * 呼び出し側は戻り値が `undefined` のとき **元の失敗をそのまま伝播する**（Fail-closed）。警告が
 * 返った場合のみ通過させ、その警告を検証結果へ添える。
 *
 * FO-1（Status List 到達不能）だけでなく FO-2（staleness）以降も同じ経路を再利用できるよう、
 * 事象固有の処理を一切持たない。
 *
 * セキュリティ上の注意:
 * - `key` は時間上限の管理にのみ使い、監査レコードへは出さない（URI 等が漏れるため）。
 * - `auditContext` は呼び出し側が用意した識別子をそのまま透過する（SDK 側で導出しない）。
 */

import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';
import { decideFailSafe, type FailOpenWindow } from './policy.js';
import type {
  FailOpenId,
  FailSafeAuditContext,
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafePolicy,
  FailSafeWarning,
} from './types.js';

/** `resolveFailOpen` の入力。 */
export interface ResolveFailOpenParams {
  /** 発生した Fail-open 許容事象の ID。 */
  readonly policyEvent: FailOpenId;
  /** SDK 利用者の override（未指定なら既定ポリシー）。 */
  readonly policy?: FailSafePolicy;
  /** Fail-open の時間上限を管理するウィンドウ。 */
  readonly window: FailOpenWindow;
  /** 時間上限を数えるキー（Status List URI など。監査レコードには出さない）。 */
  readonly key: string;
  /** 現在時刻（エポック秒）。 */
  readonly nowSeconds: number;
  /** UI 警告を出しユーザー同意を取るコールバック。 */
  readonly requestConsent?: (decision: FailSafeDecision) => boolean | Promise<boolean>;
  /**
   * 監査ログの記録先。同意・不同意のいずれでも呼ばれる。
   *
   * 未指定の場合は監査記録を残せないため Fail-open せず、元の失敗をそのまま伝播する。
   * 永続化まで行う実装は `createDashboardLogAuditRecorder` を使う。
   * 非同期実装（Dashboard ログへの追記など）は解決を待ってから通過を判断する。
   */
  readonly onPolicyEvent?: (record: FailSafeAuditRecord) => void | Promise<void>;
  /** 監査レコードへ付与する相関情報。 */
  readonly auditContext?: FailSafeAuditContext;
}

/**
 * 監査レコードを組み立てて記録先へ渡す。
 *
 * 記録先が例外を投げた（永続化に失敗した）場合は `false` を返す。監査記録は必須のため、
 * 記録できなかった Fail-open は成立させない（呼び出し側が Fail-closed に倒す）。
 *
 * @param sink 監査ログの記録先（`resolveFailOpen` が存在を確認済み）。
 * @returns 記録できたら true。
 */
async function record(
  params: ResolveFailOpenParams,
  sink: (r: FailSafeAuditRecord) => void | Promise<void>,
  decision: FailSafeDecision,
  userConsent: 'accepted' | 'rejected',
): Promise<boolean> {
  try {
    await sink({
      // 相関情報を先に展開し、判定そのもの（事象 ID・イベント名・同意結果・override）を後に置く。
      // 順序を逆にすると、`auditContext` に同名キーを混ぜるだけで監査レコードの判定部分を
      // 上書きできてしまう（型では防げても JS からの呼び出しは防げない）。監査ログは判定の記録で
      // ある以上、呼び出し側の付随情報に判定を書き換えさせてはならない。
      ...ownProperty<FailSafeAuditContext>(params, 'auditContext'),
      policy_event: decision.policyEvent,
      audit_event: decision.auditEvent,
      user_consent: userConsent,
      override: ownProperty<FailSafePolicy>(params, 'policy') ?? {},
    });
    return true;
  } catch {
    // 記録先の失敗（storage 障害・署名失敗など）は握り潰さず「記録できなかった」として扱う。
    // 例外自体は伝播させない（呼び出し側は元の失敗をそのまま伝播するため、そちらが本来の原因）。
    return false;
  }
}

/**
 * 同意コールバックを呼び、同意しなければ false に倒す。
 *
 * 同期 throw / Promise reject は「同意不能」として false（= `rejected` 記録 → Fail-closed）に正規化する。
 * 呼び出し側は `resolveFailOpen` の例外を捕捉せず `undefined` を「元の失敗を再送出」の合図としているため、
 * 同意 UI の障害で任意の `Error` が元の `VericertsError` に代わって届くのを防ぐ。
 */
async function askConsent(
  requestConsent: (decision: FailSafeDecision) => boolean | Promise<boolean>,
  decision: FailSafeDecision,
): Promise<boolean> {
  try {
    return Boolean(await requestConsent(decision));
  } catch {
    return false;
  }
}

/**
 * Fail-open を許可してよいかを判定し、許可した場合は監査ログへ記録して警告を返す。
 *
 * 許可しない条件は次の 6 つ。いずれも呼び出し側は元の失敗をそのまま伝播する（Fail-closed）:
 *
 * - `policy.escalate` で Fail-closed に格上げされている / 未知の ID である（このとき監査記録は
 *   行わない。Fail-open を選択していないため Fail-open 判定結果の記録対象ではない）。
 * - 監査ログの記録先（`onPolicyEvent`）が渡されていない。
 * - Fail-open の時間上限（既定 60 秒）を超過した。
 * - 同意プロンプトが要るのに同意コールバックが無い、またはコールバックが例外を投げた / reject した
 *   （同意を取る手段が無い ＝ 同意不能。同意 UI の障害が元の失敗を覆い隠さないよう、例外は伝播させない）。
 * - ユーザーが同意しなかった。
 * - 監査レコードの記録に失敗した。
 *
 * 同意不能・不同意は `user_consent: 'rejected'` として監査記録する。
 *
 * @param params 事象 ID・override・ウィンドウ・現在時刻・同意コールバック・監査記録先。
 * @returns 許可した場合の警告。許可しない場合は undefined。
 */
export async function resolveFailOpen(
  params: ResolveFailOpenParams,
): Promise<FailSafeWarning | undefined> {
  // 任意プロパティは自身のプロパティに限って読む。継承値を拾うと、
  // これらを**省略した**正当な呼び出しが fail-open 側へ反転する:
  // - `onPolicyEvent`: 汚染値が「監査シンクあり」を満たし、監査記録なしで fail-open が成立する。
  // - `requestConsent`: 汚染値が truthy を返せば `promptRequired` の利用者同意がユーザー操作なしで成立する。
  // - `policy`: 汚染した override が `deny` 判定を許可側へ倒す。
  const decision = decideFailSafe(
    params.policyEvent,
    ownProperty<FailSafePolicy>(params, 'policy'),
  );
  if (decision.severity === 'deny') {
    return undefined;
  }
  const sink = ownProperty<(record: FailSafeAuditRecord) => void | Promise<void>>(
    params,
    'onPolicyEvent',
  );
  if (sink === undefined) {
    // 監査記録を残せない以上 Fail-open は成立しない。
    // 時間上限のウィンドウも消費せず、同意も求めずに Fail-closed に倒す。
    return undefined;
  }
  // `window` は fail-open の 60 秒上限を課す唯一のガード。継承値を拾うと、上限を数える
  // ウィンドウが攻撃者のオブジェクトになり **無期限に失効未確認のまま通過**する。
  // クラスインスタンスであり得るため `Object.prototype` 由来だけを弾く。
  //
  // `params.window` 自体は `nonObjectPrototypeProperty` で読むが、そこで得た `window` の
  // `allow` を素のドットアクセスで検証すると、own の `allow` を持たない不正な形状
  // （`window: {}`）を渡す呼び出しに対して `Object.prototype.allow` の汚染を拾ってしまう
  // （`etsi-tsl/fail-open.ts` の FO-5 で見つかったのと同一のバグクラス）。
  // `resolveFailOpen` は全 FO-* が通る唯一の共有ゲートであるため、ここを鎖読みのまま残すと
  // 個々の呼び出し側の検証を素通りしても最終防衛線として機能しない。
  const window = nonObjectPrototypeProperty<FailOpenWindow>(params, 'window');
  if (
    window === null ||
    typeof window !== 'object' ||
    typeof nonObjectPrototypeProperty(window, 'allow') !== 'function'
  ) {
    return undefined;
  }
  if (!window.allow(params.key, params.nowSeconds)) {
    return undefined;
  }
  if (decision.promptRequired) {
    const requestConsent = ownProperty<(decision: FailSafeDecision) => boolean | Promise<boolean>>(
      params,
      'requestConsent',
    );
    const consent =
      requestConsent === undefined ? false : await askConsent(requestConsent, decision);
    if (!consent) {
      await record(params, sink, decision, 'rejected');
      return undefined;
    }
  }
  if (!(await record(params, sink, decision, 'accepted'))) {
    return undefined;
  }
  return { policyEvent: decision.policyEvent, auditEvent: decision.auditEvent };
}
