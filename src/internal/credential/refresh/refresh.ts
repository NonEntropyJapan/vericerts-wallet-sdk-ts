/**
 * W3C `refreshService` に基づく VC の期限前リフレッシュ（Holder 側）。
 *
 * `shouldRefresh` は自動更新トリガー判定、`refreshCredential` は refreshService 呼び出し → 新 VC
 * 受領・検証 → `derivedFrom` チェーン付与での入れ替えを行う。DID 解決・署名検証・同意 UI は DI
 * （`verifyRefreshed` / `requestConsent` / `fetchImpl`）で外出しし単体テスト可能にする。HTTP 層は
 * `refresh-endpoint.ts` に分離している。
 *
 * リフレッシュ失敗時の挙動（FO-9）は本モジュール独自のフォールバックを持たず、`refresh-fail-safe.ts`
 * の `applyRefreshFailSafe` を経由して `internal/failsafe-policy/` の正準ゲート（`resolveFailOpen`）
 * へ委ねる（詳細・明示的オプトインの規律は `refresh-fail-safe.ts` の docstring 参照）。
 *
 * セキュリティ: 例外 message / context に VC 本文・エンドポイント応答本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type {
  FailOpenWindow,
  FailSafeAuditContext,
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafePolicy,
  FailSafeWarning,
} from '../../failsafe-policy/index.js';
import type { FetchLike } from '../../fetch-di.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { assertVerifiableCredential } from '../presentation/vc-assert.js';
import { isoToNumericDate } from '../vc/numeric-date.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../vc/vc.js';
import { callRefreshEndpoint } from './refresh-endpoint.js';
import {
  applyRefreshFailSafe,
  clearRefreshFailSafeWindow,
  resolveRefreshFailSafeKey,
} from './refresh-fail-safe.js';

/** デフォルトのリフレッシュしきい値（期限の何日前から対象か）。 */
export const DEFAULT_REFRESH_THRESHOLD_DAYS = 7;

/** 1 日のミリ秒数。 */
const MS_PER_DAY = 24 * 60 * 60 * 1000;

/** VC 種別ごとのリフレッシュ挙動ポリシー。 */
export interface RefreshPolicy {
  /** 適用する VC type（VC の `type` 配列に含まれる型）。 */
  readonly vcType: string;
  /** 自動リフレッシュ ON/OFF。 */
  readonly autoRefresh: boolean;
  /** 期限の何日前から対象か（既定: 7）。 */
  readonly thresholdDays?: number;
  /** 失敗時のリトライ上限（既定: 3）。 */
  readonly maxAttempts?: number;
  /** 失敗時に通知するか（既定: true）。 */
  readonly notifyOnFailure?: boolean;
}

/**
 * `refreshCredential` のオプション。
 *
 * リフレッシュ失敗時の挙動は `FailSafePolicy.refreshFailure` で指定する。
 */
export interface RefreshOptions {
  /** 期限に関係なく強制リフレッシュする。 */
  readonly force?: boolean;
  /** Holder 同意 UI を省略する（事前オプトイン済みのみ）。`FailSafePolicy` 側の同意とは別軸。 */
  readonly silent?: boolean;
  /**
   * FO-9（リフレッシュ失敗）を含む fail-safe ポリシー。既定の `refreshFailure` は
   * `prompt` で、警告付きで旧 VC を返す前にユーザーの同意を求める。
   */
  readonly failSafePolicy?: FailSafePolicy;
  /**
   * FO-9 の監査レコードへ付与する相関情報。`vc_id`（Wallet 内識別子）を
   * 監査ログへ載せたい場合は呼び出し側が本フィールドで明示すること。SDK 側では `vc.id`（VC の
   * URI）から自動導出しない（FO-1 / FO-2 / FO-6 と同じく `auditContext` は透過するのみ）。
   */
  readonly auditContext?: FailSafeAuditContext;
  /** リフレッシュ対象か判定するしきい値（既定: 7 日）。 */
  readonly thresholdDays?: number;
  /** 期限判定に使う現在時刻（エポックミリ秒、テスト注入用）。既定 `Date.now()`。 */
  readonly now?: number;
}

/** `refreshCredential` の依存注入。DID 解決・署名検証・同意取得は呼び出し側が担う。 */
export interface RefreshDependencies {
  /**
   * 受領した生 VC 文字列を検証しパース済み VC を返す。署名・スキーマ・失効検証失敗時は throw する
   * （呼び出し側で `verifyCredential` 等を配線）。
   */
  readonly verifyRefreshed: (rawCredential: string) => Promise<VerifiableCredential>;
  /**
   * Holder 同意を取得する（`true` で同意）。`requireHolderConsent` かつ `silent` でない場合に呼ぶ。
   * 省略時は同意が必要な状況で `HOLDER_CONSENT_NOT_OBTAINED`（3023）となる。
   *
   * リフレッシュを実行してよいかどうかの同意であり、FO-9（リフレッシュ**失敗**時の同意）とは
   * 別物（`requestFailSafeConsent` を使う）。
   */
  readonly requestConsent?: (vc: VerifiableCredential) => Promise<boolean>;
  /** HTTP リクエストに使う `fetch` 実装（テスト注入用）。省略時はグローバル `fetch`。 */
  readonly fetchImpl?: FetchLike;
  /**
   * FO-9 で `prompt` を選んだ場合に同意を取得する。未指定または同意を取得できない場合は
   * 元のエラーを送出する。`keep-old` ではこのコールバックを使わない。
   */
  readonly requestFailSafeConsent?: (decision: FailSafeDecision) => boolean | Promise<boolean>;
  /**
   * FO-9 の監査ログ記録先。旧 VC を返すには監査記録が必要になる。
   * Dashboard ログへ記録するには `createDashboardLogAuditRecorder` を使う。
   */
  readonly onPolicyEvent?: (record: FailSafeAuditRecord) => void | Promise<void>;
  /**
   * FO-9 の時間上限を管理するウィンドウ。**未指定なら FO-9 は
   * 発動しない**（FO-6 と同じ明示的オプトイン）。複数回の `refreshCredential` 呼び出しに
   * またがって同じインスタンスを注入すること（呼び出しごとの生成は時間上限を無効化する）。
   */
  readonly failOpenWindow?: FailOpenWindow;
}

/** `refreshCredential` の結果。 */
export interface RefreshResult {
  /**
   * 採用すべき VC。成功時は新 VC、FO-9 が警告通過（`keep-old` / 同意取得済みの `prompt`）した
   * 場合は旧 VC。`refreshFailure: 'discard'` 等で Fail-closed になった場合は本型を返さず
   * `refreshCredential` が元のエラーを送出する。
   */
  readonly credential?: VerifiableCredential;
  /** リフレッシュが実際に成功して VC が入れ替わったか。 */
  readonly refreshed: boolean;
  /** FO-9 が警告通過した場合の警告（監査イベント名を含む）。 */
  readonly warning?: FailSafeWarning;
}

/**
 * VC が有効期限しきい値に達しリフレッシュ対象かを判定する（自動更新トリガー）。
 *
 * `autoRefresh=false` / `vcType` 不一致 / `expirationDate` 無し（無期限）は対象外。それ以外は
 * `now >= (exp - thresholdDays)` のとき対象（既に期限切れでも対象に含める）。
 *
 * @param nowMs 現在時刻（エポックミリ秒）。既定 `Date.now()`。
 * @throws `expirationDate` が解釈不能な ISO / 文字列でない場合（VericertsError、code `3002`。
 *         `isoToNumericDate` が正規化する）。
 */
export function shouldRefresh(
  vc: VerifiableCredential,
  policy: RefreshPolicy,
  nowMs: number = Date.now(),
): boolean {
  // policy / VC はいずれも純データ。プロトタイプ鎖で読むと、`autoRefresh` を**宣言していない**
  // policy が汚染値で「自動更新 ON」に化け、対象外のはずの VC が更新対象になる（fail-open）。
  // 必須欄が own 読みで欠けた場合は判定材料が無いので対象外（fail-closed）。
  if (ownProperty<boolean>(policy, 'autoRefresh') !== true) {
    return false;
  }
  const vcType = ownProperty<string>(policy, 'vcType');
  const vcTypes = ownProperty<readonly string[]>(vc, 'type');
  // 型は cast のみ（VC 本文は非信頼入力なので実行時には文字列とは限らない）。型不正は下流の
  // `isoToNumericDate` が 3002 へ正規化する（生の `TypeError` を漏らさない）。
  const expirationDate = ownProperty<string>(vc, 'expirationDate');
  if (
    vcType === undefined ||
    !Array.isArray(vcTypes) ||
    !vcTypes.includes(vcType) ||
    expirationDate === undefined
  ) {
    return false;
  }
  const thresholdDays =
    ownProperty<number>(policy, 'thresholdDays') ?? DEFAULT_REFRESH_THRESHOLD_DAYS;
  const expMs = isoToNumericDate(expirationDate) * 1000;
  return !Number.isFinite(nowMs) || nowMs >= expMs - thresholdDays * MS_PER_DAY;
}

/**
 * VC を `refreshService` に基づいて期限前リフレッシュする。
 *
 * 手順: (1) refreshService 未設定なら `REFRESH_SERVICE_NOT_SET`（3033）。(2) `force` でなければ
 * しきい値で期限チェックし、未達なら入れ替えず旧 VC を返す。(3) 同意が必要なら `requestConsent`、
 * 得られなければ `HOLDER_CONSENT_NOT_OBTAINED`（3023）。(4) エンドポイント呼び出し（3030 / 3004）。
 * (5) 新 VC を `verifyRefreshed` で検証（失敗で `REFRESHED_VC_VERIFICATION_FAILED` 3022）。
 * (6) 旧 VC を指す `derivedFrom` を付与して入れ替える。
 *
 * 手順 4–6 の失敗は FO-9（`opts.failSafePolicy.refreshFailure`）に従う。
 * 警告通過した場合のみ旧 VC を返し、それ以外は元のエラーをそのまま送出する。手順 1–3 は
 * 入れ替え前の判定で常に throw / 旧 VC 返却となる（FO-9 の対象外）。
 *
 * @throws refreshService 未設定（3033）・同意未取得（3023）・FO-9 が成立しない場合の通信 / 検証失敗。
 * @throws `expirationDate` が解釈不能な ISO / 文字列でない場合（VericertsError、code `3002`。
 *         手順 4–6 より前段のため FO-9 は適用しない）。
 */
export async function refreshCredential(
  vc: VerifiableCredential,
  opts: RefreshOptions,
  deps: RefreshDependencies,
): Promise<RefreshResult> {
  // `vc.refreshService` は VC 本文（データ）。プロトタイプ鎖で読むと、refreshService を
  // **持たない** VC でも汚染値が「更新エンドポイントあり」を満たし、3033 のガードを素通りして
  // 攻撃者の URL へ更新要求が飛ぶ。
  const service = ownProperty<RefreshServiceConfig>(vc, 'refreshService');
  if (service === undefined) {
    // refresh エンドポイント未付与。Issuer 対応依頼が必要なため入れ替え不可（FO-9 対象外）。
    throw new VericertsError(ErrorCodes.REFRESH_SERVICE_NOT_SET);
  }

  // 任意プロパティは自身のプロパティに限って読む。継承値を拾うと、これらを
  // **省略した**正当な呼び出しが緩い側へ倒れる:
  // - `silent`: `requireHolderConsent` を宣言したサービスの同意プロンプトが省略される。
  // - `force`: 期限しきい値の検査そのものが飛ぶ。
  // - `now` / `thresholdDays`: 攻撃者の選んだ時刻・しきい値で入れ替え要否が評価される。
  const nowMs = ownProperty<number>(opts, 'now') ?? Date.now();
  const silent = ownProperty<boolean>(opts, 'silent');
  // FO-9 の時間上限を数えるキー（own 限定読み。`undefined` なら計時不能 = FO-9 対象外。
  // 詳細は `resolveRefreshFailSafeKey` の docstring 参照）。
  const failSafeKey = resolveRefreshFailSafeKey(vc, service);

  // 期限チェック（force 時はスキップ）。しきい値未達なら入れ替えせず旧 VC を返す。
  // `vc.expirationDate` も own 限定で読む。鎖読みだと `expirationDate` を持たない（＝無期限の）
  // VC が汚染値の期限で評価され、しきい値判定の結果を攻撃者が選べる。
  // `shouldRefresh` と同じく型は cast のみで、型不正は `isoToNumericDate` が 3002 へ正規化する。
  const expirationDate = ownProperty<string>(vc, 'expirationDate');
  if (ownProperty<boolean>(opts, 'force') !== true && expirationDate !== undefined) {
    const thresholdDays =
      ownProperty<number>(opts, 'thresholdDays') ?? DEFAULT_REFRESH_THRESHOLD_DAYS;
    const expMs = isoToNumericDate(expirationDate) * 1000;
    if (nowMs < expMs - thresholdDays * MS_PER_DAY) {
      return { credential: vc, refreshed: false };
    }
  }

  // Holder 同意（requireHolderConsent かつ silent でない場合）。`requireHolderConsent` を
  // 宣言していないサービスに汚染値が乗っても、同意要否の判定は VC 本文の own 値だけで決める。
  if (ownProperty<boolean>(service, 'requireHolderConsent') === true && silent !== true) {
    // 継承した `requestConsent` は「同意を取る手段あり」に化け、攻撃者の関数が同意を返す。
    const requestConsent = nonObjectPrototypeProperty<RefreshDependencies['requestConsent']>(
      deps,
      'requestConsent',
    );
    // レシーバは `deps` に束ね直す（`this` 参照つきクラス DI を壊さない）。
    // 関数でなければ同意を得る手段が無いので fail-closed（3023）に倒す。
    const consented =
      typeof requestConsent === 'function' ? await requestConsent.call(deps, vc) : false;
    if (!consented) {
      throw new VericertsError(ErrorCodes.HOLDER_CONSENT_NOT_OBTAINED);
    }
  }

  // 手順 4–6: エンドポイント呼び出し・検証・入れ替え。失敗は FO-9 に従う。
  try {
    // 関数値の DI は own 限定では読めない。証明書ピンニング付き `fetch` を prototype メソッドで
    // 注入した正当な実装が「未指定」と判定され、無言でグローバル fetch に差し替わる（検知不能）。
    // `Object.prototype` 由来だけを弾く。
    const fetchImpl = nonObjectPrototypeProperty<RefreshDependencies['fetchImpl']>(
      deps,
      'fetchImpl',
    );
    // `callRefreshEndpoint` は注入された場合だけ `deps` を `this` に束ねる。
    const rawNewVc = await callRefreshEndpoint(service, vc, fetchImpl, deps);

    let verified: VerifiableCredential;
    try {
      // `verifyRefreshed` も `Object.prototype` 由来だけを弾く。無ければ
      // 入れ替えを成立させない（fail-closed）。
      const verifyRefreshed = nonObjectPrototypeProperty<RefreshDependencies['verifyRefreshed']>(
        deps,
        'verifyRefreshed',
      );
      if (typeof verifyRefreshed !== 'function') {
        throw new VericertsError(ErrorCodes.REFRESHED_VC_VERIFICATION_FAILED);
      }
      // レシーバは `deps` に束ね直す（`this` 参照つきクラス DI を壊さない）。
      // 戻り値は DI 実装の自己申告なので、VC として構造検証する。検証しないと非 VC 値（文字列 /
      // `{}` / null）が「リフレッシュ成功」となり、有効な旧 VC が破損 VC に入れ替わる。
      // 検証失敗は下の catch で 3022 に正規化される。
      verified = assertVerifiableCredential(await verifyRefreshed.call(deps, rawNewVc));
    } catch {
      // 新 VC の署名 / スキーマ / 失効検証失敗。原因（VC 本文）は message に載せない。
      throw new VericertsError(ErrorCodes.REFRESHED_VC_VERIFICATION_FAILED);
    }

    // 旧 VC を指す derivedFrom を付与してチェーンエッジを形成する。Issuer 設定済みならそれを優先。
    // 鎖読みだと、`derivedFrom` を持たない新 VC でも汚染値が「Issuer 設定済み」に化け、
    // 監査用チェーンエッジの付与が**無言でスキップ**される。
    const issuerDerivedFrom = ownProperty<string>(verified, 'derivedFrom');
    const oldVcId = ownProperty<string>(vc, 'id');
    const newVc: VerifiableCredential =
      issuerDerivedFrom === undefined && oldVcId !== undefined
        ? { ...verified, derivedFrom: oldVcId }
        : verified;

    // 成功時は FO-9 の計時ウィンドウを破棄する（詳細は `clearRefreshFailSafeWindow` 参照）。
    // 破棄自体が投げても握り潰す（本 try は下の catch で FO-9 評価へ落ちる構造のため、無検証だと
    // リフレッシュが成功しているにもかかわらず後始末の失敗だけで FO-9 / Fail-closed へ倒れてしまう）。
    if (failSafeKey !== undefined) {
      try {
        clearRefreshFailSafeWindow(failSafeKey, deps);
      } catch {
        // no-op: リフレッシュ成功という事実は変えない。
      }
    }
    return { credential: newVc, refreshed: true };
  } catch (error) {
    // 計時キーが無ければ FO-9 を評価せず元のエラーをそのまま送出する（計時できない対象を
    // fail-open させない）。
    if (failSafeKey === undefined) {
      throw error;
    }
    return applyRefreshFailSafe(vc, failSafeKey, nowMs, opts, deps, error);
  }
}
