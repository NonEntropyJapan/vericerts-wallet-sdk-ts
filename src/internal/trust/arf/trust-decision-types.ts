/**
 * 3 層統合信頼判定の型定義。
 *
 * ETSI Trusted List（Layer 1）> OpenID Federation（Layer 2）> ARF Catalogue
 * （Layer 3）の優先順位に沿って Issuer / RP の信頼判定を統合する。各層の検証そのもの
 * （ネットワーク I/O・署名検証・チェーン構築）は既存モジュールが担い、本スコープは「検証済みの
 * 各層結果を優先順位・競合解消ルールに従って 1 つの判定へ統合する」ことに専念する。
 *
 * 設計方針:
 * - `evaluateTrust` は純粋関数とし、各層の検証結果（`LayerVerdict`）と任意のキャッシュ状態を入力に取る。
 *   これにより副作用（I/O）と判定ロジックを分離し、判定ルールを決定的にテストできる。
 * - 判定結果のログ記録は DI シンク（`TrustDecisionLogSink`）へ委譲する（decision-log.ts）。
 * - 例外・戻り値・ログに鍵素材 / 証明書本文 / URL 断片を含めない。
 */

/** 統合信頼判定の対象となる Trust Framework 層。優先度は TSL > OIDF > ARF の順。 */
export type TrustLayer = 'tsl' | 'oidf' | 'arf';

/**
 * 単一層における検証の状態（各層モジュールの検証を正規化した値）。
 *
 * - `pass`: その層で Issuer が有効な Trust Anchor として確認できた。
 * - `revoked`: その層に載っているが失効 / granted でない等、明示的に否定された。
 * - `not-found`: その層に該当エントリがない（フォールバック対象）。
 * - `error`: 取得・検証に失敗した（オフライン等。fail-safe の判断材料）。
 */
export type LayerStatus = 'pass' | 'revoked' | 'not-found' | 'error';

/** 単一層の検証結果。呼び出し側が各層モジュールの出力を正規化して渡す。 */
export interface LayerVerdict {
  /** 判定対象の層。 */
  readonly layer: TrustLayer;
  /** その層での検証状態。 */
  readonly status: LayerStatus;
}

/**
 * 統合判定の結果コード。
 *
 * - `tsl-qualified`: Layer 1（ETSI TSL）で PASS。最強の法的保証（eIDAS 2.0）。
 * - `oidf-federated`: Layer 2（OpenID Federation）で PASS。技術的信頼。
 * - `arf-listed`: Layer 3（ARF Catalogue）で PASS。EU Commission 登録。
 * - `rejected`: いずれかの Layer に、この判定へ適用される明示的な拒否（REVOKED）があり、
 *   より下位の PASS でも覆せない。ユーザー同意による続行も許可しない。
 * - `unknown`: 全層で該当なし（REVOKED も PASS も無い）。UI で不明確さを明示しユーザー明示同意が必要。
 * - `stale`: 全外部取得に失敗しキャッシュ内の最終判定を流用（Stale-If-Error）。
 */
export type TrustDecisionCode =
  | 'tsl-qualified'
  | 'oidf-federated'
  | 'arf-listed'
  | 'rejected'
  | 'unknown'
  | 'stale';

/** キャッシュ済みの最終判定。Stale-If-Error のフォールバック元。 */
export interface CachedTrustDecision {
  /** 過去に採用された判定コード。 */
  readonly code: TrustDecisionCode;
  /** 採用された層（`unknown` の場合は undefined）。 */
  readonly layer?: TrustLayer;
  /** キャッシュされた判定の生成時刻（エポックミリ秒）。grace_period 判定に用いる。 */
  readonly decidedAtMs: number;
}

/** `evaluateTrust` の入力。 */
export interface EvaluateTrustInput {
  /** 判定対象の Issuer / RP 識別子（各層で突き合わせたキーと同一）。 */
  readonly subjectId: string;
  /**
   * 各層の検証結果。層ごとに 0 個または 1 個。重複する層は最初の要素を採用する。
   * 省略された層は `not-found` 相当（フォールバック）として扱う。
   */
  readonly verdicts: readonly LayerVerdict[];
  /** キャッシュ内の最終判定（存在すれば Stale-If-Error のフォールバック元）。 */
  readonly cached?: CachedTrustDecision;
  /** 現在時刻（エポックミリ秒）。省略時は `Date.now()`。テスト決定性のため注入可能。 */
  readonly nowMs?: number;
  /**
   * Stale-If-Error の grace period（ミリ秒）。既定 72h。
   * この期間を超えたキャッシュは stale として採用しない。
   */
  readonly gracePeriodMs?: number;
}

/** 統合判定で検出した警告（強い警告ログ / 再検証タスク投入のトリガ）。 */
export type TrustDecisionWarning =
  /** 上位層 PASS だが下位層で REVOKED を検出。 */
  | 'lower-layer-revoked'
  /**
   * より上位（高優先度）の権威層に、この判定へ適用される明示的な REVOKED があったため、
   * 下位層に PASS があっても（あるいは PASS が 1 つも無くても）採用せず明示的に拒否した
   * （`code: 'rejected'`）。
   *
   * 旧挙動（〜2026-09-10 改訂前）は「下位 PASS を採用しつつ警告」という防御的デフォルトだったが、
   * T-Hirotaro 氏の方針決定（選択肢B・fail-closed 明示拒否）を受けて拒否側へ倒した。
   */
  | 'higher-layer-revoked'
  /** 全外部取得に失敗しキャッシュへフォールバックした（Stale-If-Error）。 */
  | 'stale-fallback'
  /** 全層で該当なし。ユーザー明示同意が必要。 */
  | 'unknown-requires-consent';

/** `evaluateTrust` の結果（統合判定 + 監査に必要な付随情報）。 */
export interface TrustDecision {
  /** 判定対象の識別子。 */
  readonly subjectId: string;
  /** 統合判定コード。 */
  readonly code: TrustDecisionCode;
  /**
   * `code` が PASS 系（`tsl-qualified` 等）/ `stale` なら採用された層。`rejected` の場合は
   * 拒否の根拠となった REVOKED 層（最上位の該当層）。`unknown` の場合は undefined。
   */
  readonly layer?: TrustLayer;
  /** 判定時に検出した警告（順序は検出順・重複なし）。 */
  readonly warnings: readonly TrustDecisionWarning[];
  /** 再検証タスクをキューすべきか（上位優先で下位 REVOKED を無視した場合など）。 */
  readonly requiresRevalidation: boolean;
  /** 判定生成時刻（エポックミリ秒）。 */
  readonly decidedAtMs: number;
  /**
   * `code: 'stale'` のとき、フォールバック元の判定が下された時刻（エポックミリ秒）。
   * grace period の起点はこの値で、`decidedAtMs`（フォールバックを行った時刻）ではない。
   */
  readonly staleSinceMs?: number;
}
