/**
 * 3 層統合信頼判定のログ記録。
 *
 * `evaluateTrust`（evaluate.ts）の判定結果を監査用ログとして記録する。永続化先（Dashboard ログ・
 * 監査ストア・コンソール等）は環境依存のため、DI シンク（`TrustDecisionLogSink`）へ委譲する。
 * 上位層が PASS で下位層に REVOKED がある場合や、stale な結果を採用した場合は、判定結果の `warnings` も同じシンクに渡す。
 *
 * 設計方針:
 * - 判定（純粋関数）とログ副作用を分離するため、`evaluateTrustWithLogging` は `evaluateTrust` を
 *   呼んだうえで結果をシンクへ渡す薄いラッパに徹する。
 * - fail-safe: ログシンクの失敗は信頼判定自体を無効化しない。判定は既に確定しているため、シンクが
 *   throw / reject してもその例外を握りつぶし、判定結果を返す（監査ログの欠落で信頼判定を止めない）。
 *
 * セキュリティ / プライバシー上の注意:
 * - ログレコードに鍵素材・証明書本文・JWT・URL 断片を含めない。記録するのは判定対象識別子
 *   （各層の突き合わせキーと同一で、シーケンス図でも `issuer_id` として扱われる）と判定メタデータのみ。
 */

import { emitWarning, type OnWarning } from '../../observability/warning.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { evaluateTrust } from './evaluate.js';
import type {
  EvaluateTrustInput,
  TrustDecision,
  TrustDecisionCode,
  TrustDecisionWarning,
  TrustLayer,
} from './trust-decision-types.js';

/**
 * 監査ログへ記録する統合信頼判定レコード（機微情報を含まない正規化済みビュー）。
 *
 * `TrustDecision` から鍵素材等を持ち得ないフィールドのみを写像したもの。シンク実装がそのまま
 * シリアライズして永続化できるよう、プリミティブと配列のみで構成する。
 */
export interface TrustDecisionLogRecord {
  /** 判定対象の識別子（Issuer / RP。各層の突き合わせキー）。 */
  readonly subjectId: string;
  /** 統合判定コード。 */
  readonly code: TrustDecisionCode;
  /** 採用された層（`unknown` の場合は undefined）。 */
  readonly layer?: TrustLayer;
  /** 検出した警告（強い警告ログ / 再検証トリガ）。 */
  readonly warnings: readonly TrustDecisionWarning[];
  /** 再検証タスクをキューすべきか。 */
  readonly requiresRevalidation: boolean;
  /** 判定生成時刻（エポックミリ秒）。 */
  readonly decidedAtMs: number;
}

/**
 * 統合信頼判定レコードの記録先（DI seam）。
 *
 * 同期・非同期どちらの実装も許容する（戻り値を await する）。永続化・署名・Merkle chain 等は
 * シンク実装（例: gdpr の DashboardLog アダプタ）の責務とする。
 */
export type TrustDecisionLogSink = (record: TrustDecisionLogRecord) => void | Promise<void>;

/** `TrustDecision` を機微情報を含まないログレコードへ写像する。 */
export function toTrustDecisionLogRecord(decision: TrustDecision): TrustDecisionLogRecord {
  const layer = ownProperty<TrustDecision['layer']>(decision, 'layer');
  return {
    subjectId: decision.subjectId,
    code: decision.code,
    ...(layer !== undefined ? { layer } : {}),
    warnings: decision.warnings,
    requiresRevalidation: decision.requiresRevalidation,
    decidedAtMs: decision.decidedAtMs,
  };
}

/**
 * 統合信頼判定を実行し、その結果を監査ログシンクへ記録したうえで判定を返す。
 *
 * 判定ロジックは `evaluateTrust` に委譲する。判定確定後にログレコードを組み立ててシンクへ渡す。
 * シンクが同期・非同期いずれでも動くよう戻り値を await する。シンクが失敗しても判定は既に確定して
 * いるため、例外を握りつぶして判定結果を返す（fail-safe。監査ログの欠落で信頼判定を止めない）。
 *
 * @param input `evaluateTrust` と同じ入力。
 * @param sink 判定レコードの記録先（DI）。
 * @returns 統合信頼判定。
 */
export async function evaluateTrustWithLogging(
  input: EvaluateTrustInput,
  sink: TrustDecisionLogSink,
  onWarning?: OnWarning,
): Promise<TrustDecision> {
  const decision = evaluateTrust(input);
  try {
    await sink(toTrustDecisionLogRecord(decision));
  } catch (error) {
    // 監査ログの記録失敗は信頼判定を無効化しない（fail-safe）。判定は確定済み。
    // ただし判定の記録が欠けるので、気づきたい失敗として `onWarning` に流す。
    emitWarning(
      onWarning,
      {
        code: 'trust.decision_log_failed',
        message:
          'Failed to record the trust decision in the log sink; the decision is still returned.',
        component: 'sdk.vc',
      },
      error,
    );
  }
  return decision;
}
