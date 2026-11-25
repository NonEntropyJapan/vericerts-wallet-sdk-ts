/**
 * Cross-border Data Transfer 警告の連携（`transfer_warning`）。
 *
 * 受け取った `crossBorderWarning` を基に、域外転送の警告をログと UI に伝える。
 *
 * - ログ連携: 越境検出時に Dashboard ログへ `type: "transferWarning"` エントリを JWS 署名付きで追記する
 *   （`DashboardLog.append`。改ざん検知の連続性を維持する）。
 * - UI 連携: UI 警告に必要な最小ビュー（`TransferWarning`）を返し、組込先（Wallet UI）が同意取得前に
 *   越境転送を提示できる経路を定義する。越境でない場合は `null` を返し UI 警告を出さない。
 *
 * 設計方針（decision-log.ts の `evaluateTrustWithLogging` パターンに準拠）:
 * - trust/rp-access 型への依存を避けるため、入力は構造的な最小フィールド（`TransferWarningSource`）で受ける。
 *   呼び出し側（facade）が `RpAccessVerificationResult` をこの形へ写像する。
 * - fail-safe: ログ追記の失敗は越境警告自体を無効化しない。UI 警告ビューは常に返し、ログ副作用のみを
 *   握りつぶす（監査ログの欠落で UI 警告を止めない）。
 *
 * セキュリティ / プライバシー上の注意:
 * - payload / ビューに証明書本文・鍵素材を含めない。記録するのは RP 識別子・国コード・origin のみ
 *   （いずれも Dashboard で閲覧可能な公開情報）。
 */

import type { CredentialSigner } from '../credential/index.js';
import { emitWarning, type OnWarning } from '../observability/warning.js';
import type { DashboardLog } from './dashboard-log/dashboard-log.js';
import type { TransferWarningPayload } from './types.js';

/**
 * `transfer_warning` の入力となる RP 検証結果の最小ビュー。
 *
 * trust/rp-access の `RpAccessVerificationResult`（`rp.legalId` / `rp.country` / `rp.origin` /
 * `crossBorderWarning`）から写像する。`gdpr` を trust モジュールへ依存させないため構造型で受ける。
 */
export interface TransferWarningSource {
  /** 転送先 RP の識別子（`rp.legalId`。特定できない場合は空文字）。 */
  readonly rpIdentifier: string;
  /** 推定した RP 所在国の ISO 3166-1 alpha-2（`rp.country`。不明時は空文字）。 */
  readonly country: string;
  /** RP サービス URI（`rp.origin`。不明時は空文字）。 */
  readonly origin: string;
  /** RP 所在国が EU / EEA 域外または不明なら true（`crossBorderWarning`）。 */
  readonly crossBorderWarning: boolean;
}

/**
 * UI 警告に渡す越境転送ビュー（`transfer_warning` イベントの UI 連携経路）。
 *
 * Wallet UI が同意取得前に「EU 域外転送が発生する」旨を提示するための最小情報。プリミティブのみで
 * 構成し、組込先がそのままレンダリング / シリアライズできるようにする。
 */
export interface TransferWarning {
  /** 転送先 RP の識別子（不明時は空文字）。 */
  readonly rpIdentifier: string;
  /** 推定した RP 所在国の ISO 3166-1 alpha-2（不明時は空文字）。 */
  readonly country: string;
  /** RP サービス URI（不明時は空文字）。 */
  readonly origin: string;
}

/** `TransferWarningSource` を Dashboard ログ payload / UI ビューへ写像する（機微情報を含まない）。 */
function toPayload(source: TransferWarningSource): TransferWarningPayload {
  return {
    rpIdentifier: source.rpIdentifier,
    country: source.country,
    origin: source.origin,
  };
}

/**
 * RP 検証結果の越境判定を `transfer_warning` イベントとして Dashboard ログと UI 警告へ連携する
 * （Art.44–50）。
 *
 * `crossBorderWarning` が false（EU / EEA 域内転送）の場合は何もせず `null` を返す（転送メカニズム不要）。
 * true（域外 / 不明）の場合は Dashboard ログへ `transferWarning` エントリを JWS 署名付きで追記し、UI 警告用の
 * `TransferWarning` ビューを返す。ログ追記が失敗しても UI 警告ビューは返す（fail-safe。監査ログの欠落で
 * ユーザーへの越境警告を止めない）。
 *
 * @param source RP アクセス検証結果の最小ビュー（`verifyRpAccessCertificate` の結果から写像）。
 * @param log Dashboard ログ（イベント追記先）。
 * @param signer JWS 署名鍵（`CredentialSigner`）。
 * @param onWarning 監査ログの記録に失敗したときの通知先（省略時は何も通知しない。UI 警告は返す）。
 * @returns 越境転送時は UI 警告ビュー、域内転送時は `null`。
 */
export async function recordTransferWarning(
  source: TransferWarningSource,
  log: DashboardLog,
  signer: CredentialSigner,
  onWarning?: OnWarning,
): Promise<TransferWarning | null> {
  if (!source.crossBorderWarning) {
    return null;
  }
  const payload = toPayload(source);
  try {
    await log.append('transferWarning', { ...payload }, signer);
  } catch (error) {
    // 監査ログの記録失敗は UI 越境警告を無効化しない（fail-safe）。越境判定は既に確定済み。
    // ただし越境転送の記録が欠けるので、気づきたい失敗として `onWarning` に流す。
    emitWarning(
      onWarning,
      {
        code: 'gdpr.transfer_warning_log_failed',
        message:
          'Failed to record the transfer warning in the dashboard log; the UI warning is still returned.',
        component: 'sdk.wallet',
      },
      error,
    );
  }
  // UI ビューは payload と同一形状（ログ schema と UI view を型として分離しているだけ）。
  return { ...payload };
}
