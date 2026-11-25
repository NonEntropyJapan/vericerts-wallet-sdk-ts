/**
 * 監査ログの記録失敗（結論は変えないが記録が欠ける）が `onWarning` に流れること。
 * `recordTransferWarning`（越境警告）と `evaluateTrustWithLogging`（信頼判定）。どちらも未指定なら従来どおり。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import type { SdkWarning } from '../../observability/warning.js';
import { DashboardLog } from '../dashboard-log/dashboard-log.js';
import { recordTransferWarning, type TransferWarningSource } from '../transfer-warning.js';
import { fixedNow, testSigner } from './dashboard-log/dashboard-log-helpers.js';

const CROSS_BORDER: TransferWarningSource = {
  rpIdentifier: 'LEIXG-US-001',
  country: 'US',
  origin: 'https://verifier.example.us',
  crossBorderWarning: true,
};

class EntryWriteFailingStorage extends MemoryStorage {
  override async set(): Promise<void> {
    throw new Error('storage write failed');
  }
}

describe('recordTransferWarning の onWarning', () => {
  it('記録に失敗しても UI 警告は返り、onWarning に失敗が届く', async () => {
    const warnings: SdkWarning[] = [];
    const log = new DashboardLog(
      new EntryWriteFailingStorage(),
      fixedNow('2026-11-17T00:00:00.000Z'),
    );

    const view = await recordTransferWarning(CROSS_BORDER, log, testSigner(), (w) =>
      warnings.push(w),
    );

    expect(view).toMatchObject({ rpIdentifier: 'LEIXG-US-001' });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({ code: 'gdpr.transfer_warning_log_failed' });
    expect(warnings[0]?.attributes.error_message).toBe('storage write failed');
  });

  it('記録に成功したときは onWarning を呼ばない', async () => {
    const warnings: SdkWarning[] = [];
    const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-11-17T00:00:00.000Z'));

    await recordTransferWarning(CROSS_BORDER, log, testSigner(), (w) => warnings.push(w));

    expect(warnings).toEqual([]);
  });

  it('onWarning を指定しなければ従来どおり（UI 警告は返り、何も出ない）', async () => {
    const log = new DashboardLog(
      new EntryWriteFailingStorage(),
      fixedNow('2026-11-17T00:00:00.000Z'),
    );

    await expect(recordTransferWarning(CROSS_BORDER, log, testSigner())).resolves.toMatchObject({
      rpIdentifier: 'LEIXG-US-001',
    });
  });
});
