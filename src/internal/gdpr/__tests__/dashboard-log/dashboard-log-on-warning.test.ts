/**
 * DashboardLog の `onWarning`。末尾アンカーの書込失敗は「結論（追記の成功）は変えないが記録が欠ける」
 * 失敗なので、気づきたいものとして `onWarning` に流す。
 *
 * - 失敗したときだけ `onWarning` を呼ぶ。成功時は呼ばない。
 * - `onWarning` 未指定なら従来どおり（追記は成功し、何も出ない）。
 * - 渡す失敗の中身は既存のマスキングを通る。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import type { SdkWarning } from '../../../observability/warning.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import { fixedNow, testSigner } from './dashboard-log-helpers.js';

const NOW = '2026-11-17T00:00:00.000Z';

/** 末尾アンカー（`anchor/` 配下）の書込だけを失敗させる Storage。エントリ本体の書込は通す。 */
class AnchorWriteFailingStorage extends MemoryStorage {
  constructor(private readonly failure: Error) {
    super();
  }

  override async set(key: string, value: Uint8Array): Promise<void> {
    if (key.startsWith('anchor/')) {
      throw this.failure;
    }
    return super.set(key, value);
  }
}

function jwtLike(payload: Record<string, unknown>): string {
  const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${b64({ alg: 'ES256' })}.${b64(payload)}.c2lnbmF0dXJl`;
}

describe('DashboardLog.append: 末尾アンカーの書込失敗', () => {
  it('追記は成功し、onWarning が 1 回だけ呼ばれる', async () => {
    const warnings: SdkWarning[] = [];
    const log = new DashboardLog(
      new AnchorWriteFailingStorage(new Error('quota exceeded')),
      fixedNow(NOW),
      (warning) => warnings.push(warning),
    );

    const entry = await log.append('presentation', { rpIdentifier: 'rp-1' }, testSigner());

    expect(entry.id).toBeDefined();
    expect(await log.list()).toHaveLength(1);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({
      code: 'dashboard_log.tail_anchor_write_failed',
      component: 'sdk.wallet',
    });
    expect(warnings[0]?.attributes).toMatchObject({
      error_name: 'Error',
      error_message: 'quota exceeded',
    });
  });

  it('onWarning を指定しなければ従来どおり（追記は成功し、何も出ない）', async () => {
    const log = new DashboardLog(
      new AnchorWriteFailingStorage(new Error('quota exceeded')),
      fixedNow(NOW),
    );

    await expect(
      log.append('presentation', { rpIdentifier: 'rp-1' }, testSigner()),
    ).resolves.toBeDefined();
    expect(await log.list()).toHaveLength(1);
  });

  it('アンカーの書込が成功したときは onWarning を呼ばない', async () => {
    const warnings: SdkWarning[] = [];
    const log = new DashboardLog(new MemoryStorage(), fixedNow(NOW), (warning) =>
      warnings.push(warning),
    );

    await log.append('presentation', { rpIdentifier: 'rp-1' }, testSigner());
    await log.append('presentation', { rpIdentifier: 'rp-2' }, testSigner());

    expect(warnings).toEqual([]);
  });

  it('渡す失敗の中身は既存のマスキングを通る（メッセージに載った JWT の payload は出ない）', async () => {
    const warnings: SdkWarning[] = [];
    const secret = 'S3CR3T-SUBJECT-VALUE';
    const log = new DashboardLog(
      new AnchorWriteFailingStorage(new Error(jwtLike({ sub: secret }))),
      fixedNow(NOW),
      (warning) => warnings.push(warning),
    );

    await log.append('presentation', { rpIdentifier: 'rp-1' }, testSigner());

    expect(warnings).toHaveLength(1);
    expect(JSON.stringify(warnings[0])).not.toContain(secret);
    expect(warnings[0]?.attributes.error_message).toContain('[REDACTED]');
  });

  it('onWarning が投げても追記の結論は変わらない', async () => {
    const log = new DashboardLog(
      new AnchorWriteFailingStorage(new Error('quota exceeded')),
      fixedNow(NOW),
      () => {
        throw new Error('sink failure');
      },
    );

    await expect(
      log.append('presentation', { rpIdentifier: 'rp-1' }, testSigner()),
    ).resolves.toBeDefined();
  });
});
