/**
 * `recordTransferWarning`（監査イベント `transfer_warning`）の単体テスト。
 *
 * - 越境（crossBorderWarning: true）検出時に Dashboard ログへ `transferWarning` エントリを追記し、
 *   UI 警告ビューを返す（ログ + UI 連携）。
 * - 域内（crossBorderWarning: false）はログ追記も UI 警告も行わず null を返す。
 * - payload / ビューには RP 識別子・国コード・origin のみを含む（秘密を含めない）。
 * - fail-safe: ログ追記が失敗しても UI 警告ビューを返す（越境警告をログ欠落で止めない）。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import type { CredentialSigner } from '../../credential/index.js';
import { DashboardLog } from '../dashboard-log/dashboard-log.js';
import { recordTransferWarning, type TransferWarningSource } from '../transfer-warning.js';
import { fixedNow, testSigner } from './dashboard-log/dashboard-log-helpers.js';

const CROSS_BORDER: TransferWarningSource = {
  rpIdentifier: 'LEIXG-US-001',
  country: 'US',
  origin: 'https://verifier.example.us',
  crossBorderWarning: true,
};

const IN_EU: TransferWarningSource = {
  rpIdentifier: 'LEIXG-DE-001',
  country: 'DE',
  origin: 'https://verifier.example.de',
  crossBorderWarning: false,
};

describe('recordTransferWarning', () => {
  it('越境検出時に transferWarning エントリを追記し UI 警告ビューを返す', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-07-07T00:00:00.000Z'));

    const warning = await recordTransferWarning(CROSS_BORDER, log, signer);

    expect(warning).toEqual({
      rpIdentifier: 'LEIXG-US-001',
      country: 'US',
      origin: 'https://verifier.example.us',
    });

    const entries = await log.list();
    expect(entries).toHaveLength(1);
    const entry = entries[0];
    expect(entry?.type).toBe('transferWarning');
    expect(entry?.payload).toEqual({
      rpIdentifier: 'LEIXG-US-001',
      country: 'US',
      origin: 'https://verifier.example.us',
    });
    // JWS 署名が付く（改ざん検知の基盤）。
    expect(entry?.signature.split('.')).toHaveLength(3);
  });

  it('域内転送は null を返しログを追記しない', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());

    const warning = await recordTransferWarning(IN_EU, log, signer);

    expect(warning).toBeNull();
    expect(await log.list()).toHaveLength(0);
  });

  it('国コード / RP 識別子が不明でも越境なら空文字で記録し警告を返す', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());

    const warning = await recordTransferWarning(
      { rpIdentifier: '', country: '', origin: '', crossBorderWarning: true },
      log,
      signer,
    );

    expect(warning).toEqual({ rpIdentifier: '', country: '', origin: '' });
    const entries = await log.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.payload).toEqual({ rpIdentifier: '', country: '', origin: '' });
  });

  it('ログ追記が失敗しても UI 警告ビューを返す（fail-safe）', async () => {
    // sign が throw する signer で append を失敗させる（正常 signer を包み sign のみ差し替える）。
    const base = testSigner();
    const failingSigner: CredentialSigner = {
      alg: base.alg,
      publicKeyJwk: base.publicKeyJwk,
      sign() {
        throw new Error('signer unavailable');
      },
    };
    const log = new DashboardLog(new MemoryStorage());

    const warning = await recordTransferWarning(CROSS_BORDER, log, failingSigner);

    // 判定は確定済みなので UI 警告は返す。ログは追記されない。
    expect(warning).toEqual({
      rpIdentifier: 'LEIXG-US-001',
      country: 'US',
      origin: 'https://verifier.example.us',
    });
    expect(await log.list()).toHaveLength(0);
  });
});
