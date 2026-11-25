/**
 * LogFilter.rpIdentifier が `presentation` の `clientId` も対象にすること、および LogFilter を
 * own 限定で読むこと（`Object.prototype` 汚染下でも `purge({})` が全件対象）の検証。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import { logPresentationEvent } from '../../presentation-log.js';
import { fixedNow, testSigner } from './dashboard-log-helpers.js';

const RP = 'https://verifier.example';

function newLog(): DashboardLog {
  return new DashboardLog(new MemoryStorage(), fixedNow('2026-08-28T00:00:00.000Z'));
}

async function seed(log: DashboardLog, clientId: string): Promise<void> {
  await logPresentationEvent({ log, signer: testSigner(), clientId, credentialIds: ['vc1'] });
}

describe('LogFilter.rpIdentifier と presentation の clientId', () => {
  it('purge は clientId 一致の presentation を削除し、他 RP のエントリは残す', async () => {
    const log = newLog();
    await seed(log, RP);
    await seed(log, 'https://other.example');

    expect(await log.purge({ rpIdentifier: RP })).toBe(1);
    const remaining = await log.list();
    expect(remaining.map((e) => (e.payload as { clientId: string }).clientId)).toEqual([
      'https://other.example',
    ]);
  });

  it('exportLog も clientId 一致の presentation を拾う', async () => {
    const log = newLog();
    await seed(log, RP);
    await seed(log, 'https://other.example');

    const exported = await log.exportLog({ rpIdentifier: RP });
    expect(exported).toContain(RP);
    expect(exported).not.toContain('other.example');
  });

  it('表記ゆれ（大文字・末尾スラッシュ）でも正規化して一致する', async () => {
    const log = newLog();
    await seed(log, RP);

    expect(await log.purge({ rpIdentifier: 'https://Verifier.example/' })).toBe(1);
  });

  it('別 RP は一致しない', async () => {
    const log = newLog();
    await seed(log, RP);

    expect(await log.purge({ rpIdentifier: 'https://verifier.example.evil' })).toBe(0);
    expect((await log.list()).length).toBe(1);
  });
});

describe('LogFilter の own 限定読み', () => {
  it('Object.prototype.types が汚染されていても purge({}) は全件削除する', async () => {
    const log = newLog();
    await seed(log, RP);
    await log.append('correctionRequest', { vcId: 'vc1', reason: 'x' }, testSigner());

    const purged = await withPollutedPrototypeAsync({ types: ['correctionRequest'] }, () =>
      log.purge({}),
    );

    expect(purged).toBe(2);
  });

  it('Object.prototype.rpIdentifier が汚染されていても purge({}) は RP を継承しない', async () => {
    const log = newLog();
    await seed(log, RP);
    await seed(log, 'https://other.example');

    const purged = await withPollutedPrototypeAsync({ rpIdentifier: RP }, () => log.purge({}));

    expect(purged).toBe(2);
  });
});
