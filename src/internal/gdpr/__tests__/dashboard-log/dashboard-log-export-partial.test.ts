/**
 * 絞り込み（types / rpIdentifier 等）・削除済みで chain に欠損があるエクスポートの往復。
 *
 * 先頭 `prevHash` が `null` でない出力を従来の検証で拒否していたため、自 SDK でも取り込めなかった。
 * 欠損のある出力はルートハッシュ行に `partial: true` を付け、インポート側は署名と隣接行の
 * `prevHash` を検証しつつ元の連番を保って取り込む。行の改ざんは従来どおり `3010`。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import type { DashboardLogVerifierKey } from '../../dashboard-log/dashboard-log-import.js';
import { createPrivateKeySignerFromFill, fixedNow, testSigner } from './dashboard-log-helpers.js';

const signer = testSigner();
const verifierKey: DashboardLogVerifierKey = { alg: signer.alg, publicKeyJwk: signer.publicKeyJwk };
const sigInvalid = new VericertsError(ErrorCodes.SIG_INVALID);

async function seeded(): Promise<DashboardLog> {
  const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-10-01T00:00:00.000Z'));
  await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer); // 0
  await log.append('presentation', { clientId: 'rp1' }, signer); // 1
  await log.append('consentRevoked', { scope: { purpose: 'kyc' } }, signer); // 2
  await log.append('presentation', { clientId: 'rp2' }, signer); // 3
  await log.append('presentation', { clientId: 'rp1' }, signer); // 4
  return log;
}

function rootOf(ndjson: string): Record<string, unknown> {
  return JSON.parse(ndjson.split('\n').at(-1) as string) as Record<string, unknown>;
}

describe('絞り込みエクスポートの往復', () => {
  it.each([
    [
      'types: correctionRequest（先頭から連続 1 件）',
      { types: ['correctionRequest' as const] },
      [0],
      false,
    ],
    ['types: consentRevoked（先頭が非 null）', { types: ['consentRevoked' as const] }, [2], true],
    ['types: presentation（穴あり）', { types: ['presentation' as const] }, [1, 3, 4], true],
    ['rpIdentifier: rp1（穴あり）', { rpIdentifier: 'rp1' }, [1, 4], true],
  ])('%s', async (_label, filter, expectedSeqs, partial) => {
    const log = await seeded();
    const ndjson = await log.exportLog(filter);
    expect(rootOf(ndjson).partial).toBe(partial ? true : undefined);
    const dest = new DashboardLog(new MemoryStorage());

    const imported = await dest.importLog(ndjson, verifierKey);

    expect(imported).toBe(expectedSeqs.length);
    // 元の連番を保って取り込む（振り直すと欠損位置の prevHash と連番がずれる）。
    expect((await dest.list()).map((e) => Number(e.id))).toEqual(expectedSeqs);
    // 取り込み後の再エクスポートは同一内容。
    expect(await dest.exportLog()).toBe(ndjson);
  });

  it('欠損のない全件エクスポートには partial を付けず、従来の形のまま', async () => {
    const log = await seeded();

    expect(Object.keys(rootOf(await log.exportLog()))).toEqual(['merkleRoot', 'count']);
  });

  it('取り込み後も追記でき、追記エントリは取り込んだ末尾に連結する', async () => {
    const log = await seeded();
    const dest = new DashboardLog(new MemoryStorage());
    await dest.importLog(await log.exportLog({ rpIdentifier: 'rp1' }), verifierKey);

    const appended = await dest.append('presentation', { clientId: 'rp9' }, signer);

    expect(appended.id).toBe('000000000005');
  });

  it('行の本文を改ざんすると 3010 で拒否する', async () => {
    const log = await seeded();
    const lines = (await log.exportLog({ types: ['presentation'] })).split('\n');
    const tampered = JSON.parse(lines[0] as string) as { payload: Record<string, unknown> };
    tampered.payload.clientId = 'evil';
    lines[0] = JSON.stringify(tampered);

    await expect(
      new DashboardLog(new MemoryStorage()).importLog(lines.join('\n'), verifierKey),
    ).rejects.toThrow(sigInvalid);
  });

  it('別の鍵で署名された行が混ざると 3010 で拒否する', async () => {
    const log = await seeded();
    const other = new DashboardLog(new MemoryStorage(), fixedNow('2026-10-01T00:00:00.000Z'));
    await other.append('presentation', { clientId: 'rp1' }, createPrivateKeySignerFromFill(9));
    const [foreign] = (await other.exportLog()).split('\n');
    const lines = (await log.exportLog({ rpIdentifier: 'rp1' })).split('\n');
    lines[0] = foreign as string;

    await expect(
      new DashboardLog(new MemoryStorage()).importLog(lines.join('\n'), verifierKey),
    ).rejects.toThrow(sigInvalid);
  });

  it('連番が隣り合う行の prevHash が崩れていると 3010 で拒否する（partial でも隣接検証は残る）', async () => {
    const log = await seeded();
    // seq 3,4 は隣り合う。間の行を抜かずに seq 4 だけ残すのではなく、seq 4 の id を 3 の直後へ偽装する。
    const lines = (await log.exportLog({ rpIdentifier: 'rp1' })).split('\n');
    const second = JSON.parse(lines[1] as string) as Record<string, unknown>;
    second.id = '000000000002'; // 先頭 (seq 1) の直後 = 隣接。実際の prevHash は seq 3 のハッシュ。
    lines[1] = JSON.stringify(second);

    await expect(
      new DashboardLog(new MemoryStorage()).importLog(lines.join('\n'), verifierKey),
    ).rejects.toThrow(sigInvalid);
  });

  it('partial 行の並びが連番の昇順でないと 3010 で拒否する', async () => {
    const log = await seeded();
    const lines = (await log.exportLog({ types: ['presentation'] })).split('\n');
    [lines[0], lines[1]] = [lines[1] as string, lines[0] as string];

    await expect(
      new DashboardLog(new MemoryStorage()).importLog(lines.join('\n'), verifierKey),
    ).rejects.toThrow(sigInvalid);
  });

  it('partial でない export の先頭が非 null prevHash だと従来どおり 3010（partial の宣言なしには緩めない）', async () => {
    const log = await seeded();
    const lines = (await log.exportLog({ types: ['consentRevoked'] })).split('\n');
    lines[lines.length - 1] = JSON.stringify({
      merkleRoot: rootOf(lines.join('\n')).merkleRoot,
      count: 1,
    });

    await expect(
      new DashboardLog(new MemoryStorage()).importLog(lines.join('\n'), verifierKey),
    ).rejects.toThrow(sigInvalid);
  });

  it('partial が true 以外だと形式不正（2001）', async () => {
    const log = await seeded();
    const lines = (await log.exportLog({ types: ['consentRevoked'] })).split('\n');
    lines[lines.length - 1] = JSON.stringify({ ...rootOf(lines.join('\n')), partial: 'yes' });

    await expect(
      new DashboardLog(new MemoryStorage()).importLog(lines.join('\n'), verifierKey),
    ).rejects.toThrow(new VericertsError(ErrorCodes.INVALID_DID));
  });
});
