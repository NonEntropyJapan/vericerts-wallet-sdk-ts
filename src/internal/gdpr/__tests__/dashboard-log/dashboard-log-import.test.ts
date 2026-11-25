/**
 * DashboardLog.importLog（JWS 署名付き NDJSON の検証付きインポート）の単体テスト。
 *
 * - export → import ラウンドトリップでエントリ・署名・prevHash を保って復元する（GDPR Art.20）。
 * - 署名検証失敗・本文改ざん・ルートハッシュ改ざん・count 不一致は 3010 で拒否する。
 * - ルートハッシュ行欠落は 2001、既存ログが空でない場合は 10604 を送出する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { decodeCompactJws, verifyWithJwk } from '../../../credential/vc/jws.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import type { DashboardLogVerifierKey } from '../../dashboard-log/dashboard-log-import.js';
import { createPrivateKeySignerFromFill, fixedNow, testSigner } from './dashboard-log-helpers.js';

describe('DashboardLog importLog', () => {
  /** signer の公開鍵から import 検証鍵を組み立てる（署名時の alg + JWK）。 */
  function verifierKeyOf(signer: ReturnType<typeof testSigner>): DashboardLogVerifierKey {
    return { alg: signer.alg, publicKeyJwk: signer.publicKeyJwk };
  }

  /** エントリ 2 件を追記した source ログとその export NDJSON を用意する。 */
  async function exportedSource(): Promise<{
    ndjson: string;
    signer: ReturnType<typeof testSigner>;
  }> {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-07-02T00:00:00.000Z'));
    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);
    await log.append('consentRevoked', { scope: { purpose: 'kyc' } }, signer);
    return { ndjson: await log.exportLog(), signer };
  }

  it('export → import ラウンドトリップでエントリ・署名・prevHash を保って復元する', async () => {
    const { ndjson, signer } = await exportedSource();
    const dest = new DashboardLog(new MemoryStorage());

    const imported = await dest.importLog(ndjson, verifierKeyOf(signer));

    expect(imported).toBe(2);
    const entries = await dest.list();
    expect(entries.map((e) => e.type)).toEqual(['correctionRequest', 'consentRevoked']);
    // ID は追記順の連番で振り直される（辞書順 = chain 順）。
    expect(entries.map((e) => e.id)).toEqual(['000000000000', '000000000001']);
    // prevHash chain と署名が verbatim 保持され、再 export しても同一内容になる。
    expect(await dest.exportLog()).toBe(ndjson);
    // 復元した各エントリの署名は元の signer 公開鍵で検証できる。
    for (const entry of entries) {
      const decoded = decodeCompactJws(entry.signature);
      expect(verifyWithJwk('ES256K', decoded, signer.publicKeyJwk)).toBe(true);
    }
  });

  it('空ログの export（ルートハッシュ行のみ）を import すると 0 件になる', async () => {
    const signer = testSigner();
    const source = new DashboardLog(new MemoryStorage());
    const ndjson = await source.exportLog();
    const dest = new DashboardLog(new MemoryStorage());

    expect(await dest.importLog(ndjson, verifierKeyOf(signer))).toBe(0);
    expect(await dest.list()).toEqual([]);
  });

  it('検証鍵が署名者と異なると署名検証に失敗して拒否する（3010）', async () => {
    const { ndjson } = await exportedSource();
    // 別の秘密鍵から作った検証鍵（署名者と不一致）。
    const wrongKey = verifierKeyOf(createPrivateKeySignerFromFill(9));
    const dest = new DashboardLog(new MemoryStorage());

    await expect(dest.importLog(ndjson, wrongKey)).rejects.toMatchObject({ code: '3010' });
    // 検証失敗時は storage に一切書き込まない。
    expect(await dest.list()).toEqual([]);
  });

  it('エントリ本文を改ざんすると署名検証に失敗して拒否する（3010）', async () => {
    const { ndjson, signer } = await exportedSource();
    const lines = ndjson.split('\n');
    const tampered = JSON.parse(lines[0] as string) as { payload: { reason: string } };
    tampered.payload.reason = 'tampered';
    lines[0] = JSON.stringify(tampered);
    const dest = new DashboardLog(new MemoryStorage());

    await expect(dest.importLog(lines.join('\n'), verifierKeyOf(signer))).rejects.toMatchObject({
      code: '3010',
    });
  });

  it('Merkle ルートハッシュ行が改ざんされると拒否する（3010）', async () => {
    const { ndjson, signer } = await exportedSource();
    const lines = ndjson.split('\n');
    lines[lines.length - 1] = JSON.stringify({ merkleRoot: 'AAAA', count: 2 });
    const dest = new DashboardLog(new MemoryStorage());

    await expect(dest.importLog(lines.join('\n'), verifierKeyOf(signer))).rejects.toMatchObject({
      code: '3010',
    });
  });

  it('エントリが 1 件削除され count が食い違うと拒否する（3010）', async () => {
    const { ndjson, signer } = await exportedSource();
    const lines = ndjson.split('\n');
    // 先頭エントリ行を削除（count=2 のまま行数が減る）。
    lines.splice(0, 1);
    const dest = new DashboardLog(new MemoryStorage());

    await expect(dest.importLog(lines.join('\n'), verifierKeyOf(signer))).rejects.toMatchObject({
      code: '3010',
    });
  });

  it('ルートハッシュ行を欠く不正な NDJSON は形式不正で拒否する（2001）', async () => {
    const signer = testSigner();
    const dest = new DashboardLog(new MemoryStorage());

    await expect(dest.importLog('', verifierKeyOf(signer))).rejects.toMatchObject({ code: '2001' });
  });

  it('既存ログが空でない場合は 10604 を送出し何も変更しない', async () => {
    const { ndjson, signer } = await exportedSource();
    const dest = new DashboardLog(new MemoryStorage());
    // 既存エントリを 1 件追記しておく。
    await dest.append('presentation', { rpIdentifier: 'rp-1' }, signer);

    await expect(dest.importLog(ndjson, verifierKeyOf(signer))).rejects.toMatchObject({
      code: '10604',
    });
    // 既存エントリは維持され import 分は追加されない。
    expect(await dest.list()).toHaveLength(1);
  });
});
