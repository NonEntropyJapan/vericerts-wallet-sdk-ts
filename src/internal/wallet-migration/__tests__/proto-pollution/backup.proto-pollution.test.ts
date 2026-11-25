/**
 * W2W バックアップの `Object.prototype` 汚染耐性テスト。
 *
 * `opts.iterations` をプロトタイプ鎖で読むと、反復回数を**指定していない**正当な
 * エクスポートでも継承値が `validateKdfParams` を経ずに `deriveBits` へ届き、
 * バックアップの KDF 反復回数が攻撃者の値まで弱められる（オフライン総当たりが現実的になる）。
 *
 * `includeVCs` / `includePersonas` / `excludeFormats` / `recipientKey` も同じ経路で、
 * 出力するバックアップの内容とヘッダが継承値に左右される。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import { exportBackup, importBackup } from '../../backup.js';
import type { BackupSource } from '../../types.js';
import { testSigner } from '../fixtures.js';

const PASSPHRASE = 'correct-horse-battery';

const SOURCE: BackupSource = {
  walletId: 'urn:uuid:wallet-1',
  credentials: [{ id: 'vc-1', format: 'vc+sd-jwt', data: 'eyJ...vc1' }],
  personas: [{ id: 'persona-0', data: JSON.stringify({ index: 0 }) }],
  dids: [{ id: 'did:key:zAbc', data: JSON.stringify({ did: 'did:key:zAbc' }) }],
  settings: JSON.stringify({ locale: 'ja' }),
};

describe('exportBackup の Object.prototype 汚染耐性', () => {
  it('継承した iterations で KDF 反復回数を弱められない', async () => {
    const signer = testSigner();
    // `iterations` を**明示指定しない**こと。明示すると own 値が汚染値を隠してしまい、
    // 修正前でも pass するトートロジーになる（既定値との比較で検出する）。
    const backup = await withPollutedPrototypeAsync({ iterations: 1 }, () =>
      exportBackup(SOURCE, signer, { passphrase: PASSPHRASE }),
    );
    // 汚染値 1 ではなく既定の反復回数（600,000）が使われること。
    expect(backup.encryption.kdfParams.iterations).toBe(600_000);
  });

  it('iterations 未指定でも継承値ではなく既定値を使う', async () => {
    const signer = testSigner();
    const backup = await withPollutedPrototypeAsync({ iterations: 1 }, () =>
      exportBackup(SOURCE, signer, { passphrase: PASSPHRASE }),
    );
    expect(backup.encryption.kdfParams.iterations).toBeGreaterThan(1);
  });

  it('継承した includeVCs: false でバックアップ内容を空にできない', async () => {
    const signer = testSigner();
    const backup = await withPollutedPrototypeAsync({ includeVCs: false }, () =>
      exportBackup(SOURCE, signer, { passphrase: PASSPHRASE, iterations: 1000 }),
    );
    expect(backup.credentials).toHaveLength(1);
  });

  it('継承した excludeFormats でエントリを落とせない', async () => {
    const signer = testSigner();
    const backup = await withPollutedPrototypeAsync({ excludeFormats: ['vc+sd-jwt'] }, () =>
      exportBackup(SOURCE, signer, { passphrase: PASSPHRASE, iterations: 1000 }),
    );
    expect(backup.credentials).toHaveLength(1);
  });

  it('継承した recipientKey はバックアップヘッダに載らない', async () => {
    const signer = testSigner();
    const backup = await withPollutedPrototypeAsync(
      { recipientKey: { kty: 'EC', crv: 'P-256', x: 'attacker', y: 'attacker' } },
      () => exportBackup(SOURCE, signer, { passphrase: PASSPHRASE, iterations: 1000 }),
    );
    expect(backup.encryption.recipientKey).toBeUndefined();
  });

  it('明示的なオプションは従来どおり反映され、往復できる（正常系）', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, {
      passphrase: PASSPHRASE,
      iterations: 1000,
      includeVCs: false,
    });
    expect(backup.encryption.kdfParams.iterations).toBe(1000);
    expect(backup.credentials).toHaveLength(0);

    const full = await exportBackup(SOURCE, signer, { passphrase: PASSPHRASE, iterations: 1000 });
    const restored = await importBackup(full, PASSPHRASE, signer.publicKeyJwk);
    expect(restored.credentials).toHaveLength(1);
  });
});
