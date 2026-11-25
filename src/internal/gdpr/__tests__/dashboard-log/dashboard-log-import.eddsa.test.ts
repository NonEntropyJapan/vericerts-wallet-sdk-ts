/**
 * DashboardLog の EdDSA（Ed25519）署名によるエクスポート / インポートのテスト。
 *
 * ES256K 経路は `dashboard-log-import.test.ts` が担当し、本ファイルは
 * `DashboardLogVerifierKey.alg` が `"EdDSA"` を取り得るようになったことの正常系を固定する。
 *
 * 検証内容:
 * - EdDSA で署名したログが export → import ラウンドトリップで復元でき、各エントリの署名が
 *   OKP 鍵で検証できる。
 * - 署名ヘッダの alg が `EdDSA` になっている。
 * - 別の Ed25519 鍵を検証鍵に渡すと 3010（fail-closed の維持）。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { decodeCompactJws, verifyWithJwk } from '../../../credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import type { DashboardLogVerifierKey } from '../../dashboard-log/dashboard-log-import.js';
import { createEddsaSignerFromFill, fixedNow } from './dashboard-log-helpers.js';

/** EdDSA でエントリ 2 件を追記した source ログと export NDJSON を用意する。 */
async function exportedSource(): Promise<{
  ndjson: string;
  signer: ReturnType<typeof createEddsaSignerFromFill>;
}> {
  const signer = createEddsaSignerFromFill(41);
  const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-07-02T00:00:00.000Z'));
  await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);
  await log.append('consentRevoked', { scope: { purpose: 'kyc' } }, signer);
  return { ndjson: await log.exportLog(), signer };
}

describe('DashboardLog importLog（EdDSA / Ed25519）', () => {
  it('export → import ラウンドトリップで復元し、各エントリの署名が OKP 鍵で検証できる', async () => {
    const { ndjson, signer } = await exportedSource();
    const dest = new DashboardLog(new MemoryStorage());
    const verifierKey: DashboardLogVerifierKey = {
      alg: signer.alg,
      publicKeyJwk: signer.publicKeyJwk,
    };

    expect(await dest.importLog(ndjson, verifierKey)).toBe(2);

    const entries = await dest.list();
    expect(entries.map((e) => e.type)).toEqual(['correctionRequest', 'consentRevoked']);
    expect(await dest.exportLog()).toBe(ndjson);
    for (const entry of entries) {
      const decoded = decodeCompactJws(entry.signature);
      expect(verifyWithJwk('EdDSA', decoded, signer.publicKeyJwk)).toBe(true);
    }
  });

  it('署名ヘッダの alg が EdDSA・公開鍵が OKP になる', async () => {
    const { signer } = await exportedSource();
    expect(signer.alg).toBe('EdDSA');
    expect(signer.publicKeyJwk.kty).toBe('OKP');
    expect(signer.publicKeyJwk.crv).toBe('Ed25519');
    // OKP 鍵は `y` を持たない（RFC 8037）。
    expect(signer.publicKeyJwk.y).toBeUndefined();
  });

  it('別の Ed25519 鍵を検証鍵に渡すと 3010', async () => {
    const { ndjson } = await exportedSource();
    const other = createEddsaSignerFromFill(43);
    const dest = new DashboardLog(new MemoryStorage());
    try {
      await dest.importLog(ndjson, { alg: other.alg, publicKeyJwk: other.publicKeyJwk });
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.SIG_INVALID);
    }
  });
});
