/**
 * Transaction Data 同意の提示ログ記録の統合テスト。
 *
 * 実 `DashboardLog` + `MemoryStorage` + 実鍵を用い、抽出 → hash → 記録の一連を検証する（モック禁止）。
 * - `transactionDataConsent` エントリが署名付きで永続化され、署名を公開鍵で検証できる。
 * - payload に種別・hash・alg を含み、Transaction Data 本文（金額等）を含めない（データ最小化）。
 * - 連続記録で Merkle chain（prevHash）が連結される。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { MemoryStorage } from '../../../../storage/storage.js';
import { decodeCompactJws, verifyWithJwk } from '../../../credential/vc/jws.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { DashboardLog } from '../../../gdpr/dashboard-log/dashboard-log.js';
import {
  buildTransactionDataConsentPayload,
  recordTransactionDataConsent,
} from '../consent-log.js';
import { extractTransactionData } from '../extract.js';
import { computeTransactionDataHashes } from '../hashes.js';

const SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256K');
const FIXED_NOW = (): Date => new Date('2026-07-07T00:00:00.000Z');

function encodeTd(obj: Record<string, unknown>): string {
  return base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(obj)));
}

const RAW = [
  encodeTd({ type: 'payment', credential_ids: ['pid'], amount: '100.00', recipient: 'ACME' }),
];
const ENTRIES = extractTransactionData(RAW);

describe('recordTransactionDataConsent', () => {
  it('transactionDataConsent エントリを署名付きで永続化する', async () => {
    const log = new DashboardLog(new MemoryStorage(), FIXED_NOW);
    const entry = await recordTransactionDataConsent(
      log,
      { clientId: 'https://verifier.example', nonce: 'n-1', transactionData: ENTRIES },
      SIGNER,
    );

    expect(entry.type).toBe('transactionDataConsent');
    expect(entry.recordedAt).toBe('2026-07-07T00:00:00.000Z');
    expect(entry.prevHash).toBeNull();

    // 署名（コンパクト JWS）を signer 公開鍵で検証できる。
    const decoded = decodeCompactJws(entry.signature);
    expect(verifyWithJwk('ES256K', decoded, SIGNER.publicKeyJwk)).toBe(true);

    // 永続化を経て list からも取得できる。
    const listed = await log.list();
    expect(listed).toHaveLength(1);
    expect(listed[0]?.type).toBe('transactionDataConsent');
  });

  it('payload に種別・hash・alg を含み、Transaction Data 本文を含めない', async () => {
    const payload = buildTransactionDataConsentPayload({
      clientId: 'https://verifier.example',
      nonce: 'n-1',
      transactionData: ENTRIES,
    });

    expect(payload.transactionDataTypes).toEqual(['payment']);
    expect(payload.transactionDataHashes).toEqual(computeTransactionDataHashes(ENTRIES));
    expect(payload.hashAlgorithm).toBe('sha-256');

    // 金額・相手方などの本文はログ payload に漏れない（データ最小化）。
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain('100.00');
    expect(serialized).not.toContain('ACME');
  });

  it('連続記録で Merkle chain（prevHash）が連結される', async () => {
    const log = new DashboardLog(new MemoryStorage(), FIXED_NOW);
    const first = await recordTransactionDataConsent(
      log,
      { clientId: 'https://verifier.example', nonce: 'n-1', transactionData: ENTRIES },
      SIGNER,
    );
    const second = await recordTransactionDataConsent(
      log,
      { clientId: 'https://verifier.example', nonce: 'n-2', transactionData: ENTRIES },
      SIGNER,
    );

    expect(first.prevHash).toBeNull();
    expect(second.prevHash).not.toBeNull();
    const listed = await log.list();
    expect(listed.map((e) => e.id)).toEqual([first.id, second.id]);
  });
});
