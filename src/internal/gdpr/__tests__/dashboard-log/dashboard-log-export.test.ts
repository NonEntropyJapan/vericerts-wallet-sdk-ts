/**
 * DashboardLog.exportLog（ユーザー制御ログの JWS 署名付き NDJSON エクスポート）の単体テスト。
 *
 * - exportLog はユーザー制御ログを追記順の JWS 署名付き NDJSON で出力し、末尾に Merkle ルートハッシュ行を
 *   付与する。filter で絞り込み、署名は signer 公開鍵で検証可能。削除監査記録は対象外（GDPR Art.15/20）。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { MemoryStorage } from '../../../../storage/storage.js';
import { decodeCompactJws, verifyWithJwk } from '../../../credential/vc/jws.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import { fixedNow, testSigner } from './dashboard-log-helpers.js';

describe('DashboardLog exportLog', () => {
  /** NDJSON テキストを行配列にパースする（末尾の Merkle ルートハッシュ行を含む）。 */
  function parseNdjson(ndjson: string): Record<string, unknown>[] {
    return ndjson.split('\n').map((line) => JSON.parse(line) as Record<string, unknown>);
  }

  it('追記順の各エントリ行 + 末尾に Merkle ルートハッシュ行を出力する', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-07-02T00:00:00.000Z'));
    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);
    const last = await log.append('consentRevoked', { scope: { purpose: 'kyc' } }, signer);

    const ndjson = await log.exportLog();
    const lines = parseNdjson(ndjson);

    // エントリ 2 行 + Merkle ルートハッシュ行 1 行。
    expect(lines).toHaveLength(3);
    expect(lines[0]?.type).toBe('correctionRequest');
    expect(lines[1]?.type).toBe('consentRevoked');
    // 末尾行は Merkle ルートハッシュ（= 最終エントリ signing-input の SHA-256 base64url）と件数。
    const lastSigningInput = last.signature.split('.').slice(0, 2).join('.');
    const expectedRoot = base64urlnopad.encode(sha256(new TextEncoder().encode(lastSigningInput)));
    expect(lines[2]).toEqual({ merkleRoot: expectedRoot, count: 2 });
  });

  it('各エントリ行は追記時の JWS 署名を保持し signer 公開鍵で検証できる', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-07-02T00:00:00.000Z'));
    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);

    const ndjson = await log.exportLog();
    const entryLine = parseNdjson(ndjson)[0] as { signature: string };

    const decoded = decodeCompactJws(entryLine.signature);
    expect(verifyWithJwk('ES256K', decoded, signer.publicKeyJwk)).toBe(true);
  });

  it('filter は export 対象を絞り込む（AND 条件）', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());
    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);
    await log.append('consentRevoked', { scope: { purpose: 'kyc' } }, signer);
    await log.append('presentation', { rpIdentifier: 'rp-1' }, signer);

    const ndjson = await log.exportLog({ types: ['correctionRequest', 'presentation'] });
    const lines = parseNdjson(ndjson);

    // 一致 2 エントリ + ルートハッシュ行。
    expect(lines).toHaveLength(3);
    expect(lines.slice(0, 2).map((l) => l.type)).toEqual(['correctionRequest', 'presentation']);
    expect(lines[2]?.count).toBe(2);
  });

  it('削除監査記録（deletion-log/）は export 対象外', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());
    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);
    await log.appendDeletionRecord('vc-9', signer);

    const lines = parseNdjson(await log.exportLog());

    // ユーザー制御ログ 1 件 + ルートハッシュ行のみ（credentialDeleted は含まない）。
    expect(lines).toHaveLength(2);
    expect(lines[0]?.type).toBe('correctionRequest');
    expect(lines[1]?.count).toBe(1);
  });

  it('空ログの export は Merkle ルートハッシュ行のみ（merkleRoot: null）', async () => {
    const log = new DashboardLog(new MemoryStorage());

    const lines = parseNdjson(await log.exportLog());

    expect(lines).toEqual([{ merkleRoot: null, count: 0 }]);
  });

  it('一致なし filter は Merkle ルートハッシュ行のみ（count: 0）', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());
    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);

    const lines = parseNdjson(await log.exportLog({ types: ['authFailure'] }));

    expect(lines).toEqual([{ merkleRoot: null, count: 0 }]);
  });
});
