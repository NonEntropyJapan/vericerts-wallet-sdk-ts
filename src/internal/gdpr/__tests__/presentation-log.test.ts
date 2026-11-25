/**
 * 提示イベントの Dashboard ログ記録のテスト。
 *
 * 実 `DashboardLog` + `MemoryStorage` + 実鍵を用いる（モック禁止）。
 * - `presentation` エントリが署名付きで永続化され、署名を公開鍵で検証できる。
 * - payload に提示先・nonce・VC ID・開示クレーム**名**・目的を含む。
 * - 開示クレームの**値**と署名鍵・storage ハンドルを payload に含めない（データ最小化）。
 * - 任意メンバ未指定時はプロパティ自体を生やさない（正準 payload の安定）。
 * - 連続記録で Merkle chain（prevHash）が連結される。
 * - 不正な `event` でも同期例外にせず Promise の reject になる（失敗経路の一本化）。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { decodeCompactJws, verifyWithJwk } from '../../credential/vc/jws.js';
import { DashboardLog } from '../dashboard-log/dashboard-log.js';
import {
  buildPresentationEventPayload,
  logPresentationEvent,
  type PresentationEventInput,
} from '../presentation-log.js';
import { fixedNow, testSigner } from './dashboard-log/dashboard-log-helpers.js';

const SIGNER = testSigner();
const FIXED_NOW = fixedNow('2026-08-28T00:00:00.000Z');

function newLog(): DashboardLog {
  return new DashboardLog(new MemoryStorage(), FIXED_NOW);
}

describe('logPresentationEvent', () => {
  it('presentation エントリを署名付きで永続化する', async () => {
    const log = newLog();
    const entry = await logPresentationEvent({
      log,
      signer: SIGNER,
      clientId: 'https://verifier.example',
      nonce: 'n-1',
    });

    expect(entry.type).toBe('presentation');
    expect(entry.recordedAt).toBe('2026-08-28T00:00:00.000Z');
    expect(entry.prevHash).toBeNull();

    const decoded = decodeCompactJws(entry.signature);
    expect(verifyWithJwk('ES256K', decoded, SIGNER.publicKeyJwk)).toBe(true);

    // 永続化されており list から読み出せる。
    const listed = await log.list();
    expect(listed).toHaveLength(1);
    expect(listed[0]?.type).toBe('presentation');
  });

  it('payload に提示先・nonce・VC ID・開示クレーム名・目的を記録する', async () => {
    const entry = await logPresentationEvent({
      log: newLog(),
      signer: SIGNER,
      clientId: 'https://verifier.example',
      nonce: 'n-1',
      credentialIds: ['pid-1'],
      disclosedClaims: ['given_name', 'age_over_18'],
      purpose: 'age-verification',
    });

    expect(entry.payload).toEqual({
      clientId: 'https://verifier.example',
      nonce: 'n-1',
      credentialIds: ['pid-1'],
      disclosedClaims: ['given_name', 'age_over_18'],
      purpose: 'age-verification',
    });
  });

  it('開示クレームの値・署名鍵・storage ハンドルを payload に残さない（データ最小化）', async () => {
    const log = newLog();
    const entry = await logPresentationEvent({
      log,
      signer: SIGNER,
      clientId: 'https://verifier.example',
      disclosedClaims: ['given_name'],
    });

    const serialized = JSON.stringify(entry.payload);
    // クレーム名は残すが、値（'Alice'）は入力にも payload にも現れない。
    expect(serialized).toContain('given_name');
    expect(serialized).not.toContain('Alice');
    // 記録先・署名鍵は payload の内容ではない。
    expect(Object.keys(entry.payload)).toEqual(['clientId', 'disclosedClaims']);
    expect(serialized).not.toContain('publicKeyJwk');
  });

  it('任意メンバ未指定時はプロパティ自体を生やさない', () => {
    const payload = buildPresentationEventPayload({
      log: newLog(),
      signer: SIGNER,
      clientId: 'https://verifier.example',
    });
    expect(payload).toEqual({ clientId: 'https://verifier.example' });
    expect(Object.hasOwn(payload, 'nonce')).toBe(false);
    expect(Object.hasOwn(payload, 'purpose')).toBe(false);
  });

  it('配列メンバは複製して保持する（呼び出し側の後続変更が payload に波及しない）', () => {
    const claims = ['given_name'];
    const payload = buildPresentationEventPayload({
      log: newLog(),
      signer: SIGNER,
      clientId: 'https://verifier.example',
      disclosedClaims: claims,
    });
    claims.push('birth_date');
    expect(payload.disclosedClaims).toEqual(['given_name']);
  });

  it('event が不正でも同期例外にせず reject する（失敗経路を Promise に一本化）', async () => {
    // 呼び出し側が `try` と `.catch()` の両方を書かなくても取りこぼさないことの回帰テスト。
    // `as` は型検査を通らない不正入力（ランタイムでのみ起こり得る）を再現するために用いる。
    let thrownSynchronously: unknown;
    let returned: Promise<unknown> | undefined;
    try {
      returned = logPresentationEvent(undefined as unknown as PresentationEventInput);
    } catch (error) {
      thrownSynchronously = error;
    }

    expect(thrownSynchronously).toBeUndefined();
    await expect(returned).rejects.toBeInstanceOf(TypeError);
  });

  it('連続記録で Merkle chain（prevHash）が連結される', async () => {
    const log = newLog();
    const first = await logPresentationEvent({
      log,
      signer: SIGNER,
      clientId: 'https://verifier.example',
    });
    const second = await logPresentationEvent({
      log,
      signer: SIGNER,
      clientId: 'https://other.example',
    });

    expect(first.prevHash).toBeNull();
    expect(second.prevHash).not.toBeNull();
    expect(second.id).not.toBe(first.id);
  });
});
