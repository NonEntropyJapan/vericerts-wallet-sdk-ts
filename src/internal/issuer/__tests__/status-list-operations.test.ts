/**
 * Status List 運用ヘルパー（作成 / idx 割当 / revoke・suspend / snapshot 復元 / 再署名）の
 * ユニットテスト（実鍵・実圧縮・モック禁止）。
 *
 * 検証内容:
 * - createStatusList が全ビット 0 の新規リストを作る。
 * - allocateEntry が idx と VC 埋め込み用 status 参照を返す。
 * - revoke / suspend / unsuspend が purpose に応じて動き、用途違いを 3002 で拒否する。
 * - snapshot → restore でビット列と nextIndex が復元され、idx の二重割当が起きない。
 * - restore が不整合スナップショットを 3002 で拒否する。
 * - issueToken の ttlSeconds が exp を設定し、再署名で最新状態が反映される。
 */

import { describe, expect, it } from 'bun:test';
import { decodeCompactJws } from '../../credential/vc/jws.js';
import { createPrivateKeySigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { StatusListTokenPayload } from '../status-list-token.js';
import { createStatusList, StatusListManager } from '../token-status-list.js';

const SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256');
const URI = 'https://issuer.example/status/1';
const ISSUER = 'did:web:issuer.example';

/** revocation 用途の新規リストを作る。 */
function revocationList(size = 100): StatusListManager {
  return createStatusList({ uri: URI, issuer: ISSUER, size, bits: 1 });
}

/** suspension 用途の新規リストを作る。 */
function suspensionList(size = 100): StatusListManager {
  return createStatusList({ uri: URI, issuer: ISSUER, size, bits: 1, purpose: 'suspension' });
}

describe('createStatusList', () => {
  it('全ビット 0・未割当の新規リストを作る', () => {
    const list = revocationList(8);
    expect(list.size).toBe(8);
    expect(list.bits).toBe(1);
    expect(list.purpose).toBe('revocation');
    expect(list.nextIndex).toBe(0);
    expect(list.remaining).toBe(8);
    expect(list.getStatus(0)).toBe(0);
  });

  it('purpose 未指定なら revocation を既定にする', () => {
    expect(createStatusList({ uri: URI, issuer: ISSUER, size: 4 }).purpose).toBe('revocation');
  });
});

describe('StatusListManager.allocateEntry', () => {
  it('idx と VC 埋め込み用の status 参照を返す', () => {
    const list = revocationList();
    const first = list.allocateEntry();
    expect(first.idx).toBe(0);
    expect(first.status).toEqual({ status_list: { idx: 0, uri: URI } });

    const second = list.allocateEntry();
    expect(second.idx).toBe(1);
    expect(list.nextIndex).toBe(2);
    expect(list.remaining).toBe(98);
  });

  it('容量を使い切ると 3007 を投げる', () => {
    const list = revocationList(1);
    list.allocateEntry();
    try {
      list.allocateEntry();
      throw new Error('expected throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.STATUS_LIST_INDEX_EXHAUSTED);
    }
  });
});

describe('StatusListManager.revoke / suspend / unsuspend', () => {
  it('revoke で失効ビットが立ち isSet が true になる', () => {
    const list = revocationList();
    const { idx } = list.allocateEntry();
    expect(list.isSet(idx)).toBe(false);
    list.revoke(idx);
    expect(list.getStatus(idx)).toBe(1);
    expect(list.isSet(idx)).toBe(true);
  });

  it('suspend → unsuspend で停止と解除ができる', () => {
    const list = suspensionList();
    const { idx } = list.allocateEntry();
    list.suspend(idx);
    expect(list.isSet(idx)).toBe(true);
    list.unsuspend(idx);
    expect(list.isSet(idx)).toBe(false);
  });

  it('用途が違う操作を 3002 で拒否する', () => {
    const revocation = revocationList();
    const idx = revocation.allocate();
    expect(() => revocation.suspend(idx)).toThrow(VericertsError);
    expect(() => revocation.unsuspend(idx)).toThrow(VericertsError);

    const suspension = suspensionList();
    const sIdx = suspension.allocate();
    try {
      suspension.revoke(sIdx);
      throw new Error('expected throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
    }
  });

  it('容量外インデックスを 3002 で拒否する', () => {
    const list = revocationList(4);
    expect(() => list.revoke(100)).toThrow(VericertsError);
  });
});

describe('StatusListManager.snapshot / restore', () => {
  it('ビット列と nextIndex を復元し idx の二重割当を防ぐ', async () => {
    const list = revocationList(64);
    const a = list.allocateEntry().idx;
    list.allocateEntry();
    const c = list.allocateEntry().idx;
    list.revoke(a);
    list.revoke(c);

    // 永続化 → 別プロセス相当の復元。
    const snapshot = await list.snapshot();
    expect(snapshot.nextIndex).toBe(3);
    expect(JSON.parse(JSON.stringify(snapshot))).toEqual(snapshot);

    const restored = await StatusListManager.restore(snapshot);
    expect(restored.uri).toBe(URI);
    expect(restored.issuer).toBe(ISSUER);
    expect(restored.purpose).toBe('revocation');
    expect(restored.size).toBe(64);
    expect(restored.getStatus(a)).toBe(1);
    expect(restored.getStatus(1)).toBe(0);
    expect(restored.getStatus(c)).toBe(1);

    // 復元後の払い出しは 3 から続く（0..2 を再利用しない）。
    expect(restored.nextIndex).toBe(3);
    expect(restored.allocate()).toBe(3);
  });

  it('suspension リストも用途込みで復元する', async () => {
    const list = suspensionList(16);
    const { idx } = list.allocateEntry();
    list.suspend(idx);
    const restored = await StatusListManager.restore(await list.snapshot());
    expect(restored.purpose).toBe('suspension');
    expect(restored.isSet(idx)).toBe(true);
    // 用途が保たれているので解除操作が通る。
    restored.unsuspend(idx);
    expect(restored.isSet(idx)).toBe(false);
  });

  it('nextIndex が容量を超えるスナップショットを 3002 で拒否する', async () => {
    const snapshot = await revocationList(8).snapshot();
    await expect(StatusListManager.restore({ ...snapshot, nextIndex: 9 })).rejects.toThrow(
      VericertsError,
    );
    await expect(StatusListManager.restore({ ...snapshot, nextIndex: -1 })).rejects.toThrow(
      VericertsError,
    );
  });

  it('size と整合しないビット列を 3002 で拒否する', async () => {
    const snapshot = await revocationList(8).snapshot();
    await expect(StatusListManager.restore({ ...snapshot, size: 4096 })).rejects.toThrow(
      VericertsError,
    );
  });
});

describe('StatusListManager.issueToken（再署名）', () => {
  it('ttlSeconds から exp を計算する', async () => {
    const list = revocationList();
    const token = await list.issueToken(SIGNER, { iatSeconds: 1_700_000_000, ttlSeconds: 60 });
    const payload = decodeCompactJws(token).payload as unknown as StatusListTokenPayload;
    expect(payload.iat).toBe(1_700_000_000);
    expect(payload.exp).toBe(1_700_000_060);
  });

  it('expSeconds が ttlSeconds より優先される', async () => {
    const list = revocationList();
    const token = await list.issueToken(SIGNER, {
      iatSeconds: 1_700_000_000,
      ttlSeconds: 60,
      expSeconds: 1_700_000_500,
    });
    const payload = decodeCompactJws(token).payload as unknown as StatusListTokenPayload;
    expect(payload.exp).toBe(1_700_000_500);
  });

  it('不正な ttlSeconds を 3002 で拒否する', async () => {
    const list = revocationList();
    await expect(list.issueToken(SIGNER, { ttlSeconds: 0 })).rejects.toThrow(VericertsError);
  });

  it('revoke 後の再署名で最新の失効状態が反映される', async () => {
    const list = revocationList();
    const { idx } = list.allocateEntry();
    const before = await list.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    list.revoke(idx);
    const after = await list.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    expect(after).not.toBe(before);
  });
});
