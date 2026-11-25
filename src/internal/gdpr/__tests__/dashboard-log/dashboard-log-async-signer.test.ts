/**
 * DashboardLog の非同期 signer 受け入れ（`AnyCredentialSigner`）の単体テスト。
 *
 * K3（Passkey-PRF による Dashboard ログ署名鍵）では署名が非抽出 CryptoKey 越し（Web Crypto）になり
 * 非同期化するため、`append` / `appendDeletionRecord` は同期 `CredentialSigner` と非同期
 * `AsyncCredentialSigner` の双方を受け付ける。ここでは以下を回帰として固定する:
 *
 * - 非同期 signer で追記したエントリの JWS が signer 公開鍵で検証できる。
 * - 同期 signer と、それを包んだ非同期 signer の出力がバイト単位で一致する（後方互換。
 *   `signCompactJwsAsync` は signing-input の組み立てを同期版と共有し、`ES256` は RFC6979
 *   決定論的署名のため等価比較が成立する）。
 * - 非同期 signer の `kid` が JWS ヘッダへ伝播し、未指定時はヘッダに `kid` プロパティが存在しない。
 * - 署名鍵・アルゴリズムを chain 途中で切り替えても `prevHash` 連続性が保たれる（K2 → K3 移行時に
 *   既存エントリの chain が断絶しないこと）。
 *
 * 検証鍵の多鍵解決（`kid` による鍵選択）は 実装済みで、回帰は
 * `dashboard-log-verify-resolver.test.ts` が持つ（本ファイルは署名側の挙動だけを固定する）。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import {
  type AsyncCredentialSigner,
  type CredentialSigner,
  createPrivateKeySigner,
} from '../../../credential/index.js';
import { decodeCompactJws, verifyWithJwk } from '../../../credential/vc/jws.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import { signingInputHash } from '../../dashboard-log/dashboard-log-shared.js';
import { createPrivateKeySignerFromFill, fixedNow } from './dashboard-log-helpers.js';

const NOW = '2026-09-10T00:00:00.000Z';

/** 決定的な 32B P-256 秘密鍵（全バイト `fill`）から ES256 signer を作る。 */
function es256Signer(fill: number): CredentialSigner {
  return createPrivateKeySigner(new Uint8Array(32).fill(fill), 'ES256');
}

/**
 * 同期 signer を非同期 signer として包む（Web Crypto 署名の代役）。
 *
 * 署名バイト列は包んだ同期 signer と同一のため、同期経路との出力一致を検証できる。
 * `kid` は指定時のみプロパティを持たせる（`buildJwsHeader` が `Object.hasOwn` で有無を判定するため、
 * `kid: undefined` を常に置くと「未指定」の再現にならない）。
 */
function asAsyncSigner(signer: CredentialSigner, kid?: string): AsyncCredentialSigner {
  const base = {
    alg: signer.alg,
    publicKeyJwk: signer.publicKeyJwk,
    sign: async (signingInput: Uint8Array): Promise<Uint8Array> => signer.sign(signingInput),
  };
  return kid === undefined ? base : { ...base, kid };
}

describe('DashboardLog 非同期 signer', () => {
  it('非同期 signer で追記したエントリの JWS が signer 公開鍵で検証できる', async () => {
    const signer = asAsyncSigner(es256Signer(11));
    const log = new DashboardLog(new MemoryStorage(), fixedNow(NOW));

    const entry = await log.append('presentation', { rpIdentifier: 'rp-1' }, signer);

    expect(entry.type).toBe('presentation');
    expect(entry.recordedAt).toBe(NOW);
    expect(entry.prevHash).toBeNull();
    const decoded = decodeCompactJws(entry.signature);
    expect(verifyWithJwk('ES256', decoded, signer.publicKeyJwk)).toBe(true);
    // 署名対象は正準 payload（type / payload / recordedAt / prevHash）。
    expect(decoded.payload.type).toBe('presentation');
    expect(decoded.payload.prevHash).toBeNull();
    // 永続化されている（storage 経由で読み戻せる）。
    expect(await log.list()).toEqual([entry]);
  });

  it('同期 signer と非同期ラップ版の JWS はバイト単位で一致する（後方互換）', async () => {
    const syncSigner = es256Signer(11);
    const asyncSigner = asAsyncSigner(syncSigner);
    const syncLog = new DashboardLog(new MemoryStorage(), fixedNow(NOW));
    const asyncLog = new DashboardLog(new MemoryStorage(), fixedNow(NOW));

    const payload = { rpIdentifier: 'rp-1', purpose: 'kyc' };
    const fromSync = await syncLog.append('presentation', payload, syncSigner);
    const fromAsync = await asyncLog.append('presentation', payload, asyncSigner);

    // ES256 は RFC6979 決定論的署名のため、signing-input が同一なら署名も一致する。
    expect(fromAsync.signature).toBe(fromSync.signature);
    expect(fromAsync).toEqual(fromSync);
  });

  it('非同期 signer の kid が JWS ヘッダへ伝播する', async () => {
    const signer = asAsyncSigner(es256Signer(11), 'test-kid-1');
    const log = new DashboardLog(new MemoryStorage(), fixedNow(NOW));

    const entry = await log.append('presentation', { rpIdentifier: 'rp-1' }, signer);

    const header = decodeCompactJws(entry.signature).header;
    expect(header).toEqual({ alg: 'ES256', kid: 'test-kid-1', typ: 'JWT' });
  });

  it('kid 未指定の非同期 signer では JWS ヘッダに kid プロパティが存在しない', async () => {
    const signer = asAsyncSigner(es256Signer(11));
    const log = new DashboardLog(new MemoryStorage(), fixedNow(NOW));

    const entry = await log.append('presentation', { rpIdentifier: 'rp-1' }, signer);

    const header = decodeCompactJws(entry.signature).header;
    // `undefined` ではなくプロパティ自体が存在しないこと（`buildJwsHeader` の契約）。
    expect(Object.hasOwn(header, 'kid')).toBe(false);
    expect(header).toEqual({ alg: 'ES256', typ: 'JWT' });
  });

  it('署名鍵・alg を chain 途中で切り替えても prevHash 連続性が保たれる（K2 → K3 移行）', async () => {
    const legacy = createPrivateKeySignerFromFill(7); // K2 想定: 同期 ES256K
    const migrated = asAsyncSigner(es256Signer(11), 'k3-kid'); // K3 想定: 非同期 ES256
    const log = new DashboardLog(new MemoryStorage(), fixedNow(NOW));

    const first = await log.append('presentation', { rpIdentifier: 'rp-1' }, legacy);
    const second = await log.append('presentation', { rpIdentifier: 'rp-2' }, migrated);

    expect(first.prevHash).toBeNull();
    // prevHash は signer 非依存（直前エントリの signing-input SHA-256）。
    expect(second.prevHash).toBe(signingInputHash(first));
    // 各エントリはそれぞれの鍵・alg で検証できる（旧エントリの署名は再署名されない）。
    expect(verifyWithJwk('ES256K', decodeCompactJws(first.signature), legacy.publicKeyJwk)).toBe(
      true,
    );
    expect(verifyWithJwk('ES256', decodeCompactJws(second.signature), migrated.publicKeyJwk)).toBe(
      true,
    );
  });

  it('appendDeletionRecord も非同期 signer を受け付ける', async () => {
    const signer = asAsyncSigner(es256Signer(11));
    const log = new DashboardLog(new MemoryStorage(), fixedNow(NOW));

    const entry = await log.appendDeletionRecord('vc-9', signer);

    expect(entry.type).toBe('credentialDeleted');
    expect(entry.payload).toEqual({ vcId: 'vc-9' });
    expect(verifyWithJwk('ES256', decodeCompactJws(entry.signature), signer.publicKeyJwk)).toBe(
      true,
    );
    expect(await log.listDeletionRecords()).toEqual([entry]);
  });
});
