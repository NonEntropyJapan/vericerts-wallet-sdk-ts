/**
 * `kid` ベースの多鍵検証（`DashboardLog.verify` / `verifyDashboardLogChain`）の回帰テスト。
 *
 * Dashboard ログの同じ chain に、登録・復旧で交代した Passkey 由来の K3 ログ専用鍵、
 * PRF 非対応時の seed 由来代替鍵、旧アクティブペルソナ鍵（K2 由来・`ES256K`）で署名した
 * エントリが混在する。**旧エントリは `kid` を持たない**（当時の signer に `kid`
 * フィールドが無い）ため、`undefined` が解決キーになる。
 *
 * ここで固定する回帰:
 *
 * - 単一の検証鍵では鍵が交代した chain が `signatureInvalid` になる。
 * - `kid` → 鍵のリゾルバを渡せば、鍵が交代した chain・旧 K2 エントリ混在の chain が `ok` になる。
 * - 鍵を解決できないエントリは fail-closed で `keyUnresolved`（`signatureInvalid` ではない）。
 * - 単一の検証鍵（非関数）を渡す従来経路の挙動は変わらない（後方互換）。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import {
  type AnyCredentialSigner,
  type AsyncCredentialSigner,
  type CredentialSigner,
  createPrivateKeySigner,
} from '../../../credential/index.js';
import { encodeDashboardLogEntry } from '../../codec.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import { DASHBOARD_LOG_KEY_PREFIX } from '../../dashboard-log/dashboard-log-shared.js';
import {
  type DashboardLogVerifierKey,
  type DashboardLogVerifierKeyResolver,
  verifyDashboardLogChain,
} from '../../log-integrity/chain.js';
import type { DashboardLogEntry } from '../../types.js';
import { createPrivateKeySignerFromFill, fixedNow } from './dashboard-log-helpers.js';

const NOW = '2026-09-10T00:00:00.000Z';

/** 決定的な 32B P-256 秘密鍵（全バイト `fill`）から ES256 signer を作る。 */
function es256Signer(fill: number): CredentialSigner {
  return createPrivateKeySigner(new Uint8Array(32).fill(fill), 'ES256');
}

/**
 * 同期 signer を `kid` 付きの非同期 signer として包む（K3 の Web Crypto 署名の代役）。
 *
 * `kid` を持つ signer なので `buildJwsHeader` が JWS ヘッダへ `kid` を載せる（旧 K2 相当の signer は
 * `kid` プロパティ自体を持たない `createPrivateKeySignerFromFill` をそのまま使う）。
 */
function asAsyncSigner(signer: CredentialSigner, kid: string): AsyncCredentialSigner {
  return {
    alg: signer.alg,
    publicKeyJwk: signer.publicKeyJwk,
    kid,
    sign: async (signingInput: Uint8Array): Promise<Uint8Array> => signer.sign(signingInput),
  };
}

/** signer の公開鍵から検証鍵を組む。 */
function verifierKeyOf(signer: AnyCredentialSigner): DashboardLogVerifierKey {
  return { alg: signer.alg, publicKeyJwk: signer.publicKeyJwk };
}

/**
 * 「`kid` → 検証鍵」の対応表からリゾルバを作る。表に無い `kid` は `undefined`（fail-closed）。
 *
 * `Map` のキーは `undefined` も取れるので、`kid` を持たない旧 K2 エントリ用の鍵も同じ表で表現できる。
 */
function resolverOf(
  table: readonly (readonly [string | undefined, DashboardLogVerifierKey])[],
): DashboardLogVerifierKeyResolver {
  const keys = new Map(table);
  return (kid) => keys.get(kid);
}

describe('DashboardLog verify 多鍵解決', () => {
  const K3_A = 'k3-prf:thumb-a';
  const K3_B = 'k3-prf:thumb-b';

  /** 別々の signer で 2 件追記したログと、その 2 エントリを返す。 */
  async function seededPair(
    firstSigner: AnyCredentialSigner,
    secondSigner: AnyCredentialSigner,
  ): Promise<{
    log: DashboardLog;
    storage: MemoryStorage;
    first: DashboardLogEntry;
    second: DashboardLogEntry;
  }> {
    const storage = new MemoryStorage();
    const log = new DashboardLog(storage, fixedNow(NOW));
    const first = await log.append('presentation', { clientId: 'rp-0' }, firstSigner);
    const second = await log.append('presentation', { clientId: 'rp-1' }, secondSigner);
    return { log, storage, first, second };
  }

  it('単一の検証鍵では鍵が交代した chain が signatureInvalid になる', async () => {
    const before = asAsyncSigner(es256Signer(11), K3_A);
    const after = asAsyncSigner(es256Signer(12), K3_B);
    const { log, second } = await seededPair(before, after);

    // 従来 API（単一鍵）では、どちらの鍵を渡しても他方で署名したエントリが改ざん扱いになる。
    const result = await log.verify(verifierKeyOf(before));

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([{ id: second.id, reason: 'signatureInvalid' }]);
  });

  it('鍵が交代した chain はリゾルバが両方の kid を解決できれば ok', async () => {
    const before = asAsyncSigner(es256Signer(11), K3_A);
    const after = asAsyncSigner(es256Signer(12), K3_B);
    const { log } = await seededPair(before, after);

    const result = await log.verify(
      resolverOf([
        [K3_A, verifierKeyOf(before)],
        [K3_B, verifierKeyOf(after)],
      ]),
    );

    expect(result.ok).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.count).toBe(2);
    expect(result.truncated).toBe(false);
    expect(result.merkleRoot).not.toBeNull();
  });

  it('kid を持たない旧 K2 エントリとの混在も undefined の解決先を与えれば ok', async () => {
    // 従来のアクティブペルソナ鍵（K2 由来・同期 `ES256K`・`kid` なし）で署名した先頭エントリ。
    const legacy = createPrivateKeySignerFromFill(7);
    const current = asAsyncSigner(es256Signer(11), K3_A);
    const { log } = await seededPair(legacy, current);

    const result = await log.verify(
      resolverOf([
        [undefined, verifierKeyOf(legacy)],
        [K3_A, verifierKeyOf(current)],
      ]),
    );

    expect(result.ok).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.count).toBe(2);
  });

  it('既知鍵集合に無い kid は keyUnresolved として報告する（signatureInvalid ではない）', async () => {
    const known = asAsyncSigner(es256Signer(11), K3_A);
    const unknown = asAsyncSigner(es256Signer(12), K3_B);
    const { log, second } = await seededPair(known, unknown);

    const result = await log.verify(resolverOf([[K3_A, verifierKeyOf(known)]]));

    expect(result.ok).toBe(false);
    // 「誰が署名したのか分からない」は改ざんの証跡（signatureInvalid）と区別する。
    expect(result.issues).toEqual([{ id: second.id, reason: 'keyUnresolved' }]);
  });

  it('旧鍵を設定していないと kid なしエントリが keyUnresolved になる（fail-closed）', async () => {
    const legacy = createPrivateKeySignerFromFill(7);
    const current = asAsyncSigner(es256Signer(11), K3_A);
    const { log, first } = await seededPair(legacy, current);

    // `undefined` の解決先を持たないリゾルバ = 旧 K2 鍵を設定していない組込先。
    const result = await log.verify(resolverOf([[K3_A, verifierKeyOf(current)]]));

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([{ id: first.id, reason: 'keyUnresolved' }]);
  });

  it('単一の検証鍵（非関数）を渡す従来経路は挙動が変わらない（後方互換）', async () => {
    const signer = createPrivateKeySignerFromFill(7);
    const { log } = await seededPair(signer, signer);

    const sameKey = await log.verify(verifierKeyOf(signer));
    const otherKey = await log.verify(verifierKeyOf(createPrivateKeySignerFromFill(9)));

    expect(sameKey.ok).toBe(true);
    expect(sameKey.issues).toEqual([]);
    // 別鍵では全件 signatureInvalid（単一鍵経路では `keyUnresolved` は立たない）。
    expect(otherKey.issues.map((issue) => issue.reason)).toEqual([
      'signatureInvalid',
      'signatureInvalid',
    ]);
  });

  it('鍵が解決できたエントリの改ざんは signatureInvalid のまま検知する', async () => {
    const known = asAsyncSigner(es256Signer(11), K3_A);
    const unknown = asAsyncSigner(es256Signer(12), K3_B);
    const { log, storage, first, second } = await seededPair(known, unknown);
    // 署名は据え置いて本文だけ差し替える（解決できた鍵での署名検証が失敗する）。
    const tampered: DashboardLogEntry = { ...first, payload: { clientId: 'attacker.example' } };
    await storage.set(
      `${DASHBOARD_LOG_KEY_PREFIX}${tampered.id}`,
      encodeDashboardLogEntry(tampered),
    );
    const resolver = resolverOf([[K3_A, verifierKeyOf(known)]]);

    // chain 直呼びと `DashboardLog.verify`（`verifyStoredDashboardLog` 経由）の双方を確かめる。
    const chain = verifyDashboardLogChain([tampered, second], resolver);
    const stored = await log.verify(resolver);

    expect(chain.ok).toBe(false);
    // 鍵が解決できた 1 件目は改ざん、解決できない 2 件目は鍵未解決として別々に報告される。
    expect(chain.issues).toEqual([
      { id: tampered.id, reason: 'signatureInvalid' },
      { id: second.id, reason: 'keyUnresolved' },
    ]);
    expect(stored).toEqual(chain);
  });
});
