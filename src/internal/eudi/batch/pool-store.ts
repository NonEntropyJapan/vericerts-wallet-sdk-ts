/**
 * Batch Credential プールごとの集約メタデータを永続化する。
 * `totalCount` / `usedCount` は呼び出し側が `BatchPoolItem[]` から算出して渡す想定で、本ストアは
 * そのスナップショットを `id` をキーに永続化・一覧・更新するのみを担う（`BatchPoolItem[]`
 * 自体の消費・補充ロジックは引き続き `pool.ts` / `refill.ts` の責務であり、本ストアはそれらの
 * 結果を反映する薄い集約管理層に留める）。
 *
 * 永続化パターンは `delegated-did/delegated-did-store.ts`（`DelegatedDIDStore`）と同じ
 * 「構造的 Storage 依存 + `now`/`idGen` 注入」に揃える。facade（`wallet.ts` / `index.ts`）への
 * 配線は `eudi/batch` の他モジュール同様、統合担当が行う（`index.ts` の module doc を参照）。
 */

import { KeyLock } from '../../primitives/key-lock.js';
import { assertNonNegativeSafeInteger } from '../../primitives/option-guard.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { decodeBatchCredentialPool, encodeBatchCredentialPool } from './codec.js';
import type { BatchCredentialPool, CreateBatchCredentialPoolOptions } from './types.js';

/**
 * 永続化バックエンドへの最小依存。`Storage`（storage.ts）を構造的に満たす。
 *
 * 循環 import を避けるため `Storage` を直接 import せず、必要なメソッドのみを構造型として要求する
 * （`persona/persona.ts` の `PersonaStorage` と同パターン）。
 */
interface BatchCredentialPoolStorage {
  get(key: string): Promise<Uint8Array | null>;
  set(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

/** 消費済み件数が総数を超える（残数が負になる）状態を拒否する。 */
function assertUsedWithinTotal(usedCount: number, totalCount: number): void {
  if (usedCount > totalCount) {
    throw new RangeError('usedCount は totalCount 以下である必要があります');
  }
}

/** storage 上で BatchCredentialPool レコードを保存するキーの prefix。 */
const BATCH_POOL_KEY_PREFIX = 'eudi/batch/pool/';

/**
 * BatchCredentialPool の作成・一覧・補充/消費反映・削除を担う管理クラス。
 *
 * 状態は storage に永続化される。read-modify-write（`recordRefill` / `recordConsumption` / `remove`）は
 * プール id 単位の `KeyLock` で直列化し、並行呼び出しの lost update を防ぐ（`CredentialStore` の
 * `recordLock` と同方針。ロックは単一プロセス・同一インスタンス内でのみ有効）。
 */
export class BatchCredentialPoolStore {
  private readonly poolLock = new KeyLock();

  /**
   * @param storage レコードの永続化先。
   * @param now 現在時刻（エポックミリ秒）取得関数。既定は `Date.now`。テスト時に注入する。
   * @param idGen プール id 採番関数。既定は `crypto.randomUUID`。テスト時に注入する。
   */
  constructor(
    private readonly storage: BatchCredentialPoolStorage,
    private readonly now: () => number = Date.now,
    private readonly idGen: () => string = () => crypto.randomUUID(),
  ) {}

  /**
   * 新規プールを作成し永続化する。
   *
   * `usedCount` 省略時は `0`。`createdAt` / `refreshedAt` はいずれも作成時刻（`now()`）で
   * 初期化する。
   *
   * @param input 作成入力。
   * @returns 作成されたプール。
   * @throws `totalCount` / `threshold` / `usedCount` が非負の安全整数でない、または `usedCount` が
   *         `totalCount` を超える場合（`RangeError`。NaN 等の永続化で `get` / `list` が 6005 になるのを防ぐ）。
   */
  async create(input: CreateBatchCredentialPoolOptions): Promise<BatchCredentialPool> {
    const totalCount = assertNonNegativeSafeInteger('totalCount', input.totalCount);
    const threshold = assertNonNegativeSafeInteger('threshold', input.threshold);
    const usedCount = assertNonNegativeSafeInteger(
      'usedCount',
      ownProperty<number>(input, 'usedCount') ?? 0,
    );
    assertUsedWithinTotal(usedCount, totalCount);
    const timestamp = this.now();
    const pool: BatchCredentialPool = {
      id: this.idGen(),
      vct: input.vct,
      issuerDID: input.issuerDID,
      totalCount,
      usedCount,
      threshold,
      createdAt: timestamp,
      refreshedAt: timestamp,
    };
    await this.persist(pool);
    return pool;
  }

  /**
   * 保存済みプールを取得する。未存在なら `null`。
   *
   * @param id 取得するプール id。
   * @returns 保存済みプール、または未存在時 `null`。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async get(id: string): Promise<BatchCredentialPool | null> {
    const stored = await this.storage.get(this.recordKey(id));
    return stored === null ? null : decodeBatchCredentialPool(stored);
  }

  /**
   * 保存済みプールの一覧を返す。
   *
   * 破損レコードは握りつぶさず 6005 を伝播する（残数・補充判定の根拠を黙って欠落させないため）。
   * 数値の異常値は書き込み側（`create` / `recordRefill` / `recordConsumption`）で拒否し、破損を作らない。
   *
   * @param vct 指定時は当該 VC Type のプールのみに絞り込む。
   * @returns 該当プールの配列（該当なしは空配列）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async list(vct?: string): Promise<BatchCredentialPool[]> {
    const keys = await this.storage.list(BATCH_POOL_KEY_PREFIX);
    const items: BatchCredentialPool[] = [];
    for (const key of keys) {
      const stored = await this.storage.get(key);
      if (stored !== null) {
        items.push(decodeBatchCredentialPool(stored));
      }
    }
    return vct === undefined ? items : items.filter((item) => item.vct === vct);
  }

  /**
   * 補充結果をプールへ反映する（`evaluateRefill` の結果を受けて呼ぶ想定）。
   *
   * `totalCount` に `addedCount` を加算し、`refreshedAt` を現在時刻に更新する。
   *
   * @param id 対象プール id。
   * @param addedCount 今回の補充で追加された VC 数（非負の安全整数）。
   * @returns 更新後のプール、または未存在時 `null`（冪等。存在確認は呼び出し側に強制しない）。
   * @throws `addedCount` が非負の安全整数でない、または加算結果が安全整数を超える場合（`RangeError`）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async recordRefill(id: string, addedCount: number): Promise<BatchCredentialPool | null> {
    assertNonNegativeSafeInteger('addedCount', addedCount);
    return this.poolLock.run(id, async () => {
      const pool = await this.get(id);
      if (pool === null) {
        return null;
      }
      const updated: BatchCredentialPool = {
        ...pool,
        totalCount: assertNonNegativeSafeInteger('totalCount', pool.totalCount + addedCount),
        refreshedAt: this.now(),
      };
      await this.persist(updated);
      return updated;
    });
  }

  /**
   * 消費結果をプールへ反映する（`consumeCredential` の結果を受けて呼ぶ想定）。
   *
   * `usedCount` を `count` 分加算する（既定 1）。`refreshedAt` は更新しない（消費は補充ではないため）。
   *
   * @param id 対象プール id。
   * @param count 今回の消費件数（非負の安全整数）。省略時は 1。
   * @returns 更新後のプール、または未存在時 `null`（冪等）。
   * @throws `count` が非負の安全整数でない、または消費後の `usedCount` が `totalCount` を超える場合
   *         （`RangeError`。残数が負になる状態を永続化しない）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async recordConsumption(id: string, count = 1): Promise<BatchCredentialPool | null> {
    assertNonNegativeSafeInteger('count', count);
    return this.poolLock.run(id, async () => {
      const pool = await this.get(id);
      if (pool === null) {
        return null;
      }
      const usedCount = assertNonNegativeSafeInteger('usedCount', pool.usedCount + count);
      assertUsedWithinTotal(usedCount, pool.totalCount);
      const updated: BatchCredentialPool = { ...pool, usedCount };
      await this.persist(updated);
      return updated;
    });
  }

  /**
   * プールを物理削除する。未存在の id は no-op（冪等）。
   *
   * @param id 削除するプール id。
   */
  async remove(id: string): Promise<void> {
    // 進行中の read-modify-write の書き戻しでレコードが復活しないよう、同じロックに載せる。
    await this.poolLock.run(id, () => this.storage.delete(this.recordKey(id)));
  }

  /** プールを storage へ書き戻す。 */
  private persist(pool: BatchCredentialPool): Promise<void> {
    return this.storage.set(this.recordKey(pool.id), encodeBatchCredentialPool(pool));
  }

  /** プール id から storage キーを組み立てる。 */
  private recordKey(id: string): string {
    return `${BATCH_POOL_KEY_PREFIX}${id}`;
  }
}
