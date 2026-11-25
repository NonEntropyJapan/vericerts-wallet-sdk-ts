/**
 * seen-nonces cache の容量管理。
 *
 * `store.ts` の `AdapterNonceStore` から切り出した層。容量上限の維持と退避（LRU / 期限切れ）は
 * replay 検知そのもの（`put` / `checkAndUse` / `has` / `prune`）とは独立に読める責務であり、かつ
 * `store.ts` が 1 ファイル 300 行の上限に達していた。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { KeyLock } from '../../../primitives/key-lock.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { NonceEvictionReason, NonceStoreAdapter, SeenNonceEntry } from '../types.js';

/**
 * 退避の試行結果。`evicted` = 削除した / `gone` = 既に無かった（枠は空いている）/
 * `kept` = 再読込で退避条件を満たさなかった / `busy` = 他の `put` / `checkAndUse` が処理中。
 */
type EvictOutcome = 'evicted' | 'gone' | 'kept' | 'busy';
/** 退避の対象範囲。`expired` は期限切れのみ、`lru` は期限切れ + 未使用（`usedAt` なし）。 */
type EvictScope = 'expired' | 'lru';

/**
 * コンテキストあたりのエントリ数を上限内に保ち、超過分と期限切れを退避する。
 */
export class NonceCapacityManager {
  readonly #adapter: NonceStoreAdapter;
  readonly #maxEntries: number;
  readonly #now: () => number;
  readonly #onEvict: ((entry: SeenNonceEntry, reason: NonceEvictionReason) => void) | undefined;
  /** `put` / `checkAndUse` と同じキーロック。退避はこのロックの下で再読込してから削除する。 */
  readonly #lock: KeyLock;

  constructor(
    adapter: NonceStoreAdapter,
    maxEntries: number,
    now: () => number,
    onEvict: ((entry: SeenNonceEntry, reason: NonceEvictionReason) => void) | undefined,
    lock: KeyLock,
  ) {
    this.#adapter = adapter;
    this.#maxEntries = maxEntries;
    this.#now = now;
    this.#onEvict = onEvict;
    this.#lock = lock;
  }

  /**
   * エントリ本体を取得しない高速経路（`pruneExpired` / `count`）を使ってよいかを返す。
   *
   * `onEvict` が登録されている場合は `false`。監査フック（`NONCE_EVICTED`）は退避された
   * エントリ本体を要求するため、削除件数しか返さない一括削除に委譲すると監査が落ちる。
   * 性能のために監査を黙って失うことはしない。
   */
  canSkipEntryFetch(): boolean {
    return this.#onEvict === undefined;
  }

  /**
   * コンテキストあたりのエントリ数を上限内に収める。
   *
   * 期限切れを優先削除し、なお超過する場合は **未使用**（`usedAt` なし = 発行のみで未提示）の
   * エントリを `firstSeenAt` の古い順に退避する。TTL 内の使用済みエントリは退避しない。
   * 使用済みエントリは replay 検知そのものであり、退避すると次回 `checkAndUse` が「初見」と判定して
   * 消費済み nonce を再受理してしまう。`put` は無認証の発行エンドポイントから攻撃者が任意回数呼ばせられ、
   * 通常運用でも `one-time-credential` の `jti` が上限を超えて溜まり得るため、LRU の対象にできない。
   * 退避できる未使用エントリだけでは空きを作れない（使用済みだけで満杯）場合は何も退避せず
   * `REPLAY_DETECTED`（4010）で拒否する（fail-closed）。
   *
   * ただし `count` を持つアダプタで上限未達が確定した場合は、期限切れの先行削除も行わずに
   * 早期 return する（退避の必要が無いため）。その期限切れは遅延 sweep の `prune` が回収する。
   *
   * 退避は一覧スナップショットを**候補の提示**にしか使わない。削除は候補キーのロック下で
   * `adapter.get` を取り直し、条件（期限切れ / 未使用）を満たす場合だけ行う。スナップショット
   * 取得後に並行する `checkAndUse` が使用済みを書いた・`put` が再発行したエントリを、古い情報で
   * 消してリプレイを通さないため。ロックは待たずに取る（`KeyLock#tryRun`）: 呼び出し元は自分のキーの
   * ロックを保持しており、待つと 2 つの `put` が互いの候補キーを待ち合ってデッドロックし得る。処理中の
   * キーは退避せず次の候補へ進む。候補を使い切っても空きを作れない場合は拒否する（fail-closed）。
   *
   * @param prefix 対象コンテキストのキー接頭辞（`entryKeyPrefixFrom`）。呼び出し側が束縛照合を通した
   *               読み取り結果から組み立てて渡す（読み直すと消費記録を書くキーと容量スコープがずれる）。
   * @param newKey これから追加するキー（既存なら枠を消費しない）。
   * @throws `REPLAY_DETECTED`（4010）退避可能な未使用エントリでは上限内に収められない場合。
   */
  async enforceCapacity(prefix: string, newKey: string): Promise<void> {
    // 上限に達していないと件数だけで分かるならエントリ本体を取得しない。`count` は
    // 期限切れも `newKey` 自身も含む上振れ値なので、`maxEntries` 未満なら超過はあり得ない。
    if (this.canSkipEntryFetch() && this.#adapter.count !== undefined) {
      if ((await this.#adapter.count(prefix)) < this.#maxEntries) {
        return;
      }
    }
    // アダプタが前方一致検索を持つならキャッシュ全体の取得を避ける（redis / sqlite / indexeddb）。
    const all = await (this.#adapter.entriesByPrefix?.(prefix) ?? this.#adapter.entries());
    const now = this.#now();
    const scoped: (readonly [string, SeenNonceEntry])[] = [];

    for (const pair of all) {
      if (!pair[0].startsWith(prefix) || pair[0] === newKey) {
        continue;
      }
      if (pair[1].expiresAt <= now) {
        const outcome = await this.#evictIfStill(pair[0], 'expired');
        if (outcome === 'evicted' || outcome === 'gone') {
          continue;
        }
        // 再発行された（kept）/ 処理中（busy）のエントリは枠を占めたままとして数える。
      }
      scoped.push(pair);
    }

    const overflow = scoped.length - (this.#maxEntries - 1);
    if (overflow <= 0) {
      return;
    }
    const evictable = scoped.filter(
      ([, entry]) => ownProperty<number>(entry, 'usedAt') === undefined,
    );
    if (evictable.length < overflow) {
      // 使用済み（TTL 内）を退避すると replay が通るため、何も消さずに拒否する。
      //
      // ただし**これは replay の検知ではなく容量の枯渇**である。同じ 4010 を理由なしで
      // 返すと、運用側は「攻撃を受けている」のか「maxEntries が足りない」のかを区別できず、
      // コンテキスト全体が TTL の間ロックアウトされていることに気づけない。`reason` で区別する。
      throw new VericertsError(ErrorCodes.REPLAY_DETECTED, {
        context: { reason: 'capacity_exhausted' },
      });
    }
    evictable.sort((a, b) => a[1].firstSeenAt - b[1].firstSeenAt);
    let freed = 0;
    for (const [key] of evictable) {
      if (freed >= overflow) {
        break;
      }
      const outcome = await this.#evictIfStill(key, 'lru');
      if (outcome === 'evicted' || outcome === 'gone') {
        freed += 1;
      }
    }
    if (freed < overflow) {
      // 候補が再読込で使用済み / 処理中と分かり、空きを作れなかった。使用済みは消さずに拒否する。
      throw new VericertsError(ErrorCodes.REPLAY_DETECTED);
    }
  }

  /**
   * 期限切れのエントリを、キーロック下で再読込して削除する（`prune` 用）。
   *
   * @returns 実際に削除したなら `true`（既に無い・再発行済み・処理中なら `false`）。
   */
  async evictExpired(key: string): Promise<boolean> {
    return (await this.#evictIfStill(key, 'expired')) === 'evicted';
  }

  /**
   * 候補キーのロックを待たずに取り、`adapter.get` を取り直して退避条件を満たす場合だけ削除する。
   * スナップショット由来の判定（`usedAt` / `expiresAt`）は信用しない。監査フック
   * （`NONCE_EVICTED`）には再読込した最新のエントリを渡す。
   */
  async #evictIfStill(key: string, scope: EvictScope): Promise<EvictOutcome> {
    const result = await this.#lock.tryRun(
      key,
      async (): Promise<Exclude<EvictOutcome, 'busy'>> => {
        const current = await this.#adapter.get(key);
        if (current === undefined) {
          return 'gone';
        }
        const expired = current.expiresAt <= this.#now();
        if (
          !expired &&
          (scope === 'expired' || ownProperty<number>(current, 'usedAt') !== undefined)
        ) {
          return 'kept';
        }
        await this.#adapter.delete(key);
        this.#onEvict?.(current, expired ? 'expired' : 'lru');
        return 'evicted';
      },
    );
    return result.ran ? result.value : 'busy';
  }
}
