/**
 * nonce / replay 検知の型定義。
 *
 * wallet SDK は「インターフェースと検知ロジック」を提供し、ステートフルな永続実装
 * （IndexedDB / Redis / SQLite）は利用側（Aegis Gateway 等）が `NonceStoreAdapter` として
 * 注入する。既定では単一プロセス用のインメモリ実装を提供する。
 */

/**
 * nonce の発行コンテキスト。同一 nonce 値でもコンテキストが異なれば別エントリとして扱う。
 *
 * `one-time-credential` は一回限り使用 VC（Human Approval VC 等）の `jti` 用で、
 * 同じ VC が別の VP で再利用されたことを検知できるよう、VC の `exp` まで記録を保持する。
 *
 * `dpop` は DPoP proof（RFC 9449）の `jti` 用で、`jkt` は proof 公開鍵の RFC 7638 サムプリント。
 * 鍵ごとに名前空間を分けることで、別クライアントの `jti` 衝突が誤検知にならない（RFC 9449 §11.1）。
 */
export type NonceContext =
  | { readonly flow: 'oid4vp'; readonly clientId: string }
  | { readonly flow: 'oid4vci'; readonly issuer: string }
  | { readonly flow: 'siopv2'; readonly clientId: string }
  | { readonly flow: 'wua-pop'; readonly audience: string }
  | { readonly flow: 'one-time-credential'; readonly issuer: string }
  | { readonly flow: 'dpop'; readonly jkt: string };

/** `NonceContext` の flow 名。 */
export type NonceFlow = NonceContext['flow'];

/**
 * 拒否リスト（seen-nonces cache）の 1 エントリ。
 *
 * `usedAt` で発行記録（`put`）と使用記録（`checkAndUse`）を区別する。
 */
export interface SeenNonceEntry {
  /** 照合キーとなる nonce 値。 */
  readonly nonce: string;
  /** 発行コンテキスト。 */
  readonly context: NonceContext;
  /** 最初に記録された時刻（UNIX ms）。 */
  readonly firstSeenAt: number;
  /** 保持期限（UNIX ms）。この時刻を過ぎたエントリは prune 対象。 */
  readonly expiresAt: number;
  /** 消費された時刻（UNIX ms）。未消費なら `undefined`。 */
  readonly usedAt?: number;
}

/**
 * 永続化バックエンドへの最小依存（DI seam）。
 *
 * `storage.ts` の `Storage` と同じく構造型として最小限のメソッドのみを要求する。
 * `entries()` は挿入順を保つこと（LRU 退避が挿入順を前提とする）。
 *
 * **並行性の要件:** `NonceStore` は同一キーの `get` → `set` を単一プロセス内で直列化するが、
 * 複数プロセス / 複数インスタンスで同じバックエンドを共有する場合（redis 等）はそれだけでは
 * 足りない。二重消費を防ぐため、**アダプタ側で `get` → `set` の原子性**（トランザクション /
 * Lua スクリプト / 条件付き書き込み）を保証すること。
 */
export interface NonceStoreAdapter {
  /** キーに対応するエントリを返す。無ければ `undefined`。 */
  get(key: string): Promise<SeenNonceEntry | undefined>;
  /** エントリを保存する（既存キーは上書き）。 */
  set(key: string, entry: SeenNonceEntry): Promise<void>;
  /** エントリを削除する。存在しないキーでもエラーにしない。 */
  delete(key: string): Promise<void>;
  /** 保持中の全エントリを挿入順で返す。 */
  entries(): Promise<readonly (readonly [string, SeenNonceEntry])[]>;
  /**
   * 指定プレフィックスのエントリだけを挿入順で返す（任意実装）。
   *
   * 容量管理はコンテキスト単位で行うため、実装するとキャッシュ全体の取得を避けられる。
   * redis（`SCAN MATCH`）/ sqlite（`WHERE key LIKE ?`）/ indexeddb（`IDBKeyRange.bound`）の
   * ように前方一致検索を持つバックエンドでは**実装しなければならない**。
   * 未実装なら `entries()` にフォールバックする。
   */
  entriesByPrefix?(prefix: string): Promise<readonly (readonly [string, SeenNonceEntry])[]>;
  /**
   * 期限切れ（`expiresAt <= now`）のエントリを一括削除し、削除件数を返す（任意実装）。
   *
   * 未実装なら `NonceStore#prune` は `entries()` で全件を引き上げて比較する。TTL による自動失効を
   * 持つバックエンド（redis の `EXPIRE`）や条件付き一括削除を持つバックエンド
   * （sqlite の `DELETE FROM ... WHERE expires_at <= ?`）では**実装しなければならない**。
   * redis のように backend 側で既に失効している場合は、削除すべきものが無い旨として `0` を返してよい。
   *
   * 判定の基準時刻は `NonceStore` に注入されたクロックであり、アダプタは自前の時計を使わないこと
   * （テストの偽クロックと実装がずれると期限切れ判定が食い違う）。
   *
   * **注意:** 一括削除ではエントリ本体が SDK に戻らないため、`NonceStoreOptions.onEvict`
   * （`NONCE_EVICTED` 監査）を発火できない。`onEvict` が登録されている場合、`NonceStore` は
   * 監査を落とさないよう本メソッドへ委譲せず `entries()` 経路にフォールバックする。
   */
  pruneExpired?(now: number): Promise<number>;
  /**
   * 保持中のエントリ数を返す（任意実装）。`prefix` 指定時は前方一致するエントリのみ数える。
   *
   * 容量管理が上限未達を件数だけで判定できるようになり、エントリ本体の取得を丸ごと省ける。
   * 数え方は `entriesByPrefix` と同じ前方一致でなければならない（redis の `SCAN` / sqlite の
   * `SELECT COUNT(*) ... WHERE key LIKE ?`）。期限切れエントリを含めてよい（上限判定は上振れ側に
   * 倒れるだけで、超過を見逃すことはない）。
   *
   * **実際の保持件数を下回ってはならない。** 容量管理は `count` が上限未満なら退避処理そのものを
   * 省くため、下振れする実装（並行書き込み中の `SCAN` を数え漏らす等）を注入すると上限判定を
   * 素通りして `maxEntries` 超過が起きる。正確に数えられない場合は多めに見積もること。
   */
  count?(prefix?: string): Promise<number>;
}

/** エントリが退避された理由（監査イベント `NONCE_EVICTED`）。 */
export type NonceEvictionReason = 'expired' | 'lru';

/**
 * バックエンド種別。`memory` 以外は `adapter` の注入が必要。
 *
 * `chrome-storage` を使う呼び出し側は `chrome.storage.local` を利用するストレージを `adapter` として注入する。
 */
export type NonceStoreBackend = 'memory' | 'indexeddb' | 'redis' | 'sqlite' | 'chrome-storage';

/**
 * 高負荷時プリフィルタの調整パラメータ。`NonceStoreOptions.bloomFilter` へ渡す。
 * 省略したフィールドは既定値（初期容量 10000、目標偽陽性率 0.1%）を使う。
 */
export interface BloomFilterOptions {
  /** 初期容量。この件数を超えて追加すると内部でレイヤーを追加し自動拡張する（既定 `maxEntries` または 10000）。 */
  readonly capacity?: number;
  /** 目標偽陽性率（`(0, 1)` の範囲、既定 0.001 = 0.1%）。 */
  readonly falsePositiveRate?: number;
}

/** `createNonceStore` のオプション。 */
export interface NonceStoreOptions {
  /** バックエンド種別。`memory` 以外を指定する場合は `adapter` が必須。 */
  readonly backend: NonceStoreBackend;
  /** コンテキストあたりの最大エントリ数（既定 10000）。 */
  readonly maxEntries?: number;
  /** 遅延 sweep の最小間隔（ms、既定 60000）。 */
  readonly sweepIntervalMs?: number;
  /** `memory` 以外のバックエンドで注入する永続化実装。 */
  readonly adapter?: NonceStoreAdapter;
  /** 現在時刻（UNIX ms）を返す関数。テスト注入用。既定は `Date.now`。 */
  readonly now?: () => number;
  /** 退避時の監査フック（`NONCE_EVICTED`）。 */
  readonly onEvict?: (entry: SeenNonceEntry, reason: NonceEvictionReason) => void;
  /**
   * `adapter.get` の前段プリフィルタを有効化する（既定 false = 無効）。
   * `true` で既定パラメータ、オブジェクトで個別調整。無効時は常に `adapter.get` へ問い合わせる
   * （既定バックエンドの `memory` はローカル `Map` 参照のため、有効化しても得はしない）。
   * フィルタは初回アクセス時に `adapter.entries()` で既存キーから復元する（再起動後も消費済み nonce を
   * 見逃さない）。バックエンドへ書き込むのはこのストアだけであること（他プロセスの書き込みは反映されない）。
   */
  readonly bloomFilter?: boolean | BloomFilterOptions;
}

/** `checkAndUse` のオプション。 */
export interface CheckAndUseOptions {
  /**
   * 実測のバインディング対象値（KB-JWT の `aud` / `client_id` 等）。
   * 指定時はコンテキストの束縛値と定数時間比較し、不一致なら 4012 を投げる。
   */
  readonly binding?: string;
  /**
   * 未発行（`put` 済みでない）nonce を初見として受理する際の保持期間（ms）。
   * 未指定時は flow ごとの既定 TTL を使う。
   */
  readonly ttlMs?: number;
}

/**
 * nonce 拒否リスト（seen-nonces cache）の公開インターフェース。
 *
 * `put` が発行記録、`checkAndUse` が使用記録に対応する。
 */
export interface NonceStore {
  /** CSPRNG で nonce を生成し base64url（パディング無し）で返す。 */
  generate(byteLength?: 16 | 32): string;
  /** 発行した nonce を TTL 付きで記録する。 */
  put(nonce: string, ctx: NonceContext, ttlMs: number): Promise<void>;
  /**
   * nonce を消費する。
   *
   * @throws 4010 消費済み / 4011 期限切れ / 4012 バインディング不一致 / 4013 形式不正。
   */
  checkAndUse(nonce: string, ctx: NonceContext, opts?: CheckAndUseOptions): Promise<void>;
  /** 該当 nonce が消費済みとして記録されているかを返す（期限切れは `false`）。 */
  has(nonce: string, ctx: NonceContext): Promise<boolean>;
  /**
   * 期限切れエントリを削除し、削除件数を返す。
   *
   * 件数は「この呼び出しが削除した数」であり、保持中の期限切れ総数ではない。アダプタが
   * `pruneExpired` を持つ場合はその申告値をそのまま返すため、backend 側の TTL で既に
   * 失効済みなら `0` になりうる。逆に `count` を持つアダプタでは挿入時の期限切れ先行削除が
   * 走らないぶん、同じ操作列でも回収が `prune` に寄って戻り値が大きく出ることがある。
   * 監視用途で「失効したエントリ数」を数えたい場合は、この戻り値ではなく
   * `onEvict`（`NONCE_EVICTED`）を使うこと。
   */
  prune(): Promise<number>;
}
