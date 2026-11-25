/**
 * EUDI Batch Issuance / Unlinkability の型定義。
 *
 * 本モジュールは以下を純粋ロジックとして提供する（IndexedDB / ネットワーク I/O は
 * 呼び出し側 facade が担い、本モジュールは副作用を持たない）:
 * - Batch Credential Request の組み立て（`request.ts`）
 * - 未使用 VC の選択・消費追跡・期限切れパージ（`pool.ts`）
 * - 残量閾値に基づく自動補充判定とバックオフ（`refill.ts`）
 *
 * Unlinkability の要点: 受領した N 個の VC は各々異なる cnf 鍵にバインドされ、
 * VP 提示ごとに 1 個だけ消費して破棄する。これにより同一 VC が複数 RP に提示されず、
 * RP 間相関のリンク可能性を消す。
 */

/** Batch Issuance の既定パラメータ。 */
export const BATCH_DEFAULTS = {
  /** バッチサイズ N（ARF 推奨 5〜20 の中央値）。 */
  batchSize: 10,
  /** 補充閾値（残量がこれ未満になったら補充）。 */
  refillThreshold: 3,
  /** 補充バックオフの初期待機（ミリ秒, 5min）。 */
  backoffInitialMs: 5 * 60 * 1000,
  /** 補充バックオフの最大待機（ミリ秒, 1h）。 */
  backoffMaxMs: 60 * 60 * 1000,
} as const;

/**
 * OID4VCI Batch Credential Endpoint に送る proof。
 *
 * 各 proof は短命鍵ペア `kp_i` の公開鍵を cnf として c_nonce にバインドした JWT。
 * `proof_type` は OID4VCI 準拠で常に `jwt`。
 */
export interface BatchProof {
  /** proof の種別。OID4VCI Batch では常に `jwt`。 */
  readonly proofType: 'jwt';
  /** cnf 鍵にバインドされた署名済み proof JWT のコンパクト表現。 */
  readonly jwt: string;
}

/**
 * Batch Credential Request のボディ。
 *
 * `proofs.jwt` は 1 セッションで発行する VC 個数分の proof JWT 配列。
 */
export interface BatchCredentialRequest {
  /** 発行対象の VC Type URI（例: `urn:eudi:pid:1`）。 */
  readonly vct: string;
  /** proof JWT 配列（`{ jwt: [...] }` 形式）。 */
  readonly proofs: {
    readonly jwt: readonly string[];
  };
}

/**
 * Batch Pool に格納する 1 件の Batch VC。
 *
 * `used=false` の間だけ VP 提示に使用でき、消費すると `used=true` に遷移する。
 * `keyHandle` は cnf 鍵の WSCD ハンドル（パージ時に WSCD.delete へ渡す）。
 */
export interface BatchPoolItem {
  /** プール内の一意 ID。 */
  readonly id: string;
  /** 受領した SD-JWT VC のコンパクト表現。 */
  readonly vc: string;
  /** cnf 鍵の WSCD ハンドル（署名時・削除時に参照）。 */
  readonly keyHandle: string;
  /** 消費済みか。`true` の VC は再提示しない。 */
  readonly used: boolean;
  /** VC の有効期限（epoch ミリ秒, `exp`）。 */
  readonly expiresAt: number;
  /** 消費時刻（epoch ミリ秒）。未消費なら省略。 */
  readonly consumedAt?: number;
  /** 消費先 RP 識別子。未消費なら省略。 */
  readonly consumedRp?: string;
}

/** VC 消費の結果（`consumeCredential`）。 */
export interface ConsumeResult {
  /** 消費対象を選択できたか（未使用・未期限切れが存在したか）。 */
  readonly consumed: boolean;
  /** 消費した VC（`consumed=false` のとき省略）。 */
  readonly item?: BatchPoolItem;
  /** 消費後のプール（`item` を `used=true` に更新したもの）。 */
  readonly pool: readonly BatchPoolItem[];
}

/** 期限切れパージの結果（`purgeExpired`）。 */
export interface PurgeResult {
  /** パージ後に残るプール。 */
  readonly pool: readonly BatchPoolItem[];
  /** 削除した VC の WSCD 鍵ハンドル一覧（呼び出し側が WSCD.delete へ渡す）。 */
  readonly removedKeyHandles: readonly string[];
}

/** 自動補充判定の設定（既定は `BATCH_DEFAULTS`）。 */
export interface RefillConfig {
  /** 補充で新規発行する VC 個数。 */
  readonly batchSize: number;
  /** 残量がこの値未満になったら補充する。 */
  readonly refillThreshold: number;
  /** バックオフ初期待機（ミリ秒）。 */
  readonly backoffInitialMs: number;
  /** バックオフ最大待機（ミリ秒）。 */
  readonly backoffMaxMs: number;
}

/** 自動補充判定の入力（`evaluateRefill`）。 */
export interface RefillInput {
  /** 現在のプール。 */
  readonly pool: readonly BatchPoolItem[];
  /** 判定基準時刻（epoch ミリ秒）。期限切れ VC は残量に数えない。 */
  readonly now: number;
  /** これまでの連続補充失敗回数（0 = 失敗なし）。バックオフ算出に使う。 */
  readonly consecutiveFailures?: number;
  /** 前回補充試行時刻（epoch ミリ秒）。バックオフ中か判定する。未試行なら省略。 */
  readonly lastAttemptAt?: number;
  /** 判定設定。省略時は `BATCH_DEFAULTS`。 */
  readonly config?: Partial<RefillConfig>;
}

/** 自動補充判定の結果（`evaluateRefill`）。 */
export interface RefillDecision {
  /** 今すぐ補充を実行すべきか。 */
  readonly shouldRefill: boolean;
  /** 有効な未使用 VC の残量。 */
  readonly available: number;
  /** 補充で発行を要求する個数（`shouldRefill=false` のとき 0）。 */
  readonly requestCount: number;
  /** 残量 0 か（ユーザー通知の判断材料）。 */
  readonly depleted: boolean;
  /**
   * バックオフにより待機が必要な残ミリ秒（0 なら待機不要）。
   * `shouldRefill=false` かつ `> 0` の場合はバックオフ待機中を意味する。
   */
  readonly backoffRemainingMs: number;
}

/**
 * Batch Credential プールの集約メタデータ。
 *
 * `BatchPoolItem[]`（エントリ単位の実体）とは別に、プール単位の残量・補充状況を集約して
 * 永続化するためのレコード。真実源は引き続き `BatchPoolItem[]` にあり、本レコードは
 * `totalCount` / `usedCount` の「最後に反映した値」のスナップショットを保持する
 * （`BatchCredentialPoolStore.recordRefill` / `recordConsumption` で更新する）。
 *
 * `createdAt` と `refreshedAt` はエポックミリ秒。`id` はプールを識別する。
 */
export interface BatchCredentialPool {
  /** プールの一意識別子。`BatchCredentialEntry.poolId`（ER 層）が参照する先。 */
  readonly id: string;
  /** 対象 VC Type URI（例: `urn:eudi:pid:1`）。 */
  readonly vct: string;
  /** 発行者 DID。 */
  readonly issuerDID: string;
  /** 発行総数（このプールに含まれる `BatchPoolItem` の総数）。 */
  readonly totalCount: number;
  /** 消費済み数（`used=true` の `BatchPoolItem` の数）。 */
  readonly usedCount: number;
  /** 自動補充閾値（`RefillConfig.refillThreshold` と同じ意味、プール単位の記録用）。 */
  readonly threshold: number;
  /** 作成日時（エポックミリ秒）。 */
  readonly createdAt: number;
  /** 最終補充日時（エポックミリ秒）。初回作成時は `createdAt` と同値。 */
  readonly refreshedAt: number;
}

/** `BatchCredentialPoolStore.create` の入力。 */
export interface CreateBatchCredentialPoolOptions {
  /** 対象 VC Type URI。 */
  readonly vct: string;
  /** 発行者 DID。 */
  readonly issuerDID: string;
  /** 発行総数の初期値。 */
  readonly totalCount: number;
  /** 自動補充閾値。 */
  readonly threshold: number;
  /** 消費済み数の初期値。省略時は 0。 */
  readonly usedCount?: number;
}
