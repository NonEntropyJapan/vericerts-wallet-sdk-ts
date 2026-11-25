/**
 * DID 解決の外部 I/O ファンアウトに上限を掛けるラッパー。
 *
 * ## なぜ必要か
 *
 * Wallet ファサードの `verifyPresentation` は、VP に内包された VC の**件数ぶん**の発行者 DID 解決を
 * 走らせる。`did:web` / `did:ethr` / `did:ipid` はネットワーク I/O を伴うため、VC を数百件詰めた VP を
 * 提示されると Verifier ホストから大量の同時アウトバウンド要求が出て、解決先・RPC エンドポイントへの
 * 負荷、コネクション / ファイルディスクリプタ枯渇を招く。内包 VC の解決は VP 署名の検証後に行うため
 * 「未検証入力を起点にした増幅」ではないが、**正当な holder なら誰でも引き起こせる**ため上限が要る。
 *
 * 件数を呼び出し側（エントリ側）で数えるのではなく `resolve` の呼び出しを包むことで、
 * **重複排除・並列度上限・相異なる DID 数の上限**を一箇所で担保する。
 *
 * ## スコープ
 *
 * `createBoundedResolver` は**1 スコープ（= VP 1 件ぶんの検証）につき 1 インスタンス**を作る前提。
 * 重複排除テーブルと上限カウンタはインスタンスに閉じており、別の VP の検証には影響しない。
 * インスタンスを使い回すと「相異なる DID 数」が VP をまたいで累積し、正当な検証が上限に当たる。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列を含めない（resolver.ts 冒頭と同じ制約）。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { DIDDocument } from './did.js';
import {
  createResolutionWorkBudget,
  DEFAULT_MAX_SCOPE_BODY_LENGTH,
  DEFAULT_MAX_SCOPE_WORK_UNITS,
  type ResolutionWorkBudget,
} from './resolution-budget.js';
import { resolveWithinScope } from './resolution-charge.js';

/**
 * DID 解決の DI 用構造型（`Resolver` クラスと構造的に互換）。
 *
 * `Resolver` は private フィールド（メソッド登録テーブル）を持つため、ラッパーのオブジェクトリテラルを
 * `Resolver` 型として返すことができない。解決に必要な面だけを構造型として切り出し、ラッパーと実体の
 * どちらも受け取れるようにする。
 */
export interface DidResolverLike {
  /** DID 文字列を DID Document に解決する。 */
  /** `scope` はスコープ全体の仕事量予算。受け取った実装は高コストな検証を計上してよい。 */
  resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument>;
}

/** 下位 resolver を同時に走らせる最大数。 */
export const DEFAULT_MAX_RESOLUTION_CONCURRENCY = 4;

/** 1 スコープで解決を許す相異なる DID の最大数。 */
export const DEFAULT_MAX_DISTINCT_RESOLUTIONS = 32;

/**
 * 1 スコープで解決を許す相異なる DID の文字数合計の上限。通常の DID（did:key 約 60 文字、
 * did:web 数十〜数百文字）32 件は 8 KiB 未満に収まる。長大な did:peer:4（1 件 4 KiB 超）は
 * 数件で打ち切られ、base58 デコードの合計コストが 1 スコープあたり約 0.1 秒に収まる。
 */
export const DEFAULT_MAX_TOTAL_DID_LENGTH = 16 * 1024;

/** `createBoundedResolver` の上限指定。 */
export interface BoundedResolverLimits {
  /** 下位 resolver の同時実行数の上限。 */
  readonly maxConcurrency?: number;
  /** 相異なる DID の解決数の上限。 */
  readonly maxDistinctDids?: number;
  /** 解決を許す相異なる DID の文字数合計の上限。 */
  readonly maxTotalDidLength?: number;
  /** スコープ全体の検証仕事量（署名検証 1 回 = 100）の上限。 */
  readonly maxWorkUnits?: number;
  /** スコープ全体で取得・保持する DID Document / DID Log 本文の文字数合計の上限。 */
  readonly maxBodyLength?: number;
}

/**
 * 同時実行数を `limit` 件に抑えるセマフォを作る。
 *
 * 空きが無い間は待機キューに積み、完了ごとに 1 件だけ起こす。
 *
 * 解放時は**スロットを次の待機者へそのまま引き渡す**（カウンタを一旦戻さない）。戻してから起こすと、
 * 起こされた待機者が再開する前に割り込んだ新規呼び出しが空きを見つけてしまい、同時実行数が
 * 上限を 1 件超える。
 *
 * @param limit 同時に走らせる最大数（1 以上）。
 * @returns タスクをスロット付きで実行する関数。
 */
function createSemaphore(limit: number): <T>(task: () => Promise<T>) => Promise<T> {
  let active = 0;
  const waiters: Array<() => void> = [];
  return async <T>(task: () => Promise<T>): Promise<T> => {
    if (active < limit) {
      active += 1;
    } else {
      // スロットの引き渡しを受けるまで待つ（再開時点で active は自分のぶんを計上済み）。
      await new Promise<void>((resume) => {
        waiters.push(resume);
      });
    }
    try {
      return await task();
    } finally {
      const next = waiters.shift();
      if (next === undefined) {
        active -= 1;
      } else {
        next();
      }
    }
  };
}

/**
 * DID 解決に重複排除と上限を掛けたラッパーを作る。
 *
 * - **重複排除**: 同一 DID の解決は Promise を共有し 1 回に集約する（in-flight・完了済みとも）。
 *   失敗した Promise を共有するのも意図どおりで、同一スコープ内で同じ発行者の解決を再試行しない。
 * - **相異なる DID 数の上限**: `maxDistinctDids` に達した後の**新しい** DID は下位 resolver を
 *   呼ばずに `2001 INVALID_DID` で失敗させる（既に解決を始めた DID は上限後も共有結果を返す）。
 * - **DID 長の合計上限**: 解決を許可した相異なる DID の文字数合計が `maxTotalDidLength` を超える
 *   **新しい** DID も同様に `2001` で失敗させる。1 件の長さ上限（`isDidWithinLengthLimit`）
 *   だけでは「32 件 × 上限長」で合計コストが 32 倍に増幅するため。
 * - **検証仕事量の総量上限**: 下位 resolver へ共通の仕事量予算（`ResolutionWorkBudget`）を渡し、
 *   did:webvh の署名検証・鍵ハッシュをスコープ全体で数える。1 件ごとの上限（版数 512）は
 *   DID ごとに効くだけで、32 個の相異なる DID を並べれば総量が 32 倍になるため。超過は同じ `2001`。
 * - **取得本文量の総量上限**: 同じ予算で、取得した DID Document / DID Log の本文文字数の合計を数える。
 *   did:web は署名検証が無く、解決済み文書が `resolutions` にスコープの間残るため、1 件 1 MiB の
 *   `did.json` を相異なる DID 32 件ぶん保持させる増幅を縛る。超過は同じ `2001`（`resolution_work_limit`）。
 * - **並列度の上限**: 下位 `resolve` の同時実行を `maxConcurrency` 件までに抑える。
 *
 * 上限超過を例外にするのは、呼び出し側（`attachCredentialResults`）が解決失敗を fail-closed
 * （当該 VC を `valid: false`）へ落とす既存経路にそのまま乗せるため。
 *
 * @param resolver 解決を委譲する下位 resolver。
 * @param limits 上限の上書き（自身のプロパティに限って読む）。省略した項目は既定値を使う。
 * @returns 上限付きの `DidResolverLike`。1 スコープにつき 1 インスタンスを使う。
 */
export function createBoundedResolver(
  resolver: DidResolverLike,
  limits?: BoundedResolverLimits,
): DidResolverLike {
  // 上限は「未指定なら既定値」であり、`Object.prototype` 汚染で緩められては困る純データのため
  // own 限定で読む（own-property.ts の使い分け方針）。
  const source = limits ?? {};
  const maxConcurrency =
    ownProperty<number>(source, 'maxConcurrency') ?? DEFAULT_MAX_RESOLUTION_CONCURRENCY;
  const maxDistinctDids =
    ownProperty<number>(source, 'maxDistinctDids') ?? DEFAULT_MAX_DISTINCT_RESOLUTIONS;
  const maxTotalDidLength =
    ownProperty<number>(source, 'maxTotalDidLength') ?? DEFAULT_MAX_TOTAL_DID_LENGTH;
  // スコープ全体の検証仕事量。相異なる DID を並べて 1 件ごとの解決コストを増幅する攻撃への総量の上限。
  const workBudget = createResolutionWorkBudget(
    ownProperty<number>(source, 'maxWorkUnits') ?? DEFAULT_MAX_SCOPE_WORK_UNITS,
    ownProperty<number>(source, 'maxBodyLength') ?? DEFAULT_MAX_SCOPE_BODY_LENGTH,
  );
  const withSlot = createSemaphore(maxConcurrency);
  /** DID → 解決 Promise。完了後も残し、同一 DID の再解決を防ぐ。 */
  const resolutions = new Map<string, Promise<DIDDocument>>();
  /** 解決を許可した相異なる DID の文字数合計（重複は計上しない）。 */
  let admittedDidLength = 0;

  return {
    async resolve(did: string): Promise<DIDDocument> {
      const shared = resolutions.get(did);
      if (shared !== undefined) {
        return shared;
      }
      if (resolutions.size >= maxDistinctDids) {
        // DID 文字列は context に含めない（resolver.ts 冒頭のセキュリティ注記）。
        throw new VericertsError(ErrorCodes.INVALID_DID, {
          context: { reason: 'resolution_fanout_limit' },
        });
      }
      // 解決コスト（did:peer:4 の base58 デコード等は DID 長の二次時間）の合計を抑える。
      // 上限を超える DID は下位 resolver を呼ばず、合計にも計上しない。
      if (admittedDidLength + did.length > maxTotalDidLength) {
        throw new VericertsError(ErrorCodes.INVALID_DID, {
          context: { reason: 'resolution_cost_limit' },
        });
      }
      admittedDidLength += did.length;
      // 下位 resolver を呼ぶ唯一の入口。返した文書の保持量はメソッドの計上有無に関わらずここで計上する。
      const pending = withSlot(() =>
        resolveWithinScope(workBudget, (scope) => resolver.resolve(did, scope)),
      );
      resolutions.set(did, pending);
      return pending;
    },
  };
}
