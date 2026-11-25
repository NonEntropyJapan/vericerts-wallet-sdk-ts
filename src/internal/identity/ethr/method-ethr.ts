/**
 * did:ethr メソッド実装（ERC-1056 DID Registry、解決のみ）。
 *
 * 解決フロー:
 *   parse（did-url.ts）→ eventSource.fetchEvents（registry.ts / ethers）
 *   → buildDidEthrDocument（events.ts、純関数）
 *
 * 書き込み更新（setAttribute / changeOwner 等）は別 Issue のため、本実装は解決のみ。
 * `create` / `update` / `deactivate` は `METHOD_NOT_SUPPORTED`（code `2002`）。
 *
 * ethers.js への依存は registry.ts に閉じ込めてあり、本モジュールは
 * `Erc1056EventSource` シーム経由でイベントを取得する（テストはモック注入）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・アドレス・RPC URL を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FetchLike } from '../../fetch-di.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { CreateOptions, DIDDocument, DIDMethod, UpdateOptions } from '../did.js';
import type { ResolutionWorkBudget } from '../resolution-budget.js';
import { parseDidEthr } from './did-url.js';
import { buildDidEthrDocument } from './events.js';
import { createEthersEventSource, type Erc1056EventSource } from './registry.js';

/** 現在時刻（Unix 秒）を返すクロック。テストで決定的に差し替え可能。 */
export type Clock = () => number;

/**
 * `MethodEthr` のコンストラクタ引数。
 */
export interface MethodEthrOptions {
  /** チェーン ID → RPC URL マップ（既定 eventSource 用、未設定チェーンは DID_NOT_FOUND）。 */
  readonly rpcUrls: Readonly<Record<number, string>>;
  /** イベント取得シーム。省略時は ethers 実装を `rpcUrls` から生成する。 */
  readonly eventSource?: Erc1056EventSource;
  /** チェーン ID → レジストリアドレス（既定アドレスの上書き、既定 eventSource 用）。 */
  readonly registryAddresses?: Readonly<Record<number, string>>;
  /** RPC 往復に使う fetch 実装（既定 eventSource 用。省略時はグローバル `fetch`、テスト注入用）。 */
  readonly fetchImpl?: FetchLike;
  /** 現在時刻クロック（Unix ミリ秒）。省略時は `Date.now`。 */
  readonly clock?: () => number;
}

/**
 * did:ethr を DID Document に解決する。
 *
 * @param did did:ethr 文字列。
 * @param eventSource ERC-1056 イベント取得シーム。
 * @param nowSeconds 現在時刻（Unix 秒）。validTo 評価の基準。
 * @param scope 解決スコープ全体の予算（省略時は計上しない）。
 * @returns DID Document。
 * @throws DID 形式不正の場合（VericertsError、code `2001`）、
 *         未設定チェーン・取得失敗の場合（VericertsError、code `2003`）、
 *         イベント件数・生成 VM 数が上限を超える場合（code `2010`）、
 *         スコープの予算を超える場合（code `2001`、`context.reason: 'resolution_work_limit'`）。
 */
export async function resolveDidEthr(
  did: string,
  eventSource: Erc1056EventSource,
  nowSeconds: number,
  scope?: ResolutionWorkBudget,
): Promise<DIDDocument> {
  const { chainId, address } = parseDidEthr(did);
  const events = await eventSource.fetchEvents(chainId, address, scope);
  return buildDidEthrDocument(did, address, chainId, events, nowSeconds);
}

/**
 * did:ethr メソッドプラグイン。`resolve` のみを提供する。
 *
 * 書き込み更新は別 Issue のため `create` / `update` / `deactivate` は非対応
 * （`METHOD_NOT_SUPPORTED`、code `2002`）。
 */
export class MethodEthr implements DIDMethod {
  /** ERC-1056 イベント取得シーム。 */
  private readonly eventSource: Erc1056EventSource;
  /** 現在時刻クロック（Unix ミリ秒）。 */
  private readonly clock: () => number;

  /**
   * @param opts rpcUrls（必須）と、任意の eventSource / registryAddresses / clock。
   */
  constructor(opts: MethodEthrOptions) {
    // 任意オプションは自身のプロパティだけを読む。`opts` はリテラルで渡されることが多く、
    // 素の `opts.eventSource ?? …` は `Object.prototype` の汚染値を拾って controller・RPC 宛先を差し替えられる。
    // 関数値・DI 依存はクラスインスタンスでもあり得るので `nonObjectPrototypeProperty`、純データは `ownProperty`。
    const eventSource = nonObjectPrototypeProperty<Erc1056EventSource>(opts, 'eventSource');
    const clock = nonObjectPrototypeProperty<() => number>(opts, 'clock');
    this.eventSource =
      eventSource ??
      createEthersEventSource(
        ownProperty<Readonly<Record<number, string>>>(opts, 'rpcUrls') ?? {},
        ownProperty<Readonly<Record<number, string>>>(opts, 'registryAddresses'),
        nonObjectPrototypeProperty<FetchLike>(opts, 'fetchImpl'),
      );
    this.clock = clock ?? (() => Date.now());
  }

  /** メソッド名（`'ethr'`）。 */
  method(): string {
    return 'ethr';
  }

  /** did:ethr は ERC-1056 への書き込みが必要なため生成非対応（code `2002`）。 */
  async create(_opts: CreateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /**
   * did:ethr 文字列を DID Document に解決する（ERC-1056 イベントスキャン）。
   *
   * @param scope 解決スコープ全体の予算。取得したイベントの保持量・デコード仕事量を計上する。
   */
  async resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    const nowSeconds = Math.floor(this.clock() / 1000);
    return resolveDidEthr(did, this.eventSource, nowSeconds, scope);
  }

  /** 書き込み更新は別 Issue のため非対応（code `2002`）。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** 書き込み更新（無効化）は別 Issue のため非対応（code `2002`）。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }
}
