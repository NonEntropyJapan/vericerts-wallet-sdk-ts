/**
 * Trust Chain 構築結果（`FederationEntityCache`）の型定義とキャッシュ層。
 *
 * TTL の計算には、Federation の Entity Statement キャッシュと同じ上限を適用する。
 *
 * `statement-cache.ts` が「1 つの Entity Statement（生 JWT）」を記憶するのに対し、本モジュールは
 * 「Leaf → Trust Anchor まで解決し終えた chain 全体」を 1 エントリとして記憶する。したがって
 * キャッシュキーは URL ではなく Leaf の Entity Identifier（`entityId`）である。
 *
 * 本キャッシュは**プロセス内の TTL キャッシュ**であり、ディスク / DB への永続化ではない
 * （`cache/ttl-cache.ts`）。プロセス再起動で消えれば必ず再構築が走るため、失効・鍵無効化の反映が
 * 遅れる方向には倒れない（fail-closed 側）。「永続キャッシュ」という語はこの意味で使う。
 *
 * TTL の上界は `statement-cache.ts` と同じく `FEDERATION_CACHE_MAX_TTL_SECONDS`（600 秒）で
 * 頭打ちにする。これは性能調整値ではなく鍵無効化宣言（`revoked_keys`）の伝播 SLA という仕様上の
 * 要求であり、chain 単位で記憶する本モジュールでこそ緩めてはならない（chain 全体を長く抱えると
 * 上位が公開した無効化宣言がその間ずっと Verifier に届かない）。
 *
 * セキュリティ上の注意:
 * - `FederationEntityCache` は entity_id と JWT を含む。ログ・例外メッセージ・`context`・観測
 *   イベントには載せない。
 */

import { createTtlCache, systemNowSeconds, type TtlCache } from '../../../cache/index.js';
import { parseIsoDateTimeMs } from '../../../cache/iso-datetime.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { TrustChain, TrustChainNode } from '../federation-types.js';
import { FEDERATION_CACHE_MAX_TTL_SECONDS } from './statement-cache.js';

/**
 * Trust Chain の解決結果（`FederationEntityCache` に対応）。
 *
 * `trustChain` は Leaf（index 0）→ Trust Anchor（末尾）順の生 compact JWT 列であり、
 * `TrustChain.nodes` と同じ並びである。`entityConfigurationJwt` はそのうち Leaf の
 * Entity Configuration JWT（= `trustChain[0]`）を再掲したものである。
 */
export interface FederationEntityCache {
  /** Leaf の Entity Identifier（HTTPS URL）。キャッシュキーでもある。 */
  readonly entityId: string;
  /** Leaf の Entity Configuration の生 compact JWT。 */
  readonly entityConfigurationJwt: string;
  /**
   * この chain が依拠する Trust Anchor の Entity Identifier 群。
   *
   * 現行 `buildTrustChain` は単一 trustAnchor 引数のみを取るため、`toFederationEntityCache` が
   * 組み立てる値は常に単一要素配列になる。複数トラストアンカー対応は実装の対象外。
   */
  readonly trustAnchors: readonly string[];
  /** Leaf → Trust Anchor 順の生 compact JWT 列（`TrustChain.nodes` と同じ並び）。 */
  readonly trustChain: readonly string[];
  /** Trust Chain 検証結果（`TrustChain.valid`）。 */
  readonly valid: boolean;
  /** 取得（chain 構築）日時（ISO 8601 / UTC）。 */
  readonly fetchedAt: string;
  /** この結果を信頼してよい期限（ISO 8601 / UTC）。 */
  readonly expiresAt: string;
}

/** エポック秒を ISO 8601（UTC）文字列に変換する。 */
function toIsoString(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString();
}

/**
 * ノードの生 JWT を取り出す。未設定なら chain 構築側の配線漏れとして不成立にする。
 *
 * `jwt` は型上 optional（既存呼び出し側を壊さないための追加フィールド）だが、
 * `buildTrustChain` が返す chain では全ノードに設定される。欠落を黙って握り潰すと
 * 「Trust Anchor まで届かない `trustChain`」が正当な結果として記憶されるため、投げる。
 */
function requireNodeJwt(node: TrustChainNode | undefined): string {
  const jwt = node === undefined ? undefined : ownProperty<string>(node, 'jwt');
  if (jwt === undefined) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  return jwt;
}

/**
 * chain 全体の有効期限（エポック秒）を求める。
 *
 * 採用 TTL は `min(min(全ノードの exp) - now, maxTtlSeconds)` を 0 で下限クリップした値。
 * 最小 `exp` を採るのは、**チェーン内で最も早く失効するリンクが 1 つでもあればチェーン全体が
 * 成立しなくなる**ためである（1 段でも期限切れなら `buildTrustChain` は 5010 で不成立になる）。
 * 個々のノードの `exp` ではなく最小値で切らないと、既に成立しない chain をキャッシュが
 * 有効なものとして返し続ける。
 *
 * `maxTtlSeconds` による頭打ちは SDK の判断ではなく鍵無効化宣言の伝播 SLA という仕様上の要求
 * （`FEDERATION_CACHE_MAX_TTL_SECONDS`）。
 *
 * **`chain.warnings`（FO-6 由来）が設定されている場合は TTL を 0 にする**。FO-6 は 同意・監査・60 秒ウィンドウを前提に 1 回の解決だけを通過させる判定
 * であり、chain 単位で最大 600 秒キャッシュしてこれらの前提を素通りさせてはならないため。
 *
 * @param chain 構築済み Trust Chain。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @param maxTtlSeconds TTL 上限（秒）。
 * @returns 有効期限（エポック秒）。
 */
function chainExpiresAtSeconds(
  chain: TrustChain,
  nowSeconds: number,
  maxTtlSeconds: number,
): number {
  if (ownProperty<unknown>(chain, 'warnings') !== undefined) {
    return nowSeconds;
  }
  const minExp = Math.min(...chain.nodes.map((node) => node.statement.exp));
  return nowSeconds + Math.max(0, Math.min(minExp - nowSeconds, maxTtlSeconds));
}

/**
 * `FederationEntityCache.expiresAt` から `cache.set` に渡す TTL（秒）を逆算する。
 *
 * `toFederationEntityCache` の `expiresAt` は「chain.warnings（FO-6 由来）なら TTL 0」「最も早く
 * 失効するノードの `exp`」「`maxTtlSeconds`（既定 600 秒）上限」をすべて織り込んだ**唯一の出典**
 * である。にもかかわらず `expiresAt` は文字列フィールドとして表示されるだけで、実際の
 * `TtlCache.set` 第三引数（TTL 秒）は呼び出し側が別途組み立てる形になっており、両者が食い違う
 * 余地があった。呼び出し側が `maxTtlSeconds` 等から TTL を独自に
 * 再計算すると、FO-6 由来 chain の TTL 0 化が `cache.set` まで伝わらずに元の TTL（最大 600 秒）が
 * 使われてしまう——これは実際に発生していた不具合であり、本関数はそれを塞ぐために設けた。
 *
 * 推奨呼び出しパターン:
 * ```ts
 * const cached = toFederationEntityCache(chain, nowSeconds);
 * cache.set(cached.entityId, cached, federationEntityCacheTtlSeconds(cached, nowSeconds), nowSeconds);
 * ```
 *
 * @param cached `toFederationEntityCache` が返した Trust Chain 解決結果。
 * @param nowSeconds 現在時刻（エポック秒）。`toFederationEntityCache` に渡したものと同じ時計を使う。
 * @returns `TtlCache.set` の第三引数に渡す TTL（秒）。0 で下限クリップ（負値を作らない）。
 *   `expiresAt` が厳格 ISO 8601（オフセット必須）でない、または `nowSeconds` が非有限なら 0（キャッシュしない）。
 */
export function federationEntityCacheTtlSeconds(
  cached: FederationEntityCache,
  nowSeconds: number,
): number {
  const expiresAtSeconds = Math.floor(parseIsoDateTimeMs(cached.expiresAt) / 1000);
  const ttlSeconds = expiresAtSeconds - nowSeconds;
  return Number.isFinite(ttlSeconds) ? Math.max(0, ttlSeconds) : 0;
}

/**
 * 構築済み Trust Chain を `FederationEntityCache`に変換する。
 *
 * 生 JWT はすべて chain のノードから採る。いずれかのノードで `jwt` が欠落していれば
 * `TRUST_CHAIN_INVALID`（5010）で不成立にする（欠落したまま短い `trustChain` を作らない）。
 *
 * @param chain `buildTrustChain` が返した検証済み Trust Chain。
 * @param nowSeconds 現在時刻（エポック秒）。`fetchedAt` と TTL の起点になる。
 * @param maxTtlSeconds TTL 上限（秒）。既定は `FEDERATION_CACHE_MAX_TTL_SECONDS`（600）。
 * @returns 永続化可能な形にまとめた Trust Chain 解決結果。
 * @throws ノードの生 JWT が欠落している場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function toFederationEntityCache(
  chain: TrustChain,
  nowSeconds: number,
  maxTtlSeconds: number = FEDERATION_CACHE_MAX_TTL_SECONDS,
): FederationEntityCache {
  const trustChain = chain.nodes.map((node) => requireNodeJwt(node));
  return {
    entityId: chain.leaf,
    entityConfigurationJwt: requireNodeJwt(chain.nodes[0]),
    trustAnchors: [chain.trustAnchor],
    trustChain,
    valid: chain.valid,
    fetchedAt: toIsoString(nowSeconds),
    expiresAt: toIsoString(chainExpiresAtSeconds(chain, nowSeconds, maxTtlSeconds)),
  };
}

/**
 * Trust Chain 解決結果用の TTL キャッシュを生成する。
 *
 * キーは Leaf の Entity Identifier（`FederationEntityCache.entityId`）。TTL 上限は
 * `FEDERATION_CACHE_MAX_TTL_SECONDS`（600 秒）で固定し、生成側では緩められない
 * （`createFederationStatementCache` と同じ規律）。
 *
 * get / set の専用ラッパは設けない。呼び出し側は `cache.get(entityId, nowSeconds)` /
 * `cache.set(entityId, cached, federationEntityCacheTtlSeconds(cached, nowSeconds), nowSeconds)`
 * を直接使う（`ttlSeconds` を独自に組み立てない。`federationEntityCacheTtlSeconds` が
 * `cached.expiresAt`——FO-6 由来 chain の TTL 0 化を含む——から逆算した値だけを使うことで、
 * `expiresAt` の意味論と実際のキャッシュ保持時間を一致させる）。
 *
 * @param nowSeconds 時計（エポック秒）。未指定なら実時計。
 * @param maxEntries 保持する最大エントリ数（省略時はキャッシュ層の既定）。
 * @returns Trust Chain 解決結果用 TTL キャッシュ。
 */
export function createFederationEntityCache(
  nowSeconds: () => number = systemNowSeconds,
  maxEntries?: number,
): TtlCache<FederationEntityCache> {
  const maxTtlSeconds = FEDERATION_CACHE_MAX_TTL_SECONDS;
  return createTtlCache<FederationEntityCache>(
    maxEntries === undefined
      ? { maxTtlSeconds, nowSeconds }
      : { maxTtlSeconds, nowSeconds, maxEntries },
  );
}
