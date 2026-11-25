/**
 * `jar-signature.ts` の `requireTrustedSigner` 向け RP Cert 判定結果キャッシュ配線。
 *
 * キャッシュ本体（TTL・キー組み立て）は `trust/rp-access/cache.ts` が提供する。本モジュールは
 * その上に「`x5c` 先頭証明書 + Trust Anchor 集合 + 失効集合からキャッシュキーを組み立てて
 * 読み書きする」という JAR 固有の配線だけを持つ薄いレイヤーで、`jar-signature.ts` 本体を
 * Linterly のファイル行数上限内に保つために分離した。
 *
 * キーはリーフ・中間証明書の DER 全体のハッシュから組み立てる（シリアルだけでは
 * 同一シリアルの偽造 `x5c` がキャッシュに衝突する）。パース不能な証明書もハッシュ化できるため、
 * キャッシュ回避の分岐は持たない。
 */

import type { TtlCache } from '../../cache/index.js';
import type { QtspServiceCertificate } from '../../trust/etsi-tsl/index.js';
import { parseCertificate } from '../../trust/etsi-tsl/index.js';
import {
  readRpCertJudgment,
  rpCertJudgmentCacheKey,
  storeRpCertJudgment,
} from '../../trust/rp-access/index.js';

/**
 * キャッシュ済みの RP Cert 判定結果を読む。
 *
 * @param nowSeconds 基準時刻（エポック秒）。検証に渡した `now` と同じものを渡す。格納時の TTL は
 *        証明書の有効期間で頭打ちにされているため、期限を過ぎた基準時刻ではヒットしない。
 *        未指定ならキャッシュ層の既定（実時計）。
 * @returns キャッシュヒットした判定結果（`true`/`false`）。未格納・TTL 切れ
 *          の場合は `undefined`（呼び出し側は `verifyRpAccessCertificate` を実行すること）。
 */
export function readCachedRpCertJudgment(
  cache: TtlCache<boolean>,
  leafDer: Uint8Array,
  intermediatesDer: readonly Uint8Array[],
  anchors: readonly QtspServiceCertificate[],
  revokedSerials: ReadonlySet<string> | undefined,
  nowSeconds?: number,
): boolean | undefined {
  return readRpCertJudgment(
    cache,
    rpCertJudgmentCacheKey(leafDer, intermediatesDer, anchors, revokedSerials),
    nowSeconds,
  );
}

/**
 * `leaf` と `intermediates` のうち、基準時刻より先に `notBefore` を迎える最も近い時刻までの秒数。
 * まだ有効でない証明書が無ければ `Infinity`。パース不能な証明書は無視する（判定が既に `false`）。
 */
function secondsUntilNotBefore(certsDer: readonly Uint8Array[], nowSeconds: number): number {
  let seconds = Number.POSITIVE_INFINITY;
  for (const der of certsDer) {
    try {
      const { notBefore } = parseCertificate(der);
      if (notBefore > nowSeconds) {
        seconds = Math.min(seconds, notBefore - nowSeconds);
      }
    } catch {
      // パース不能 = 後で有効になる見込みが無い。TTL の頭打ちには使わない。
    }
  }
  return seconds;
}

/**
 * RP Cert 判定結果をキャッシュへ格納する。
 *
 * TTL は証明書の有効期間で頭打ちにする。成功は `validUntilSeconds`（使った全証明書の
 * 最小 `notAfter`）まで。失敗は leaf・中間のいずれかが `notBefore` 前だった場合にその時刻まで
 * （有効になった後も `false` を配り続けない）。成功なのに `validUntilSeconds` が無い場合は
 * 境界が不明なので格納しない。
 *
 * @param nowSeconds 判定に使った基準時刻（エポック秒）。
 * @param validUntilSeconds `verifyRpAccessCertificate` の `validUntil`。
 */
export function storeRpCertJudgmentForLeaf(
  cache: TtlCache<boolean>,
  leafDer: Uint8Array,
  intermediatesDer: readonly Uint8Array[],
  anchors: readonly QtspServiceCertificate[],
  revokedSerials: ReadonlySet<string> | undefined,
  valid: boolean,
  nowSeconds: number,
  validUntilSeconds: number | undefined,
): void {
  const maxTtlSeconds = valid
    ? (validUntilSeconds ?? Number.NaN) - nowSeconds
    : secondsUntilNotBefore([leafDer, ...intermediatesDer], nowSeconds);
  storeRpCertJudgment(
    cache,
    rpCertJudgmentCacheKey(leafDer, intermediatesDer, anchors, revokedSerials),
    valid,
    nowSeconds,
    maxTtlSeconds,
  );
}
