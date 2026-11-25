/**
 * 取得した LOTL / TSL の世代の単調性検査（trust/etsi-tsl）。
 *
 * `freshness.ts` の `NextUpdate` 検査は「期限切れの世代」しか落とせない。加盟国 TSL の `NextUpdate` は通常
 * 数か月先で、その間は CA が granted だった旧世代（後に withdrawn になる前の署名済み TSL）を TLS を握る
 * 攻撃者が再生できる。ETSI TS 119 612 は世代ごとに `SchemeInformation/TSLSequenceNumber` を単調増加で
 * 振り、`ListIssueDateTime` も発行のたびに進むので、キャッシュに直前の世代があればそれより古い世代を拒否する。
 *
 * 守れる範囲: 注入された `cache` に直近に受理した世代が残っている間。基準は TTL 切れ（キャッシュ寿命の
 * 30 日上限 `TRUSTED_LIST_CACHE_MAX_TTL_SECONDS` や `NextUpdate` 超過）でも使い続ける（TTL 内だけだと
 * 31 日目以降は `NextUpdate` 内の旧世代を再生できる）。キャッシュを渡さない呼び出し側、容量超過で追い出された
 * エントリ、初回取得は守れない。拡張は直近に受理した世代を
 * `chrome.storage.local` に残して毎回渡す。値はいずれも署名済み領域から
 * 読む（`parseSignedRegion`）ので、署名検証後に呼ぶこと。
 */

import type { TtlCache } from '../../cache/index.js';
import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { readLastAcceptedTrustedList, type TrustedListCache } from './cache.js';
import { findByLocalName, type XmlElement } from './xml/parse.js';
import { parseSignedRegion } from './xml/signed-region.js';

/** 署名済み TSL から読んだ世代情報。読めなかった項目は `undefined`。 */
export interface TrustedListGeneration {
  /** `TSLSequenceNumber`（正の整数。桁数に上限を置かないため bigint）。 */
  readonly sequenceNumber?: bigint;
  /** `ListIssueDateTime`（エポックミリ秒）。 */
  readonly issueDateTimeMs?: number;
}

/** `SchemeInformation` 直下の子要素のテキストを返す（無ければ `undefined`）。 */
function schemeInformationChildText(
  scheme: XmlElement | undefined,
  localName: string,
): string | undefined {
  const text = scheme?.children.find((c) => c.localName === localName)?.text.trim();
  return text === undefined || text.length === 0 ? undefined : text;
}

/**
 * 署名済み領域から `TSLSequenceNumber` / `ListIssueDateTime` を読む。構造不備・不正値は `undefined`
 * （例外は投げない。判定側が「新しい世代が読めない」を拒否に倒す）。
 */
export function extractTrustedListGeneration(xml: string): TrustedListGeneration {
  let scheme: XmlElement | undefined;
  try {
    scheme = findByLocalName(parseSignedRegion(xml), 'SchemeInformation');
  } catch {
    return {};
  }
  const rawSequence = schemeInformationChildText(scheme, 'TSLSequenceNumber');
  const rawIssue = schemeInformationChildText(scheme, 'ListIssueDateTime');
  const issueMs = rawIssue === undefined ? Number.NaN : parseIsoDateTimeMs(rawIssue);
  return {
    ...(rawSequence !== undefined && /^\d{1,30}$/.test(rawSequence)
      ? { sequenceNumber: BigInt(rawSequence) }
      : {}),
    ...(Number.isNaN(issueMs) ? {} : { issueDateTimeMs: issueMs }),
  };
}

/**
 * 新しく取得した世代が、直前に受理した世代より古くないかを返す。
 *
 * - 直前の世代に `TSLSequenceNumber` があれば、新しい世代も持ち、かつそれ以上でなければならない。
 *   厳密に大きければ受理し、同値なら `ListIssueDateTime` の比較へ進む（同一世代の再取得は許す）。
 * - 直前の世代に `ListIssueDateTime` があれば、新しい世代も持ち、かつそれ以上でなければならない。
 * - 直前の世代にどちらも無ければ比較できないので `true`（従来どおり `NextUpdate` 検査のみ）。
 * 新しい側に項目が無い・読めないのに直前の世代にはあった場合は `false`（項目を消した旧世代で比較を
 * 迂回させない）。
 *
 * @param previousXml 直前に受理した（署名検証済みの）XML。
 * @param currentXml 今回取得した（署名検証済みの）XML。
 * @returns 世代が後退していなければ `true`。
 */
export function isTrustedListGenerationMonotonic(previousXml: string, currentXml: string): boolean {
  // 世代は own 限定で読む。項目が読めなかった世代は `{}`（パース失敗を含む）で、`Object.prototype.sequenceNumber` /
  // `issueDateTimeMs` の汚染値が「新世代の項目」として拾われると、項目を消した旧世代で後退検査を迂回できてしまう。
  const previous = extractTrustedListGeneration(previousXml);
  const current = extractTrustedListGeneration(currentXml);
  const previousSequence = ownProperty<bigint>(previous, 'sequenceNumber');
  const currentSequence = ownProperty<bigint>(current, 'sequenceNumber');
  if (previousSequence !== undefined) {
    if (currentSequence === undefined || currentSequence < previousSequence) {
      return false;
    }
    if (currentSequence > previousSequence) {
      return true;
    }
  }
  const previousIssue = ownProperty<number>(previous, 'issueDateTimeMs');
  if (previousIssue !== undefined) {
    const currentIssue = ownProperty<number>(current, 'issueDateTimeMs');
    return currentIssue !== undefined && currentIssue >= previousIssue;
  }
  return true;
}

/**
 * `cache` に直近に受理した世代（TTL 切れでも可）があり、取得した世代がそれより後退していれば署名検証失敗と同じコード
 * （LOTL: 10302 / TSL: 5002）で拒否する。署名検証後に呼ぶこと。FO-5 の cache 由来 XML には適用しない
 * （それ自体が直前の世代）。
 *
 * @throws VericertsError 世代が後退している場合。
 */
export function assertNotRolledBack(
  cache: TtlCache<TrustedListCache>,
  url: string,
  kind: 'lotl' | 'tsl',
  xml: string,
  nowSeconds: number,
): void {
  const previous = readLastAcceptedTrustedList(cache, url, nowSeconds);
  // 前回の XML は own 限定で読む。own の文字列でない（欠落・汚染継承）なら比較できないので拒否する（fail-closed）。
  const previousXml = previous === undefined ? undefined : ownProperty<unknown>(previous, 'xml');
  if (
    previous !== undefined &&
    (typeof previousXml !== 'string' || !isTrustedListGenerationMonotonic(previousXml, xml))
  ) {
    throw new VericertsError(
      kind === 'tsl' ? ErrorCodes.TSL_SIG_INVALID : ErrorCodes.XMLDSIG_VERIFICATION_FAILED,
    );
  }
}
