/**
 * 取得した LOTL / TSL の鮮度検査（trust/etsi-tsl）。
 *
 * ETSI TS 119 612 の `SchemeInformation/NextUpdate` は「それ以降この TSL を信頼してはならない」期限である。
 * 署名が本物でも期限切れの世代を受理すると、後に withdrawn / 削除された QTSP の CA を載せた古い署名済み TSL
 * の再生（ロールバック）で失効が伝わらなくなる。`NextUpdate` は署名済み領域だけから読む（`tsl.ts`）。
 */

import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import { extractNextUpdate } from './tsl.js';

/**
 * `NextUpdate` が基準時刻より未来にある場合のみ `true`。
 *
 * 欠落・空・パース不能（`parseIsoDateTimeMs` が `NaN`）・基準時刻以前はすべて `false`（fail-closed。
 * 判定不能を「新しい」側に倒さない）。例外は投げない。
 *
 * @param xml 署名検証済みの LOTL / TSL。
 * @param nowSeconds 基準時刻（エポック秒）。
 * @returns 期限内なら `true`。
 */
export function isTrustedListCurrent(xml: string, nowSeconds: number): boolean {
  let nextUpdate: string | undefined;
  try {
    nextUpdate = extractNextUpdate(xml);
  } catch {
    return false;
  }
  return parseIsoDateTimeMs(nextUpdate) > nowSeconds * 1000;
}
