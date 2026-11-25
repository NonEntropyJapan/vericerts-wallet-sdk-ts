/**
 * TSL / LOTL 構造抽出の仕事量予算と構造制限（trust/etsi-tsl）。
 *
 * ETSI TS 119 612 の `TSPService` は `TrustServiceProvider/TSPServices` の直下に並ぶだけで、入れ子にならない。
 * 以前は `TSPService` を子孫から全件拾い（入れ子の内側も外側も）、外側ごとに配下の `X509Certificate` を全て
 * 拾っていたため、深さ d に入れ子にした 1 つの署名済み TSL（8 MiB 以内）が証明書数 N を d×N 件の Trust Anchor
 * へ増幅した（60 段・8 MB で 115 万件、`verifyQualifiedCertificate` が 6.6 秒・RSS 3.5 GB）。
 *
 * 対策は 2 層。
 *  1. 構造: `TSPService` / `TrustServiceProvider` / `OtherTSLPointer` は同名の要素の内側に現れたら拒否
 *     する（入れ子を許さなければ、各要素は高々 1 つの親にしか属さず、抽出量は XML 本文に比例する）。
 *     加えて、これらを期待される深さ（実在 TSL は 5 段）の範囲に限る。
 *  2. 総量: サービス数・証明書数・Trust Anchor 数・ポインタ数を 1 回の抽出ごとに数え、超過は拒否する。
 *     Trust Anchor は `verifyQualifiedCertificate` が検証 1 回ごとに全件を再パースするため、構造が正しくても
 *     件数自体を縛る。
 *
 * 超過はすべて `TSL_SIG_INVALID`（署名済みでも構造が信頼できない TSL を受理しない fail-closed。既存の
 * 要素数・深さ超過がどちらも署名検証失敗に畳まれるのと同じ扱い）。`context.reason` で原因を区別する。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { XmlElement } from '../xml/parse.js';

/** 実在の EU 加盟国 TSL（31 件）で `TSPService` が現れる深さは 5（`TrustServiceStatusList` を 1 とする）。 */
export const MAX_TSL_ELEMENT_DEPTH = 8;
/** 1 つの TSL に許す `TrustServiceProvider` の総数（実在の最大は 100 程度）。 */
export const MAX_TSL_PROVIDERS = 4_096;
/** 1 つの TSL に許す `TSPService` の総数（実在の最大は 1,000 未満）。 */
export const MAX_TSL_SERVICES = 8_192;
/** 1 つの TSL で読む `X509Certificate` の総数（`TSPService` 配下の現行情報のみ。実在の最大は 1,000 程度）。 */
export const MAX_TSL_CERTIFICATES = 8_192;
/** 1 つの TSL から返す Trust Anchor（granted な証明書）の総数。 */
export const MAX_TSL_TRUST_ANCHORS = 4_096;
/** 1 つの LOTL に許す `OtherTSLPointer` の総数（実在は 50 未満）。 */
export const MAX_LOTL_POINTERS = 1_024;

/** 抽出 1 回あたりの総量カウンタ（証明書・Trust Anchor）。 */
export interface TslExtractBudget {
  certificates: number;
  trustAnchors: number;
}

/** 新しい抽出予算（全て 0 から数える）。 */
export function createTslExtractBudget(): TslExtractBudget {
  return { certificates: 0, trustAnchors: 0 };
}

/** 構造・総量の違反を `TSL_SIG_INVALID`（`context.reason` 付き）で拒否する。 */
function reject(reason: string): never {
  throw new VericertsError(ErrorCodes.TSL_SIG_INVALID, { context: { reason } });
}

/**
 * `root` 配下（`root` 自身を含む）の `localName` 要素を、入れ子を許さず・深さ制限つきで集める。
 *
 * @param root 探索の起点。
 * @param localName 集める要素のローカル名。
 * @param max 集めてよい件数（超過は `reason` で拒否）。
 * @param reason 件数超過時の `context.reason`。
 * @param rootDepth `root` の深さ（`TrustServiceStatusList` = 1。`TrustServiceProvider` 配下なら 3 など）。
 * @returns 外側の要素のみ（入れ子が無いので全件）。
 * @throws 同名要素の内側に同名要素がある / 深さ `MAX_TSL_ELEMENT_DEPTH` 超 / 件数超過
 *   （VericertsError、TSL_SIG_INVALID）。
 */
export function collectUnnested(
  root: XmlElement,
  localName: string,
  max: number,
  reason: string,
  rootDepth = 1,
): XmlElement[] {
  const out: XmlElement[] = [];
  const walk = (el: XmlElement, depth: number, inside: boolean): void => {
    const isTarget = el.localName === localName;
    if (isTarget) {
      if (inside) {
        reject('tsl_nested_element');
      }
      if (depth > MAX_TSL_ELEMENT_DEPTH) {
        reject('tsl_element_too_deep');
      }
      if (out.length >= max) {
        reject(reason);
      }
      out.push(el);
    }
    for (const child of el.children) {
      walk(child, depth + 1, inside || isTarget);
    }
  };
  walk(root, rootDepth, false);
  return out;
}

/** 証明書要素 1 件を数える（デコード前）。超過は拒否。 */
export function countCertificate(budget: TslExtractBudget): void {
  if (budget.certificates >= MAX_TSL_CERTIFICATES) {
    reject('tsl_too_many_certificates');
  }
  budget.certificates += 1;
}

/** Trust Anchor 1 件を数える。超過は拒否。 */
export function countTrustAnchor(budget: TslExtractBudget): void {
  if (budget.trustAnchors >= MAX_TSL_TRUST_ANCHORS) {
    reject('tsl_too_many_trust_anchors');
  }
  budget.trustAnchors += 1;
}
