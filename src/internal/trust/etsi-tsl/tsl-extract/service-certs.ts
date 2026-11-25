import type { QtspServiceCertificate } from '../tsl.js';
import { findAllByLocalName, findByLocalName, type XmlElement } from '../xml/parse.js';
import { decodeCert } from './cert-encoding.js';
import { countCertificate, countTrustAnchor, type TslExtractBudget } from './limits.js';

/** サービスが Trust Anchor 候補か判定する関数（`ServiceStatus` / `ServiceTypeIdentifier` のテキストを受ける）。 */
export type AnchorPredicate = (status: string | undefined, typeId: string | undefined) => boolean;

/**
 * TSPService から `ServiceHistory`（過去の旧サービス情報）を除いた現行ビューを返す。
 *
 * `ServiceHistory/ServiceHistoryInstance` は withdrawn / revoked を含む旧証明書の履歴であり、
 * 現行の ServiceStatus を適用して Trust Anchor にしてはならない。
 */
export function currentServiceView(service: XmlElement): XmlElement {
  return { ...service, children: service.children.filter((c) => c.localName !== 'ServiceHistory') };
}

/**
 * TSPService の現行情報（`ServiceHistory` を除く）から、ステータス付きでサービス証明書を抽出する。
 * 証明書要素と granted な Trust Anchor は `budget` に数え、上限超過は拒否する。
 */
export function extractServiceCerts(
  service: XmlElement,
  isAnchor: AnchorPredicate,
  budget: TslExtractBudget,
): QtspServiceCertificate[] {
  const info = currentServiceView(service);
  const status = findByLocalName(info, 'ServiceStatus')?.text.trim();
  const typeId = findByLocalName(info, 'ServiceTypeIdentifier')?.text.trim();
  const granted = isAnchor(status, typeId);
  const certEls = findAllByLocalName(info, 'X509Certificate');
  const out: QtspServiceCertificate[] = [];
  for (const el of certEls) {
    countCertificate(budget);
    if (el.text.trim().length === 0) {
      continue;
    }
    try {
      out.push({ certDer: decodeCert(el.text), granted });
    } catch {
      // 不正な証明書エンコードは黙って除外（fail-closed: 信頼リストに載せない）。
      continue;
    }
    if (granted) {
      countTrustAnchor(budget);
    }
  }
  return out;
}
