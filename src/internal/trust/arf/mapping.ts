/**
 * ARF ⇔ ETSI TSL マッピング。
 *
 * ETSI Trusted List（trust/etsi-tsl）から抽出した granted な QTSP サービス証明書と、ARF
 * Catalogue（catalogue.ts）の登録エントリを突き合わせ、両 Trust Framework 間の対応関係を返す。
 *
 * 3 層統合信頼判定（Layer 1: ETSI TSL > Layer 3: ARF）で、同一の Trust Anchor がどちらの層に載って
 * いるかを可視化するための基礎データを提供する。突き合わせキーは証明書公開鍵の SPKI
 * （subjectPublicKeyInfo・DER）とする。ARF エントリの公開鍵と QTSP サービス証明書の公開鍵が一致
 * すれば「同一 Trust Anchor」とみなす。統合信頼判定そのもの（優先順位・キャッシュ・競合解消）は
 * `evaluateTrust`の責務とする。
 *
 * セキュリティ上の注意:
 * - 突き合わせは公開鍵の完全一致のみで判定する（部分一致・DN 文字列一致は用いない）。
 * - 例外・戻り値に証明書本文 / 鍵素材の平文表現を含めない。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import { derEquals, parseCertificate } from '../etsi-tsl/x509.js';
import type { ArfCatalogueEntry } from './arf-types.js';

/** ETSI TSL の granted QTSP サービス証明書（trust/etsi-tsl と同型・依存を最小化するため再宣言）。 */
export interface TslServiceCertificate {
  /** サービス証明書の DER。 */
  readonly certDer: Uint8Array;
  /** ServiceStatus が granted 相当か。 */
  readonly granted: boolean;
}

/** ARF エントリと ETSI TSL 証明書の 1 対応。 */
export interface ArfTslMatch {
  /** 対応した ARF Catalogue エントリ。 */
  readonly entry: ArfCatalogueEntry;
  /** 対応した TSL サービス証明書の DER。 */
  readonly tslCertDer: Uint8Array;
}

/** `mapArfToTsl` の結果。 */
export interface ArfTslMapping {
  /** ARF ⇔ TSL の両方に載る Trust Anchor（SPKI 一致）。 */
  readonly matched: readonly ArfTslMatch[];
  /** TSL に対応がない ARF エントリ（ARF のみ・Layer 3 限定）。 */
  readonly arfOnly: readonly ArfCatalogueEntry[];
  /** ARF に対応がない TSL granted 証明書の DER（TSL のみ・Layer 1 限定）。 */
  readonly tslOnly: readonly Uint8Array[];
}

/**
 * ARF エントリの SPKI を読む。**自身のプロパティだけ**を採り、`Uint8Array` 以外は無いものとして扱う。
 *
 * `loadArfTrustAnchor` は SPKI を持たないエントリ（Layer 3 のみの登録）に `spki` プロパティを生やさない。
 * 素で読むと `Object.prototype.spki` に TSL の granted 証明書の SPKI（公開情報）を置くだけで、ARF にしか
 * 載っていないエントリが Layer 1（TSL）の Qualified と突き合わさり、`evaluateTrust` の最上位に採られる。
 * SPKI の有無判定と突き合わせの両方（SDK の `mapArfToTsl` / 呼び出し側の事前判定）が本関数を共有する。
 *
 * @param entry ARF Catalogue エントリ。
 * @returns SPKI。持たなければ `undefined`。
 */
export function arfEntrySpki(entry: ArfCatalogueEntry): Uint8Array | undefined {
  const spki = ownProperty<unknown>(entry, 'spki');
  return spki instanceof Uint8Array ? spki : undefined;
}

/**
 * ARF Catalogue エントリと ETSI TSL の granted サービス証明書を SPKI で突き合わせる。
 *
 * granted でない TSL 証明書、および公開鍵（SPKI）を持たない ARF エントリはマッチ対象外とし、
 * それぞれ `arfOnly` / `tslOnly` にも含めない（信頼判定に使えないため）。
 *
 * @param arfEntries ARF Catalogue の登録エントリ。
 * @param tslCerts ETSI TSL から抽出したサービス証明書（granted フラグ付き）。
 * @returns ARF ⇔ TSL の対応関係（一致・ARF のみ・TSL のみ）。
 */
export function mapArfToTsl(
  arfEntries: readonly ArfCatalogueEntry[],
  tslCerts: readonly TslServiceCertificate[],
): ArfTslMapping {
  const tslSpkis = grantedTslSpkis(tslCerts);

  const matched: ArfTslMatch[] = [];
  const arfOnly: ArfCatalogueEntry[] = [];
  const matchedTslIndices = new Set<number>();

  for (const entry of arfEntries) {
    const entrySpki = arfEntrySpki(entry);
    if (entrySpki === undefined) {
      continue;
    }
    const hit = tslSpkis.find(
      (t) => !matchedTslIndices.has(t.index) && derEquals(t.spki, entrySpki),
    );
    if (hit !== undefined) {
      matchedTslIndices.add(hit.index);
      matched.push({ entry, tslCertDer: hit.certDer });
    } else {
      arfOnly.push(entry);
    }
  }

  const tslOnly = tslSpkis.filter((t) => !matchedTslIndices.has(t.index)).map((t) => t.certDer);

  return { matched, arfOnly, tslOnly };
}

/** granted な TSL サービス証明書から SPKI を抽出する（パース不能なものは除外・fail-closed）。 */
function grantedTslSpkis(
  tslCerts: readonly TslServiceCertificate[],
): { index: number; spki: Uint8Array; certDer: Uint8Array }[] {
  const out: { index: number; spki: Uint8Array; certDer: Uint8Array }[] = [];
  let index = 0;
  for (const cert of tslCerts) {
    // `granted` も own 限定。欠落した入力が汚染値 `true` で granted 扱いにならないようにする。
    if (ownProperty<boolean>(cert, 'granted') !== true) {
      continue;
    }
    try {
      const parsed = parseCertificate(cert.certDer);
      out.push({ index: index++, spki: parsed.spki, certDer: cert.certDer });
    } catch {
      // 不正な証明書は信頼リストに載せない。
    }
  }
  return out;
}
