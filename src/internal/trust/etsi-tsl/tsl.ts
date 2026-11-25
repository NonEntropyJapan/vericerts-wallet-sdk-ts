/**
 * LOTL / TSL の XML 構造抽出（trust/etsi-tsl）。
 *
 * ETSI TS 119 612 の TrustStatusListType から、機能に必要な要素を取り出す:
 *  - LOTL: `OtherTSLPointer` から加盟国の TSL 取得 URL とスキーム territory を抽出。
 *  - TSL: `TrustServiceProvider` → `TSPService` のうち、現行（`ServiceHistory` を除く）の `ServiceStatus` が
 *    granted のものの `X509Certificate`（QTSP の CA/サービス証明書）を抽出。`ServiceHistory`
 *    （過去の旧情報）は対象外。
 *  - LOTL / TSL 共通: `SchemeInformation/NextUpdate` からキャッシュ用の次回更新予定日時を抽出する。
 *  - TSL: `TrustServiceProvider` 単位で `QualifiedTspEntry`に集約。
 *
 * XML パースは `xml.ts` の軽量パーサを用いる。署名検証は `xmldsig.ts` が担い、本モジュールは
 * 構造抽出に専念する（責務分離）。
 *
 * セキュリティ上の注意:
 * - 抽出結果に鍵素材は含むが（公開証明書のみ）、例外に本文を載せない。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import { encodeCertToPem } from './tsl-extract/cert-encoding.js';
import {
  collectUnnested,
  createTslExtractBudget,
  MAX_LOTL_POINTERS,
  MAX_TSL_PROVIDERS,
  MAX_TSL_SERVICES,
} from './tsl-extract/limits.js';
import {
  type AnchorPredicate,
  currentServiceView,
  extractServiceCerts,
} from './tsl-extract/service-certs.js';
import { findByLocalName } from './xml/parse.js';
import { parseSignedRegion } from './xml/signed-region.js';

/** `TrustServiceProvider` の標準的な深さ（`TrustServiceStatusList/TrustServiceProviderList/TrustServiceProvider`）。 */
const PROVIDER_DEPTH = 3;
/** ETSI ServiceStatus URI のうち EU レベルで有効（granted）を示す値。 */
const GRANTED_STATUS = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
/** 国内レベルで承認されたサービス（Qualified ではない）。Trust Anchor には既定で採らない。 */
const NATIONAL_LEVEL_STATUS =
  'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel';

/**
 * Trust Anchor として採る `ServiceTypeIdentifier` の既定。証明書を発行する Qualified CA の
 * サービス種別だけ。TSA・OCSP 応答署名・非 Qualified CA（`CA/PKC`）・EDS・PSES などは含めない。
 */
export const DEFAULT_ANCHOR_SERVICE_TYPES: readonly string[] = [
  'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
  'http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC',
];

/** Trust Anchor 抽出のオプション。いずれも own プロパティだけを読む。 */
export interface ExtractQtspOptions {
  /** Trust Anchor として採る `ServiceTypeIdentifier`（既定 {@link DEFAULT_ANCHOR_SERVICE_TYPES}）。 */
  readonly serviceTypes?: readonly string[];
  /** `true` なら `recognisedatnationallevel` も granted 扱いにする明示オプトイン（既定 `false`）。 */
  readonly includeRecognisedAtNationalLevel?: boolean;
}

/** LOTL 内の加盟国 TSL ポインタ。 */
export interface TslPointer {
  /** 加盟国 TSL の取得 URL。 */
  readonly location: string;
  /** スキームの territory（例 `DE`）。抽出できなければ undefined。 */
  readonly territory?: string;
}

/** TSL から抽出した QTSP サービス証明書。 */
export interface QtspServiceCertificate {
  /** サービス証明書の DER。 */
  readonly certDer: Uint8Array;
  /** Trust Anchor として使えるか（ServiceStatus が granted かつ ServiceTypeIdentifier が許可リスト内）。 */
  readonly granted: boolean;
}

/**
 * TSL 内の Qualified TSP をサービス単位から集約したエントリ（`QualifiedTspEntry`）。
 *
 * `TrustServiceProvider` 1 件につき 1 エントリ。配下の `TSPService` が提供するサービス種別と
 * 証明書（PEM）をまとめ、`status` は集約規則（`extractQualifiedTspEntries` 参照）で 1 つに決める。
 */
export interface QualifiedTspEntry {
  /** TSP 識別子（`TSPName` の最初の `Name` テキスト）。 */
  readonly tspId: string;
  /** 加盟国コード（呼び出し側が指定。TSL 自身の `SchemeTerritory` ではなく LOTL 由来の territory
   *  など呼び出し側が把握している文脈を採用するため、本関数は XML から自動判定しない）。 */
  readonly country: string;
  /** 提供サービス種別（`ServiceTypeIdentifier`、重複除去・出現順）。 */
  readonly services: readonly string[];
  /** Qualified Certificate（PEM エンコード）。 */
  readonly certificates: readonly string[];
  /** granted / withdrawn（集約規則は `extractQualifiedTspEntries` 参照）。 */
  readonly status: 'granted' | 'withdrawn';
}

/** 署名済み領域に `OtherTSLPointer` があるか（LOTL 判定用）。パース不能なら `false`。 */
export function hasOtherTslPointer(xml: string): boolean {
  try {
    return findByLocalName(parseSignedRegion(xml), 'OtherTSLPointer') !== undefined;
  } catch {
    return false;
  }
}

/**
 * LOTL XML から加盟国 TSL ポインタ一覧を抽出する。
 *
 * `OtherTSLPointer` ごとに `TSLLocation` と、`SchemeTerritory` を拾う。EU LOTL は各国 TSL への
 * ポインタと、参照実装用の pivot LOTL ポインタを含むが、ここでは TSLLocation を持つものを一律に
 * 返す（呼び出し側でフィルタ可能）。
 *
 * @param lotlXml LOTL の XML テキスト。
 * @returns TSL ポインタ配列。
 */
export function extractTslPointers(lotlXml: string): TslPointer[] {
  const root = parseSignedRegion(lotlXml);
  // 入れ子の `OtherTSLPointer` は仕様上存在せず、許すと外側ごとの子孫走査が二次になる。
  const pointers = collectUnnested(
    root,
    'OtherTSLPointer',
    MAX_LOTL_POINTERS,
    'tsl_too_many_pointers',
  );
  const result: TslPointer[] = [];
  for (const ptr of pointers) {
    const location = findByLocalName(ptr, 'TSLLocation')?.text.trim();
    if (location === undefined || location.length === 0) {
      continue;
    }
    const territory = findByLocalName(ptr, 'SchemeTerritory')?.text.trim();
    result.push({ location, territory: territory || undefined });
  }
  return result;
}

/** `options`（own 限定）から Trust Anchor 判定を組み立てる。型が読めないサービスは anchor にしない（fail-closed）。 */
function anchorPredicate(options: ExtractQtspOptions | undefined): AnchorPredicate {
  const rawTypes =
    options === undefined ? undefined : ownProperty<unknown>(options, 'serviceTypes');
  const types = Array.isArray(rawTypes)
    ? new Set<unknown>(rawTypes)
    : new Set<unknown>(DEFAULT_ANCHOR_SERVICE_TYPES);
  const national =
    options !== undefined &&
    ownProperty<unknown>(options, 'includeRecognisedAtNationalLevel') === true;
  return (status, typeId) =>
    typeId !== undefined &&
    types.has(typeId) &&
    (status === GRANTED_STATUS || (national && status === NATIONAL_LEVEL_STATUS));
}

/**
 * TSL XML から QTSP サービス証明書一覧を抽出する。
 *
 * `TSPService`（= `ServiceInformation` を持つ要素）を走査し、Trust Anchor 候補（`granted: true`）を返す。
 * 候補にするのは `ServiceStatus` が `granted`、かつ `ServiceTypeIdentifier` が許可リスト
 * （既定は Qualified CA の `CA/QC` / `NationalRootCA-QC`）に含まれるサービスだけ。TSA・OCSP・非 Qualified CA
 * など証明書を発行しないサービスや、種別が読めないサービスは `granted: false`。
 * `recognisedatnationallevel` は `options.includeRecognisedAtNationalLevel` で明示した場合のみ granted 扱い。
 * 抽出対象は署名済み領域だけで、`ds:Signature` 内の要素は読まない。
 *
 * @param tslXml 加盟国 TSL の XML テキスト。
 * @param options 許可する `ServiceTypeIdentifier` / 国内レベル承認の扱い。
 * @returns サービス証明書配列（granted フラグ付き）。
 */
export function extractQtspCertificates(
  tslXml: string,
  options?: ExtractQtspOptions,
): QtspServiceCertificate[] {
  const root = parseSignedRegion(tslXml);
  const isAnchor = anchorPredicate(options);
  // `TSPService` は `TSPServices` 直下に並ぶだけで入れ子にならない。入れ子を許すと外側ごとに配下の証明書を
  // 重ねて拾い、Trust Anchor が深さ倍に増幅する。
  const services = collectUnnested(root, 'TSPService', MAX_TSL_SERVICES, 'tsl_too_many_services');
  const budget = createTslExtractBudget();
  const out: QtspServiceCertificate[] = [];
  for (const service of services) {
    out.push(...extractServiceCerts(service, isAnchor, budget));
  }
  return out;
}

/** granted なサービス証明書の DER のみを返す（Trust Anchor 集合の構築用）。 */
export function grantedTrustAnchors(certs: readonly QtspServiceCertificate[]): Uint8Array[] {
  return certs.filter((c) => c.granted).map((c) => c.certDer);
}

/** エントリ集約用: サービス種別を問わず `ServiceStatus` が granted / recognisedatnationallevel なら granted。 */
const entryStatusPredicate: AnchorPredicate = (status) =>
  status === GRANTED_STATUS || status === NATIONAL_LEVEL_STATUS;

/**
 * TSL XML から `QualifiedTspEntry`一覧を抽出する。
 *
 * `TrustServiceProvider` ごとに 1 エントリを組み立てる:
 * - `tspId`: `TSPName` 配下の最初の `Name` テキスト。存在しない TSP は識別子を持てないため
 *   除外する（`extractTslPointers` の `TSLLocation` 欠落時と同じ「構造不備は黙って除外」方針）。
 * - `services`: 配下 `TSPService` の `ServiceTypeIdentifier`（重複除去・出現順）。
 * - `certificates`: 配下 `TSPService` の証明書すべてを PEM エンコードしたもの
 *   （`extractQtspCertificates` と異なり granted 有無で絞り込まない。エンティティ全体の
 *   保有証明書を表すため）。
 * - `status`: 配下に証明書が 1 件も無い、またはいずれか 1 件でも非 granted（withdrawn 等）なら
 *   `'withdrawn'`。すべて granted のときのみ `'granted'`（fail-closed: 部分的な失効や
 *   判定不能を「有効」側に倒さない）。
 *
 * @param tslXml 加盟国 TSL の XML テキスト。
 * @param country 加盟国コード（呼び出し側が指定。TSL 自身の `SchemeTerritory` は参照しない）。
 * @returns Qualified TSP エントリ配列。
 */
export function extractQualifiedTspEntries(tslXml: string, country: string): QualifiedTspEntry[] {
  const root = parseSignedRegion(tslXml);
  // `TrustServiceProvider` / `TSPService` は入れ子にならない。サービスは provider ごとに集める。
  const providers = collectUnnested(
    root,
    'TrustServiceProvider',
    MAX_TSL_PROVIDERS,
    'tsl_too_many_providers',
  );
  const budget = createTslExtractBudget();
  let serviceCount = 0;
  const out: QualifiedTspEntry[] = [];
  for (const provider of providers) {
    const tspNameEl = findByLocalName(provider, 'TSPName');
    const tspId = (
      tspNameEl !== undefined ? findByLocalName(tspNameEl, 'Name') : undefined
    )?.text.trim();
    if (tspId === undefined || tspId.length === 0) {
      continue;
    }
    const services = collectUnnested(
      provider,
      'TSPService',
      MAX_TSL_SERVICES - serviceCount,
      'tsl_too_many_services',
      PROVIDER_DEPTH,
    );
    serviceCount += services.length;
    const serviceTypes = new Set<string>();
    const certificates: string[] = [];
    let hasCertificate = false;
    let allGranted = true;
    for (const service of services) {
      const typeId = findByLocalName(
        currentServiceView(service),
        'ServiceTypeIdentifier',
      )?.text.trim();
      if (typeId !== undefined && typeId.length > 0) {
        serviceTypes.add(typeId);
      }
      for (const cert of extractServiceCerts(service, entryStatusPredicate, budget)) {
        hasCertificate = true;
        certificates.push(encodeCertToPem(cert.certDer));
        if (!cert.granted) {
          allGranted = false;
        }
      }
    }
    out.push({
      tspId,
      country,
      services: [...serviceTypes],
      certificates,
      status: hasCertificate && allGranted ? 'granted' : 'withdrawn',
    });
  }
  return out;
}

/**
 * LOTL / TSL の `SchemeInformation/NextUpdate/dateTime` から次回更新予定日時を抽出する
 * （`TrustedListCache.nextUpdate`）。
 *
 * 見つからない、または空の場合は `undefined` を返す（他の抽出関数と同じく構造不備を例外にせず
 * 呼び出し側の判断に委ねる。`cache.ts` の `buildTrustedListCacheEntry` は `undefined` のとき
 * 取得日時を代わりに採用し、結果として即時失効扱いになる）。
 *
 * @param xml LOTL / TSL の XML テキスト。
 * @returns 次回更新予定日時の文字列（TSL の記法をそのまま返す）。抽出不能なら `undefined`。
 */
export function extractNextUpdate(xml: string): string | undefined {
  const root = parseSignedRegion(xml);
  const nextUpdateEl = findByLocalName(root, 'NextUpdate');
  const dateTimeEl =
    nextUpdateEl !== undefined ? findByLocalName(nextUpdateEl, 'dateTime') : undefined;
  const text = dateTimeEl?.text.trim();
  return text !== undefined && text.length > 0 ? text : undefined;
}
