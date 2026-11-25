/**
 * ETSI Trusted List の高レベル API（trust/etsi-tsl）。
 *
 * LOTL / TSL の取得（DI seam）→ XMLDSig 検証 → QTSP サービス証明書抽出、および取得済み Trust
 * Anchor に対する Qualified Certificate チェーン検証を提供する。ネットワーク I/O は SDK コアに
 * 持ち込まず `TrustedListFetcher` 経由で注入する（既存の status-list-resolver / fetch-adapter と
 * 同方針の依存隔離・テスト容易性）。facade（wallet.ts）への配線は統合担当が行う。
 *
 * 対応 API:
 *  - `loadTrustedList(url)`: LOTL または TSL を取得・署名検証し、国一覧・Trust Anchor を返す。
 *  - `verifyQualifiedCertificate(cert)`: リーフ証明書を Trust Anchor 群に対して検証する。
 *
 * ## キャッシュと Fail-open（FO-5）
 *
 * `options.cache` を注入した場合、取得・署名検証に成功するたびに `cache.ts` の TTL キャッシュへ
 * 格納する（TTL は TSL 自身の `NextUpdate`）。取得に失敗したとき、**さらに `options.failOpenWindow`
 * を注入した場合に限り**、キャッシュが有効期限内（`NextUpdate` を過ぎていない）であれば警告付きで
 * 通過する（FO-5）。キャッシュが無い・期限切れの場合は
 * fail-closed のままである（`fail-open.ts` の JSDoc を参照）。
 *
 * セキュリティ上の注意:
 * - fail-closed が既定。取得失敗は 5001/10301、署名検証失敗は 5002/10302、チェーン不成立は 10303。
 *   FO-5 はいずれも明示的なオプトイン（`cache` + `failOpenWindow`）でのみ有効になる。
 * - 例外・戻り値・context に XML 本文 / URL / 鍵素材を含めない。
 */

import type { TtlCache } from '../../cache/index.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../errors.js';
import type { FailSafeWarning } from '../../failsafe-policy/index.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import {
  buildTrustedListCacheEntry,
  readTrustedListCache,
  storeTrustedListCache,
  type TrustedListCache,
} from './cache.js';
import { type CertChainResult, verifyCertificateChain } from './chain.js';
import {
  clearTrustedListFailOpenWindow,
  decideTrustedListFetchFailure,
  type TrustedListFailOpenDeps,
} from './fail-open.js';
import { isTrustedListCurrent } from './freshness.js';
import { acceptedCachedEntry, validKindHint } from './input/kind-hint.js';
import { resolveNowSeconds } from './input/now-seconds.js';
import { assertNotRolledBack } from './rollback.js';
import type { SigningAnchorOptions, SigningAnchorResult } from './signing-anchor/index.js';
import { resolveSigningAnchor } from './signing-anchor/index.js';
import {
  type ExtractQtspOptions,
  extractQtspCertificates,
  extractTslPointers,
  grantedTrustAnchors,
  hasOtherTslPointer,
  type QtspServiceCertificate,
  type TslPointer,
} from './tsl.js';
import { verifyXmlDsig } from './xml/xmldsig.js';

/** Trusted List（LOTL / TSL）を URL から取得する DI seam。ネットワーク I/O を呼び出し側へ委譲する。 */
export type TrustedListFetcher = (url: string) => Promise<string>;

/** LOTL / TSL のどちらとして扱うか。既定は自動判定（`OtherTSLPointer` の有無）。 */
export type TrustedListKind = 'lotl' | 'tsl' | 'auto';

/** `loadTrustedList` の結果。 */
export interface LoadTrustedListResult extends SigningAnchorResult {
  /** XMLDSig 署名検証に成功したか。 */
  readonly signatureValid: boolean;
  /** LOTL の場合: 加盟国 TSL ポインタ。TSL の場合は空配列。 */
  readonly pointers: readonly TslPointer[];
  /** LOTL のスキーム territory 一覧（重複除去）。 */
  readonly countries: readonly string[];
  /** TSL の場合: 抽出した QTSP サービス証明書。LOTL の場合は空配列。 */
  readonly serviceCertificates: readonly QtspServiceCertificate[];
  /** FO-5 で通過した場合の警告（成立しなければ `undefined`）。 */
  readonly warnings?: readonly FailSafeWarning[];
}

/**
 * `loadTrustedList` のオプション。
 *
 * `cache` / FO-5 関連（`TrustedListFailOpenDeps`）はいずれも任意。`cache` のみ注入した場合は
 * 取得結果を記憶するだけで fail-open はしない（従来どおり取得失敗を fail-closed で伝播する）。
 * `failOpenWindow` も注入した場合に限り FO-5 が有効になる。
 */
export interface LoadTrustedListOptions
  extends TrustedListFailOpenDeps,
    SigningAnchorOptions,
    ExtractQtspOptions {
  /** Trusted List 取得関数（DI）。 */
  readonly fetcher: TrustedListFetcher;
  /** 種別（既定 `auto`）。 */
  readonly kind?: TrustedListKind;
  /** 取得結果の TTL キャッシュ（`cache.ts`）。未指定ならキャッシュせず、FO-5 も発動しない。 */
  readonly cache?: TtlCache<TrustedListCache>;
  /** 現在時刻（エポック秒）。未指定なら実時計。 */
  readonly nowSeconds?: number;
}

/** LOTL か TSL かを署名済み領域の内容から判定する（`OtherTSLPointer` を含めば LOTL とみなす）。 */
function detectKind(xml: string): 'lotl' | 'tsl' {
  return hasOtherTslPointer(xml) ? 'lotl' : 'tsl';
}

type TrustedListStructure = Omit<LoadTrustedListResult, 'warnings' | 'signatureAnchored'>;

/** 署名検証済み XML から Trusted List の構造（`warnings` / アンカリングを除く）を組み立てる。 */
function extractResult(
  kind: 'lotl' | 'tsl',
  xml: string,
  options: ExtractQtspOptions,
): TrustedListStructure {
  if (kind === 'lotl') {
    const pointers = extractTslPointers(xml);
    const countries = dedupe(
      pointers.map((p) => p.territory).filter((t): t is string => t !== undefined),
    );
    return { signatureValid: true, pointers, countries, serviceCertificates: [] };
  }
  const serviceCertificates = extractQtspCertificates(xml, options);
  return { signatureValid: true, pointers: [], countries: [], serviceCertificates };
}

/**
 * XMLDSig 署名を検証したうえで構造を抽出する。取得経路（新規取得 / stale キャッシュ）に依らず
 * 共通で使う。キャッシュ命中時も「検証済みとして扱う」経路を作らないため必ず呼び直す。
 *
 * 署名者証明書のアンカリング（`signing-anchor/index.ts`）も同じコードで拒否する。埋め込み証明書で
 * 署名を確かめただけの結果を「検証済み」として返さないためである。
 * @param kind LOTL / TSL 種別。
 * @param xml 検証対象の XML 本体。
 * @param options 呼び出し元のオプション（署名者 Trust Anchor を own 限定で読む）。
 * @param nowSeconds チェーン検証の基準時刻（エポック秒）。
 * @returns 検証結果・アンカリング有無・ポインタ・国一覧・サービス証明書。
 * @throws 署名検証失敗・署名者がアンカーへ不連結の場合（10302 LOTL / 5002 TSL）。
 */
async function verifyAndExtract(
  kind: 'lotl' | 'tsl',
  xml: string,
  options: LoadTrustedListOptions,
  nowSeconds: number,
): Promise<Omit<LoadTrustedListResult, 'warnings'>> {
  const code = kind === 'tsl' ? ErrorCodes.TSL_SIG_INVALID : ErrorCodes.XMLDSIG_VERIFICATION_FAILED;
  const dsig = await verifyXmlDsig(xml);
  // 署名が本物でも NextUpdate を過ぎた世代は受理しない（古い署名済み TSL の再生対策）。
  // キャッシュ由来の XML（FO-5）も同じ経路を通るので、期限切れキャッシュは自然に落ちる。
  if (!dsig.valid || !isTrustedListCurrent(xml, nowSeconds)) {
    throw new VericertsError(code);
  }
  const signatureAnchored = await resolveSigningAnchor(options, dsig.signingCertDer, nowSeconds);
  if (signatureAnchored === undefined) {
    throw new VericertsError(code);
  }
  return { ...extractResult(kind, xml, options), signatureAnchored };
}

/**
 * 取得失敗時、有効期限内のキャッシュがあれば FO-5 を試みる。成立しなければ `fetchFailedCode`
 * をそのまま投げる（従来どおりの fail-closed）。
 * @param options 呼び出し元のオプション（キャッシュ・FO-5 依存）。
 * @param url キャッシュキー（LOTL / TSL の取得元 URL）。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @param fetchFailedCode 取得失敗として伝播するエラーコード（LOTL: 10301 / TSL: 5001）。
 * @param kindHint 呼び出し側が指定した種別（`auto` なら未指定扱い）。キャッシュ済みエントリの
 *                 実際の種別と食い違う場合は FO-5 を成立させない。
 * @param explicitInvalidKind `options.kind` に明示指定があったがユニオン外だったか。`kindHint`
 *                 は `'auto'` へ畳まれ済みのため、これが無いと不一致ガードを迂回する。
 * @returns FO-5 が成立した場合の結果（`warnings` 付き）。
 * @throws 成立しない場合は `fetchFailedCode`（VericertsError）。キャッシュされた XML の署名が
 *         再検証で不成立の場合は署名検証失敗のコード（10302/5002）。署名検証を監査より先に行う
 *         ため、この場合の監査記録・同意は一切発生しない。
 */
async function resolveWithFailOpen(
  options: LoadTrustedListOptions,
  url: string,
  nowSeconds: number,
  fetchFailedCode: ErrorCode,
  kindHint: TrustedListKind,
  explicitInvalidKind: boolean,
): Promise<LoadTrustedListResult> {
  // キャッシュも `Object.prototype` 由来だけを弾いて読む（`nonObjectPrototypeProperty`）。
  // `loadTrustedList` の正常系（`storeTrustedListCache` 側）と読み取り規律を揃えるためのもので、
  // `options.cache` を継承値で塗り替えさせない点は own 限定の他オプションと同じ。
  const cache = nonObjectPrototypeProperty<TtlCache<TrustedListCache>>(options, 'cache');
  const cached = cache === undefined ? undefined : readTrustedListCache(cache, url, nowSeconds);
  if (cached === undefined) {
    // キャッシュ無し・期限切れのいずれも「再利用できる実データが無い」として扱う。FO-6 と同じく
    // resolveFailOpen 自体を呼ばない（監査記録もウィンドウの消費も発生させない）。
    throw new VericertsError(fetchFailedCode);
  }
  // 種別を明示している場合、キャッシュ済みエントリの実際の種別と一致しなければ対象外にする（同一 URL への過去の
  // `kind: 'auto'` 呼び出しが `lotl` 判定していた場合に `kind: 'tsl'` を明示する呼び出しが無言で受理すると Trust Anchor が
  // 空になる）。`explicitInvalidKind`（ユニオン外の明示値）も同じ扱い。エントリの `type` / `xml` は own 限定で読み、
  // 欠落・不正なエントリは汚染値で補わず対象外にする。判定は `acceptedCachedEntry`。
  const accepted = acceptedCachedEntry(cached, kindHint, explicitInvalidKind);
  if (accepted === undefined) {
    throw new VericertsError(fetchFailedCode);
  }
  // 署名検証を先に済ませる。キャッシュ命中時も「検証済みとして扱う」経路を作らないのは従来どおり。
  // 検証失敗（10302/5002）はここで伝播し、以降の監査記録・同意は発生しない。
  const result = await verifyAndExtract(accepted.type, accepted.xml, options, nowSeconds);
  const warning = await decideTrustedListFetchFailure(options, url, nowSeconds);
  if (warning === undefined) {
    throw new VericertsError(fetchFailedCode);
  }
  return { ...result, warnings: [warning] };
}

/**
 * LOTL または TSL を取得し、XMLDSig 署名を検証したうえで構造を抽出する。
 *
 * `options.cache` を注入した場合、取得・検証に成功した結果を格納する。取得に失敗した場合は
 * `options.cache` に有効期限内のエントリがあり、かつ `options.failOpenWindow` を注入している
 * ときに限り FO-5 を試みる（`resolveWithFailOpen`）。
 * @param url LOTL / TSL の XML URL。
 * @param options 取得関数・種別・キャッシュ・FO-5 依存。
 * @returns 署名検証結果・ポインタ・国一覧・サービス証明書（FO-5 成立時は `warnings` も返す）。
 * @throws 取得失敗（10301 LOTL / 5001 TSL）、署名検証失敗（10302 LOTL / 5002 TSL）。
 */
export async function loadTrustedList(
  url: string,
  options: LoadTrustedListOptions,
): Promise<LoadTrustedListResult> {
  // 種別も own 限定で読む（継承値だと `kind` 省略時の自動判定が迂回され、本物の TSL が LOTL 扱いで
  // 素通りして Trust Anchor が無言で空になる）。`rawKind`（未検証）は残し、FO-5 の
  // 種別不一致ガードへ「明示指定はあったが妥当でなかった」ことを別途伝える（`kindHint` だけでは
  // `'auto'` に畳まれた時点で未指定と区別できないため）。
  const rawKind = ownProperty<unknown>(options, 'kind');
  const kindHint = validKindHint(rawKind);
  const explicitInvalidKind = rawKind !== undefined && rawKind !== kindHint;
  const nowSeconds = resolveNowSeconds(options);

  // TSL の取得先も own 限定で読む（継承値だと取得が攻撃者の関数へ委譲される）。
  // `fetcher` 未設定は呼び出し側の設定ミスでありネットワーク障害と区別するため、try の外で
  // 無条件に投げる（設定ミスまで FO-5 の対象にすると不具合を fail-open で覆い隠してしまう）。
  const fetcher = ownProperty<(url: string) => Promise<string>>(options, 'fetcher');
  if (typeof fetcher !== 'function') {
    throw new VericertsError(ErrorCodes.TSL_FETCH_FAILED);
  }

  let xml: string;
  try {
    xml = await fetcher(url);
  } catch {
    // URL・本文は載せない。LOTL 取得は 10301、TSL 取得は 5001 に正規化する。
    const code = kindHint === 'tsl' ? ErrorCodes.TSL_FETCH_FAILED : ErrorCodes.LOTL_FETCH_FAILED;
    return resolveWithFailOpen(options, url, nowSeconds, code, kindHint, explicitInvalidKind);
  }
  const kind = kindHint === 'auto' ? detectKind(xml) : kindHint;

  const result = await verifyAndExtract(kind, xml, options, nowSeconds);

  const cache = nonObjectPrototypeProperty<TtlCache<TrustedListCache>>(options, 'cache');
  // 直前に受理した世代より古い署名済み TSL の再生を拒否する（`rollback.ts`）。
  if (cache !== undefined) {
    assertNotRolledBack(cache, url, kind, xml, nowSeconds);
  }
  if (cache !== undefined) {
    storeTrustedListCache(
      cache,
      buildTrustedListCacheEntry({
        url,
        type: kind,
        xml,
        signatureValid: true,
        fetchedAt: new Date(nowSeconds * 1000).toISOString(),
      }),
      nowSeconds,
    );
  }
  // 取得に成功したので FO-5 の計時ウィンドウを破棄する。ウィンドウ未注入・不正な形状なら
  // 何もしない（`fail-open.ts` の `clearTrustedListFailOpenWindow` を参照）。
  clearTrustedListFailOpenWindow(options, url);
  return result;
}

/** `verifyQualifiedCertificate` の入力。 */
export interface VerifyQualifiedCertificateOptions {
  /** 検証対象リーフ証明書の DER。 */
  readonly certDer: Uint8Array;
  /** TSL から抽出した granted なサービス証明書（Trust Anchor 候補）。 */
  readonly trustAnchors: readonly QtspServiceCertificate[];
  /** チェーンを辿るための中間 CA 証明書 DER（任意）。 */
  readonly intermediatesDer?: readonly Uint8Array[];
  /** 検証基準時刻（Unix 秒・任意）。 */
  readonly now?: number;
}

/**
 * リーフ証明書が TSL の granted な QTSP Trust Anchor に連結するか検証する。
 *
 * @param options 対象証明書・Trust Anchor・中間証明書・基準時刻。
 * @returns チェーン検証結果（`trusted` / 到達 Anchor）。
 * @throws Trust Anchor が空、またはチェーン不成立の場合（10303 QUALIFIED_CERT_INVALID）。
 */
export async function verifyQualifiedCertificate(
  options: VerifyQualifiedCertificateOptions,
): Promise<CertChainResult> {
  // トラストアンカー集合も own 限定で読む。同関数の `now` / `intermediatesDer` は
  // own 化済みで、ここだけ漏れると汚染値が Trust Anchor になり攻撃者 CA が信頼の起点になる。
  const trustAnchorsDer = grantedTrustAnchors(
    ownProperty<VerifyQualifiedCertificateOptions['trustAnchors']>(
      options,
      'trustAnchors',
    ) as VerifyQualifiedCertificateOptions['trustAnchors'],
  );
  if (trustAnchorsDer.length === 0) {
    throw new VericertsError(ErrorCodes.QUALIFIED_CERT_INVALID);
  }
  // 任意プロパティは自身のプロパティに限って読む。`now: options.now` と無条件に
  // 詰め直すと、継承値が own プロパティに化けて `verifyCertificateChain` 側の own 限定読み取りが
  // 常に汚染値を受け取る（期限切れ QTSP 証明書が trusted になる）。`rp-access/verify.ts` は
  // own 由来の値を渡しており、こちらだけが漏れていた。
  const now = ownProperty<number>(options, 'now');
  const intermediatesDer = ownProperty<readonly Uint8Array[]>(options, 'intermediatesDer');
  const result = await verifyCertificateChain(options.certDer, intermediatesDer ?? [], {
    trustAnchorsDer,
    ...(now !== undefined ? { now } : {}),
  });
  if (!result.trusted) {
    throw new VericertsError(ErrorCodes.QUALIFIED_CERT_INVALID);
  }
  return result;
}

/** 文字列配列の重複を除去する（順序保持）。 */
function dedupe(values: readonly string[]): string[] {
  return [...new Set(values)];
}
