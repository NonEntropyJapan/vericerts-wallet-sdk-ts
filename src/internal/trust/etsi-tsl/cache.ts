/**
 * ETSI Trusted List（LOTL/TSL）の永続キャッシュ型とキャッシュ層（trust/etsi-tsl）。
 *
 * `tsl.ts` / `etsi-tsl.ts` は LOTL / TSL の XML をそのつどパースする純粋関数群であり、
 * `url` / `xml` / `nextUpdate` / `fetchedAt` を持つキャッシュエンティティ自体は提供しない
 * （キャッシュ管理は呼び出し側の責務）。本モジュールはキャッシュエンティティの型
 * `TrustedListCache` と、その永続キャッシュ層を提供する。
 * `QualifiedTspEntry` は TSL から構造を抽出した結果であり、
 * `tsl.ts` の `extractQualifiedTspEntries` が定義・生成する（責務分離は既存の
 * `TslPointer` / `QtspServiceCertificate` と同じ配置方針）。
 *
 * キャッシュ本体は対象非依存の `internal/cache/ttl-cache.ts` を用いる（did:web /
 * Federation Entity Statement / Token Status List と同方針）。TTL は TSL 自身の
 * `NextUpdate`（XMLDSig 検証済み XML から `tsl.ts` の `extractNextUpdate` で抽出。
 * 署名検証済みのため呼び出し元が改ざんできない）をそのまま採用する。ETSI TSL は
 * `NextUpdate` で自身の更新周期を宣言しており、did:web / Federation のような鍵無効化
 * 伝播 SLA に基づく SDK 側の独自上限は存在しない。`TRUSTED_LIST_CACHE_MAX_TTL_SECONDS`
 * は極端に遠い将来の `NextUpdate` からキャッシュ寿命を守るための工学的な安全弁であり、
 * trust/audit 判定ロジックの一部ではない。
 *
 * 実際の永続化（IndexedDB 等）・ネットワーク取得は本モジュールの責務ではない
 * （`eudi/batch` の `BatchPoolItem` と同じく、facade 側が担う）。本モジュールが提供するのは
 * インメモリの TTL キャッシュと、ER のフィールドに対応するエントリの組み立てである。
 *
 * セキュリティ上の注意:
 * - キャッシュキー（URL）・XML 本体はログ・例外メッセージ・`context` に含めない。
 */

import {
  createTtlCache,
  STRING_CACHE_MAX_TOTAL_LENGTH,
  systemNowSeconds,
  type TtlCache,
} from '../../cache/index.js';
import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { extractNextUpdate } from './tsl.js';

/**
 * LOTL / TSL の取得・検証結果の永続キャッシュ（`TrustedListCache`）。
 */
export interface TrustedListCache {
  /** LOTL / TSL の取得元 URL（キャッシュキー）。 */
  readonly url: string;
  /** LOTL か TSL か。 */
  readonly type: 'lotl' | 'tsl';
  /** 加盟国コード（TSL のみ。LOTL は省略）。 */
  readonly country?: string;
  /** 取得した XML 本体。 */
  readonly xml: string;
  /** XMLDSig 検証結果。 */
  readonly signatureValid: boolean;
  /** 次回更新予定日時（ISO 8601 相当。TSL 自身の `NextUpdate` 由来）。 */
  readonly nextUpdate: string;
  /** 取得日時（ISO 8601）。 */
  readonly fetchedAt: string;
}

/**
 * キャッシュ保存時の TTL 上限（秒、30 日）。
 *
 * 工学的な安全弁であり、trust/audit 判定の一部ではない（モジュール先頭のコメント参照）。
 * 通常は各 TSL の `nextUpdate` までの残り秒数がこの値を大きく下回る（EU 加盟国 TSL の更新
 * 周期は数週間〜数か月単位）ため、この上限が実際に効くのは `nextUpdate` が異常に遠い将来を
 * 指す場合のみである。
 */
export const TRUSTED_LIST_CACHE_MAX_TTL_SECONDS = 30 * 24 * 60 * 60;

/**
 * `TrustedListCache` 用の TTL キャッシュを生成する。
 *
 * TTL 上限は `TRUSTED_LIST_CACHE_MAX_TTL_SECONDS`（30 日）で固定する。
 *
 * @param nowSeconds 時計（エポック秒）。未指定なら実時計。
 * @param maxEntries 保持する最大エントリ数（省略時はキャッシュ層の既定）。
 * @returns `TrustedListCache` 用 TTL キャッシュ（キーは `url`）。
 */
export function createTrustedListCache(
  nowSeconds: () => number = systemNowSeconds,
  maxEntries?: number,
): TtlCache<TrustedListCache> {
  const maxTtlSeconds = TRUSTED_LIST_CACHE_MAX_TTL_SECONDS;
  return createTtlCache<TrustedListCache>(
    maxEntries === undefined
      ? { maxTtlSeconds, nowSeconds, maxTotalWeight: STRING_CACHE_MAX_TOTAL_LENGTH }
      : { maxTtlSeconds, nowSeconds, maxEntries, maxTotalWeight: STRING_CACHE_MAX_TOTAL_LENGTH },
  );
}

/** ISO 8601 日時（オフセット必須）をエポック秒に変換する。パース不能なら `undefined`。 */
function parseIsoSeconds(iso: string): number | undefined {
  const ms = parseIsoDateTimeMs(iso);
  return Number.isNaN(ms) ? undefined : Math.floor(ms / 1000);
}

/**
 * `cache` が有効な形状（`get` / `set` を関数として持つ）かを検証する。
 *
 * `options.cache`（`etsi-tsl.ts`）は呼び出し側の自由な注入であり、`createTrustedListCache` の
 * 戻り値以外の不正な形状（`{}` 等）が渡され得る。検証せずに `cache.get` / `cache.set` を呼ぶと、
 * 成功パス（`storeTrustedListCache`）・失敗パス（`readTrustedListCache`）の双方が生の `TypeError`
 * でクラッシュしてしまう（`fail-open.ts` の `validFailOpenWindow` と同じ規律）。
 *
 * `get` / `set` はプロトタイプ鎖ではなく `nonObjectPrototypeProperty` で読む（`Object.prototype`
 * 由来だけを弾く）。素の `cache.get` / `cache.set`（プロトタイプ鎖読み）のままだと、
 * `Object.prototype.get` / `Object.prototype.set` が汚染された環境で `cache: {}` のような不正な
 * 形状がこのガードを素通りし、攻撃者の関数がキャッシュ本体として呼ばれてしまう（`createTtlCache` はオブジェクトリテラルで own メソッドを返すため、正当なキャッシュ
 * は `nonObjectPrototypeProperty` に切り替えても影響を受けない）。
 *
 * @param cache 検証対象。
 * @returns `get` / `set` を関数として持てば `true`。
 */
function isValidTrustedListCache(cache: unknown): cache is TtlCache<TrustedListCache> {
  if (cache === null || typeof cache !== 'object') {
    return false;
  }
  return (
    typeof nonObjectPrototypeProperty<unknown>(cache, 'get') === 'function' &&
    typeof nonObjectPrototypeProperty<unknown>(cache, 'set') === 'function'
  );
}

/** `buildTrustedListCacheEntry` の入力。 */
export interface BuildTrustedListCacheEntryInput {
  /** LOTL / TSL の取得元 URL。 */
  readonly url: string;
  /** LOTL か TSL か。 */
  readonly type: 'lotl' | 'tsl';
  /** 加盟国コード（TSL のみ）。 */
  readonly country?: string;
  /** 取得した XML 本体（XMLDSig 検証は呼び出し側が完了させていること）。 */
  readonly xml: string;
  /** XMLDSig 検証結果。 */
  readonly signatureValid: boolean;
  /** 取得日時（ISO 8601）。 */
  readonly fetchedAt: string;
}

/**
 * `loadTrustedList` 等の結果から `TrustedListCache` エントリを組み立てる。
 *
 * `nextUpdate` は `xml` から `extractNextUpdate`（`tsl.ts`）で抽出する。抽出できない
 * （構造不備）場合は `fetchedAt` を採用する。`storeTrustedListCache` の TTL 計算は
 * `nextUpdate - now` を用いるため、この場合 TTL は自然に 0（＝格納しない・毎回再取得）に
 * なる。判定不能を「長期キャッシュしてよい」側に倒さない fail-closed の挙動である。
 *
 * @param input 取得元 URL・種別・加盟国コード・XML 本体・署名検証結果・取得日時。
 * @returns 組み立てた `TrustedListCache` エントリ。
 */
export function buildTrustedListCacheEntry(
  input: BuildTrustedListCacheEntryInput,
): TrustedListCache {
  const nextUpdate = extractNextUpdate(input.xml) ?? input.fetchedAt;
  return { ...input, nextUpdate };
}

/**
 * `TrustedListCache` エントリを TTL キャッシュへ格納する。
 *
 * TTL は `nextUpdate` までの残り秒数を `TRUSTED_LIST_CACHE_MAX_TTL_SECONDS` で頭打ちにした値。
 * `nextUpdate` が現在時刻以前、またはパース不能な場合は TTL 0（格納しない）として扱い、
 * 次回参照時に必ず未命中とする（fail-closed）。
 *
 * `cache` が不正な形状（`set` を関数として持たない）の場合は何もしない（fail-closed。
 * `isValidTrustedListCache` 未検証のまま `cache.set` を呼ぶと生の `TypeError`
 * で成功パスがクラッシュしていた）。
 *
 * @param cache 格納先キャッシュ（`createTrustedListCache` で生成）。
 * @param entry 格納する `TrustedListCache` エントリ。
 * @param nowSeconds 現在時刻（エポック秒）。未指定なら実時計。
 */
export function storeTrustedListCache(
  cache: TtlCache<TrustedListCache>,
  entry: TrustedListCache,
  nowSeconds: number = systemNowSeconds(),
): void {
  if (!isValidTrustedListCache(cache)) {
    return;
  }
  // 公開 API の `entry` は own 限定で読む。`url` / `xml` / `nextUpdate` を省略した手組みエントリが
  // `Object.prototype` の汚染値でキー・TTL・重みを決めない。文字列でなければ格納しない（fail-closed）。
  const url = ownProperty<unknown>(entry, 'url');
  const xml = ownProperty<unknown>(entry, 'xml');
  const type = ownProperty<unknown>(entry, 'type');
  if (typeof url !== 'string' || typeof xml !== 'string' || (type !== 'tsl' && type !== 'lotl')) {
    return;
  }
  const nextUpdateSeconds = parseIsoSeconds(ownProperty<string>(entry, 'nextUpdate') as string);
  const ttlSeconds =
    nextUpdateSeconds === undefined ? 0 : Math.max(0, nextUpdateSeconds - nowSeconds);
  // XML 本文長を重みに計上し、総保持量を抑える。
  cache.set(url, entry, ttlSeconds, nowSeconds, xml.length);
}

/**
 * URL に対応する `TrustedListCache` エントリを取得する。
 *
 * `cache` が不正な形状（`get` を関数として持たない）の場合は未格納と同じ `undefined` を返す
 * （fail-closed。呼び出し側の `etsi-tsl.ts` はこれを「再利用できる実データが無い」として扱い、
 * `TSL_FETCH_FAILED` / `LOTL_FETCH_FAILED` に正規化する）。
 *
 * @param cache 参照元キャッシュ（`createTrustedListCache` で生成）。
 * @param url LOTL / TSL の取得元 URL（キャッシュキー）。
 * @param nowSeconds 現在時刻（エポック秒）。未指定なら実時計。
 * @returns TTL 内のエントリ。未格納・TTL 切れ・不正な形状の `cache` なら `undefined`。
 */
export function readTrustedListCache(
  cache: TtlCache<TrustedListCache>,
  url: string,
  nowSeconds: number = systemNowSeconds(),
): TrustedListCache | undefined {
  if (!isValidTrustedListCache(cache)) {
    return undefined;
  }
  const entry = cache.get(url, nowSeconds);
  return entry !== undefined && !entry.expired ? entry.value : undefined;
}

/**
 * 世代ロールバック検査（`rollback.ts`）の基準にする「直近に受理した世代」を、**TTL 切れでも**返す。
 *
 * `readTrustedListCache` は TTL 切れを `undefined` にするが、TTL は `TRUSTED_LIST_CACHE_MAX_TTL_SECONDS`（30 日）
 * で頭打ちになる一方、実在の TSL の `NextUpdate` は数か月先である。TTL 切れで比較対象を失うと、`NextUpdate`
 * 内の旧世代（CA が granted だった署名済み TSL）が 31 日目以降に再び受理される。`TtlCache` は
 * 失効エントリも（`expired: true` として）容量上限で追い出されるまで保持するため、世代の高水位としては
 * 失効済みでも読む。これは**世代の比較専用**であり、FO-5 の再利用や Trust Anchor の供給には使わない
 * （それらは TTL 内だけを返す `readTrustedListCache` を使う）。
 *
 * @param cache 参照元キャッシュ（`createTrustedListCache` で生成）。
 * @param url LOTL / TSL の取得元 URL（キャッシュキー）。
 * @param nowSeconds 現在時刻（エポック秒）。未指定なら実時計。
 * @returns 直近に受理したエントリ（失効済み含む）。未格納・不正な形状の `cache` なら `undefined`。
 */
export function readLastAcceptedTrustedList(
  cache: TtlCache<TrustedListCache>,
  url: string,
  nowSeconds: number = systemNowSeconds(),
): TrustedListCache | undefined {
  if (!isValidTrustedListCache(cache)) {
    return undefined;
  }
  return cache.get(url, nowSeconds)?.value;
}
