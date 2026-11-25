/**
 * FO-5（ETSI TSL / LOTL 取得失敗時に有効期限内のキャッシュで警告通過）テストの共有ヘルパ。
 *
 * 可変時計・途中でオフラインに切り替えられる fetcher・キャッシュ・監査シンク・同意コールバックを
 * 1 つにまとめる。FO-5 は「一度取得に成功してキャッシュを持っている」状態が前提のため、どのテスト
 * も「成功 → 時計を進める → オフライン」という同じ筋書きを踏む（`federation/__tests__/fail-open/`
 * と同じ方針）。
 *
 * テストケースは含まない（Linterly の 1 ファイル 300 行上限に収めるための分離）。
 */

import { expect } from 'bun:test';
import { base64 } from '@scure/base';
import type { TtlCache } from '../../../../cache/index.js';
import { type ErrorCode, VericertsError } from '../../../../errors.js';
import type {
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafeWarning,
} from '../../../../failsafe-policy/index.js';
import { createTrustedListCache, type TrustedListCache } from '../../cache.js';
import type { LoadTrustedListOptions } from '../../etsi-tsl.js';
import { makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from '../xml/xml-fixtures.js';

/** FO-5 の監査イベント名。 */
export const FO5_WARNING: FailSafeWarning = {
  policyEvent: 'FO-5',
  auditEvent: 'tsl_fetch_failed_cache_ok',
};

const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';

export const TSL_URL = 'https://tsl.example/DE.xml';
export const NOW_SECONDS = 1_700_000_000;

/**
 * キャッシュの TTL 上限（`NextUpdate` までの秒数）。TSL 自身がこの期間だけ「まだ最新」と
 * 宣言している値であり、この範囲内に収まる前進量なら FO-5 の対象（有効期限内）のままになる。
 */
export const CACHE_TTL_SECONDS = 3600;

/** `CACHE_TTL_SECONDS` を確実に超える前進量（NextUpdate 経過 = FO-5 対象外になる）。 */
export const EXPIRED_AFTER_SECONDS = CACHE_TTL_SECONDS + 1;

/** granted な QTSP CA を 1 件持つ TSL 本体を、`NextUpdate` 付きで署名して返す。 */
function signedTslXml(nextUpdateSeconds: number): string {
  const ca = makeCertificate({ cn: 'DE QTSP CA', kind: 'rsa' });
  const signer = makeCertificate({ cn: 'DE TSL Signer', kind: 'ec' });
  const nextUpdateIso = new Date(nextUpdateSeconds * 1000).toISOString();
  const bodyInner =
    `<SchemeInformation><NextUpdate><dateTime>${nextUpdateIso}</dateTime></NextUpdate></SchemeInformation>` +
    `<TSPService><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${GRANTED}</ServiceStatus>` +
    `<X509Certificate>${base64.encode(ca.der)}</X509Certificate></TSPService>`;
  return signEnvelopedXml({
    bodyOpen: '<TrustServiceStatusList>',
    bodyInner,
    bodyClose: '</TrustServiceStatusList>',
    privateKey: signer.privateKey,
    certDer: signer.der,
    kind: 'ec',
  });
}

/** FO-5 テスト用の可変環境。 */
export interface FailOpenHarness {
  /** 記録された監査レコード。 */
  readonly records: FailSafeAuditRecord[];
  /** 同意コールバックに渡された判定。 */
  readonly consents: FailSafeDecision[];
  /** `loadTrustedList` へ渡す基本オプション（キャッシュ・取得関数）。テストごとに FO-5 系の
   * 依存を足して使う。`nowSeconds` は各呼び出し時点で `h.now()` を明示的に渡すこと。 */
  readonly base: Omit<LoadTrustedListOptions, 'nowSeconds'>;
  /** キャッシュ本体（`readTrustedListCache` 等で直接検査したい場合用）。 */
  readonly cache: TtlCache<TrustedListCache>;
  /** 現在時刻（エポック秒）を返す。 */
  now(): number;
  /** 時計を進める（秒）。 */
  advance(seconds: number): void;
  /** 以降の取得を失敗させる。 */
  goOffline(): void;
  /** 監査ログの記録先（`onPolicyEvent`）。 */
  onPolicyEvent(record: FailSafeAuditRecord): void;
  /** 常に同意するコールバック。 */
  requestConsent(decision: FailSafeDecision): boolean;
}

/**
 * FO-5 テスト用の環境を組み立てる。取得は既定でオンライン（`signedTslXml` を返す）。
 *
 * @param nextUpdateSeconds `NextUpdate`（エポック秒）。既定は `NOW_SECONDS + CACHE_TTL_SECONDS`。
 */
export function failOpenHarness(
  nextUpdateSeconds: number = NOW_SECONDS + CACHE_TTL_SECONDS,
): FailOpenHarness {
  let now = NOW_SECONDS;
  let offline = false;
  const records: FailSafeAuditRecord[] = [];
  const consents: FailSafeDecision[] = [];
  const cache = createTrustedListCache(() => now);
  const xml = signedTslXml(nextUpdateSeconds);

  return {
    records,
    consents,
    cache,
    base: {
      kind: 'tsl',
      cache,
      fetcher: async (): Promise<string> => {
        if (offline) {
          throw new Error('network');
        }
        return xml;
      },
    },
    now: (): number => now,
    advance: (seconds: number): void => {
      now += seconds;
    },
    goOffline: (): void => {
      offline = true;
    },
    onPolicyEvent: (record: FailSafeAuditRecord): void => {
      records.push(record);
    },
    requestConsent: (decision: FailSafeDecision): boolean => {
      consents.push(decision);
      return true;
    },
  };
}

/** 「一度取得に成功 → キャッシュ格納 → オフライン」まで進めた環境を返す。 */
export async function primedAndOffline(
  loadTrustedList: (url: string, options: LoadTrustedListOptions) => Promise<unknown>,
  nextUpdateSeconds?: number,
): Promise<FailOpenHarness> {
  const h = failOpenHarness(nextUpdateSeconds);
  await loadTrustedList(TSL_URL, { ...h.base, nowSeconds: h.now() });
  h.goOffline();
  return h;
}

/** reject が指定コードの VericertsError であることを検証する。 */
export async function expectRejectCode(
  promise: Promise<unknown>,
  code: ErrorCode,
): Promise<VericertsError> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  const failure = caught as VericertsError;
  expect(failure.code).toBe(code);
  return failure;
}
