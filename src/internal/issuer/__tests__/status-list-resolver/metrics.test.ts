/**
 * `createStatusListResolver` のメトリクス配線の回帰テスト。
 *
 * Status List のメトリクスとキャッシュ状態を示す `cache` ラベルを検証する。
 *
 * 検証内容:
 * - `vericerts_status_list_fetch_duration_seconds` が キャッシュ状態の 3 値（`cold` / `warm` / `hot`）を
 *   実測で出し分ける。negative cache 命中もネットワーク I/O が無いため `hot`。
 * - 取得失敗もレイテンシの実測値として記録する（`cold` へ 1 件）。
 * - `vericerts_status_list_check_total` は**失効確認ができたか**を数える。失効済み VC でも確認は
 *   成立するので `success`、送出と FO-1（確認を諦めた通過）が `failure`。
 * - ラベルは ラベルの予算（`metrics-budget.ts`）を通しても拒否されない語彙である。
 * - 計器を注入しない従来どおりの構築では何も記録せず、既存の挙動も変わらない。
 */

import { describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { createLogger } from '../../../observability/logger.js';
import {
  createInMemoryMetrics,
  type HistogramSample,
  type Labels,
  MetricNames,
  type MetricSample,
} from '../../../observability/metrics.js';
import { createMetrics } from '../../../observability/metrics-budget.js';
import { createStatusListCache } from '../../status-list-cache.js';
import { createStatusListResolver } from '../../status-list-resolver.js';
import { StatusListManager } from '../../token-status-list.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const PUB = getP256PublicKey(ISSUER_KEY, false);
const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const ISSUER_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: b64u(PUB.subarray(1, 33)),
  y: b64u(PUB.subarray(33, 65)),
};

const URI = 'https://issuer.example/status/1';
const NOW = 1_700_000_000;
const MANAGER = new StatusListManager({
  uri: URI,
  issuer: 'did:web:issuer.example',
  size: 100,
  bits: 1,
});
/** 有効なままのエントリと、失効させたエントリ（判定の成否と VC の有効性を切り分けるため）。 */
const VALID_REF = MANAGER.reference(MANAGER.allocate());
const REVOKED_INDEX = MANAGER.allocate();
MANAGER.revoke(REVOKED_INDEX);
const REVOKED_REF = MANAGER.reference(REVOKED_INDEX);
const TOKEN = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW });

/** 名前とラベルが完全一致する系列を 1 本取り出す。 */
function findSample<T extends { name: string; labels: Labels }>(
  samples: readonly T[],
  name: string,
  labels: Labels,
): T | undefined {
  return samples.find((sample) => sample.name === name && Bun.deepEquals(sample.labels, labels));
}

/** 取得レイテンシの系列（`cache` ラベル 1 本）の件数を読む。 */
function fetchCount(snapshot: () => { histograms: readonly HistogramSample[] }, cache: string) {
  return findSample(snapshot().histograms, MetricNames.STATUS_LIST_FETCH_DURATION_SECONDS, {
    cache,
  })?.count;
}

/** 判定回数の系列（`result` ラベル 1 本）の値を読む。 */
function checkCount(snapshot: () => { counters: readonly MetricSample[] }, result: string) {
  return findSample(snapshot().counters, MetricNames.STATUS_LIST_CHECK_TOTAL, { result })?.value;
}

/** 計器を注入した解決器と、時計・取得回数・蓄積値の読み出し口を組み立てる。 */
function setup(opts: { fail?: boolean; budgeted?: boolean } = {}) {
  const sink = createInMemoryMetrics();
  // 実運用と同じく ラベルの予算を通した計器でも配線が成立することを確かめる。
  const metrics =
    opts.budgeted === true ? createMetrics(sink.metrics, createLogger(undefined)) : sink.metrics;
  let now = NOW;
  let calls = 0;
  const failing = opts.fail === true;
  const resolver = createStatusListResolver({
    fetchToken: async () => {
      calls += 1;
      if (failing) {
        throw new Error('network unreachable');
      }
      return TOKEN;
    },
    issuerPublicKey: ISSUER_JWK,
    purpose: 'revocation',
    statusCache: createStatusListCache(() => now),
    nowSeconds: () => now,
    metrics,
  });
  return {
    resolver,
    snapshot: sink.snapshot,
    calls: () => calls,
    at: (offsetSeconds: number) => {
      now = NOW + offsetSeconds;
    },
  };
}

describe('Status List メトリクス配線', () => {
  it('初回取得は cold、TTL 内は hot、TTL 切れの再取得は warm として記録する', async () => {
    const s = setup();

    await s.resolver.resolve(VALID_REF);
    expect(fetchCount(s.snapshot, 'cold')).toBe(1);

    // TTL 内。ネットワークに出ないので hot。
    s.at(59);
    await s.resolver.resolve(VALID_REF);
    expect(s.calls()).toBe(1);
    expect(fetchCount(s.snapshot, 'hot')).toBe(1);

    // TTL 切れ。再取得するので warm。
    s.at(61);
    await s.resolver.resolve(VALID_REF);
    expect(s.calls()).toBe(2);
    expect(fetchCount(s.snapshot, 'warm')).toBe(1);

    // 3 経路が別系列に分かれており、cold が後続で増えていない。
    expect(fetchCount(s.snapshot, 'cold')).toBe(1);
    expect(checkCount(s.snapshot, 'success')).toBe(3);
    expect(checkCount(s.snapshot, 'failure')).toBeUndefined();
  });

  it('失効済み VC でも失効確認は成立しているので success に数える', async () => {
    const s = setup();

    const result = await s.resolver.resolve(REVOKED_REF);

    expect(result.valid).toBe(false);
    expect(checkCount(s.snapshot, 'success')).toBe(1);
    expect(checkCount(s.snapshot, 'failure')).toBeUndefined();
  });

  it('取得失敗は failure に数え、レイテンシは cold の実測として残す', async () => {
    const s = setup({ fail: true });

    await expect(s.resolver.resolve(VALID_REF)).rejects.toThrow('network unreachable');

    expect(checkCount(s.snapshot, 'failure')).toBe(1);
    expect(checkCount(s.snapshot, 'success')).toBeUndefined();
    expect(fetchCount(s.snapshot, 'cold')).toBe(1);
  });

  it('negative cache 命中はネットワークに出ないので hot として記録する', async () => {
    const s = setup({ fail: true });

    await expect(s.resolver.resolve(VALID_REF)).rejects.toThrow('network unreachable');
    // 記憶済みの失敗が生きている間（30 秒固定）の 2 回目。取得関数は呼ばれない。
    s.at(10);
    await expect(s.resolver.resolve(VALID_REF)).rejects.toThrow('network unreachable');

    expect(s.calls()).toBe(1);
    expect(fetchCount(s.snapshot, 'hot')).toBe(1);
    expect(fetchCount(s.snapshot, 'cold')).toBe(1);
    expect(checkCount(s.snapshot, 'failure')).toBe(2);
  });

  it('FO-1 で通過した場合は失効確認ができていないので failure に数える', async () => {
    const sink = createInMemoryMetrics();
    const resolver = createStatusListResolver({
      fetchToken: async () => {
        throw new Error('network unreachable');
      },
      issuerPublicKey: ISSUER_JWK,
      purpose: 'revocation',
      nowSeconds: () => NOW,
      metrics: sink.metrics,
      // 同意を得て Fail-open する構成（FO-1）。
      onPolicyEvent: () => {},
      requestConsent: () => true,
    });

    const result = await resolver.resolve(VALID_REF);

    // 通過はするが、読み取ったビットではなく 既定のポリシーで valid になっている。
    expect(result.valid).toBe(true);
    expect(result.warnings?.[0]?.policyEvent).toBe('FO-1');
    expect(checkCount(sink.snapshot, 'failure')).toBe(1);
    expect(checkCount(sink.snapshot, 'success')).toBeUndefined();
  });

  it('ラベルの予算を通した計器でもラベルが拒否されず記録される', async () => {
    const s = setup({ budgeted: true });

    await s.resolver.resolve(VALID_REF);

    expect(fetchCount(s.snapshot, 'cold')).toBe(1);
    expect(checkCount(s.snapshot, 'success')).toBe(1);
  });

  it('計器を注入しない従来どおりの構築では何も記録せず挙動も変わらない', async () => {
    const sink = createInMemoryMetrics();
    const resolver = createStatusListResolver({
      fetchToken: async () => TOKEN,
      issuerPublicKey: ISSUER_JWK,
      purpose: 'revocation',
      nowSeconds: () => NOW,
    });

    expect(await resolver.resolve(VALID_REF)).toEqual({
      valid: true,
      purpose: 'revocation',
      value: 0,
    });
    expect(sink.snapshot().histograms).toEqual([]);
    expect(sink.snapshot().counters).toEqual([]);
  });
});
