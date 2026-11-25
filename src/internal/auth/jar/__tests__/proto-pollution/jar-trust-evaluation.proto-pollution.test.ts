/**
 * `jar-trust-evaluation.ts`（OIDF / ARF 層）の `Object.prototype` 汚染耐性テスト。
 *
 * `arfSet.entries` / `entry.spki` / `entry.id`・`federationTrustAnchor.trustAnchorEntityId` /
 * `federationTrustAnchor.deps` をプロトタイプ鎖で読むと、
 *
 * - `entries` を持たない `ArfTrustAnchorSet` でも汚染値が「登録エントリ集合」に化け、
 * - `spki` / `id` を持たないエントリが汚染値で SPKI・origin の双方一致に化け、
 * - `trustAnchorEntityId` を持たない `federationTrustAnchor` でも汚染値が OIDF の Trust Anchor
 *   そのものに化け（本テストの最重要ケース）、
 * - `deps` を持たない `federationTrustAnchor` でも汚染値の `fetchFn` へ Entity Configuration
 *   取得が委譲される、
 *
 * という形で ARF Catalogue に登録されていない／OIDF Trust Anchor として設定していないエンティティ
 * が信頼の起点として通ってしまう。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, type VericertsError } from '../../../../errors.js';
import type { ArfTrustAnchorSet } from '../../../../trust/arf/index.js';
import { parseCertificate } from '../../../../trust/etsi-tsl/index.js';
import { nowFn } from '../../../../trust/federation/__tests__/federation-fixtures.js';
import { verifyJarSignature } from '../../jar-signature.js';
import type { JarFederationTrustAnchorOption } from '../../jar-trust-evaluation.js';
import { CLIENT_ID, makeJarSigner, signJar } from '../jar-fixtures.js';

const VERIFIER = makeJarSigner();

/** 汚染を戻してからアサーションするため、投げられたエラーを捕捉して返す。 */
async function captureError(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
    return undefined;
  } catch (error) {
    return error;
  }
}

/**
 * 捕捉したエラーが `jarFailure('rp_cert_untrusted')`（8030）へ正規化されていることを確かめる
 * （時間があれば対応：`toBeDefined()` だけでは「型は合っているが reason が別物のエラー」や
 * 「正規化されずに漏れた生の例外」も通ってしまい、本来検出したい欠陥を見落とし得る）。
 */
function expectNormalizedRpCertUntrusted(error: unknown): void {
  expect(error).toBeInstanceOf(Error);
  const vericertsError = error as VericertsError;
  expect(vericertsError.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  expect(vericertsError.context).toMatchObject({ reason: 'rp_cert_untrusted' });
}

describe('ARF Trust Anchor Catalogue の汚染耐性', () => {
  it('entries を持たない ArfTrustAnchorSet に汚染値の登録一覧が生えない', async () => {
    const spki = parseCertificate(VERIFIER.rp.der).spki;
    const evilEntries = [{ id: CLIENT_ID, role: 'issuer', spki }];
    const arfSetWithoutEntries = { signatureValid: true } as unknown as ArfTrustAnchorSet;
    const error = await withPollutedPrototypeAsync({ entries: evilEntries }, () =>
      captureError(() =>
        verifyJarSignature(signJar(VERIFIER), {
          trustAnchors: [],
          arfTrustAnchor: arfSetWithoutEntries,
        }),
      ),
    );
    expectNormalizedRpCertUntrusted(error);
  });

  it('spki / id を持たないエントリが汚染値で SPKI・origin 一致に化けない', async () => {
    const spki = parseCertificate(VERIFIER.rp.der).spki;
    const arfSet = {
      signatureValid: true,
      entries: [{ role: 'issuer' }],
    } as unknown as ArfTrustAnchorSet;
    const error = await withPollutedPrototypeAsync({ spki, id: CLIENT_ID }, () =>
      captureError(() =>
        verifyJarSignature(signJar(VERIFIER), { trustAnchors: [], arfTrustAnchor: arfSet }),
      ),
    );
    expectNormalizedRpCertUntrusted(error);
  });
});

describe('OpenID Federation Trust Anchor オプションの汚染耐性（修正4・最重要）', () => {
  it('trustAnchorEntityId を持たない federationTrustAnchor が汚染値の Entity Identifier を Trust Anchor として使わない', async () => {
    let fetchCalled = false;
    const countingFetch = (async (
      input: string | URL | Request,
      init?: RequestInit,
    ): Promise<Response> => {
      fetchCalled = true;
      return fetch(input, init);
    }) as typeof fetch;
    // `trustAnchorEntityId` を own で持たない（型の穴は意図的。汚染で埋まらないことを検証する）。
    const federationOptionWithoutEntityId = {
      deps: { fetchFn: countingFetch, now: nowFn },
    } as unknown as JarFederationTrustAnchorOption;
    // 汚染値はたまたま正しい CLIENT_ID（もし継承されれば Trust Chain 構築が試みられてしまう）。
    const error = await withPollutedPrototypeAsync({ trustAnchorEntityId: CLIENT_ID }, () =>
      captureError(() =>
        verifyJarSignature(signJar(VERIFIER), {
          trustAnchors: [],
          expectedClientId: CLIENT_ID,
          federationTrustAnchor: federationOptionWithoutEntityId,
        }),
      ),
    );
    // own 限定で読めば `trustAnchorEntityId` は未設定と判定され、Trust Chain 構築（＝fetch）へ
    // 進まない。鎖読みのままなら継承値が正しい CLIENT_ID を掴み、fetch が呼ばれてしまう。
    expect(fetchCalled).toBe(false);
    expect(error).toBeDefined();
  });

  it('deps を持たない federationTrustAnchor が汚染値の fetchFn へ委譲しない', async () => {
    let delegated = false;
    const attackerFetch = (async (
      _input: string | URL | Request,
      _init?: RequestInit,
    ): Promise<Response> => {
      delegated = true;
      return new Response('{}', { status: 200 });
    }) as typeof fetch;
    // `deps` 省略時のランタイム既定はグローバル `fetch`。実ネットワークへ出る／タイムアウトで
    // テストが遅くならないよう、グローバル側を即失敗するスタブへ差し替える（本テストの関心は
    // 「汚染された `attackerFetch` が呼ばれないこと」であり、既定 fetch の結果ではない）。
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (
      _input: string | URL | Request,
      _init?: RequestInit,
    ): Promise<Response> => {
      throw new Error('network disabled in test');
    }) as typeof fetch;
    // `deps` を own で持たない。
    const federationOptionWithoutDeps = {
      trustAnchorEntityId: CLIENT_ID,
    } as unknown as JarFederationTrustAnchorOption;
    try {
      const error = await withPollutedPrototypeAsync(
        { deps: { fetchFn: attackerFetch, now: nowFn } },
        () =>
          captureError(() =>
            verifyJarSignature(signJar(VERIFIER), {
              trustAnchors: [],
              expectedClientId: CLIENT_ID,
              federationTrustAnchor: federationOptionWithoutDeps,
            }),
          ),
      );
      expect(delegated).toBe(false);
      expect(error).toBeDefined();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
