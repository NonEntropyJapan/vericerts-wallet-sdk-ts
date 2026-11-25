/**
 * `verifyJarSignature` の時刻まわりの回帰テスト。
 *
 * - ARF Catalogue の `nextUpdate` を使用時にも評価する
 * - 小数秒の `now` + `rpCertJudgmentCache` が TtlCache の整数 TTL 制約で 3002 にならない
 * - 非有限の `now` が素の RangeError ではなく 8030 になる
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { spkiToBase64 } from '../../../trust/arf/__tests__/arf-fixtures.js';
import { parseCertificate } from '../../../trust/etsi-tsl/index.js';
import { createRpCertJudgmentCache } from '../../../trust/rp-access/cache.js';
import { verifyJarSignature } from '../jar-signature.js';
import { buildArfTrustAnchor } from './arf-trust-anchor-fixtures.js';
import { CLIENT_ID, jarClaims, makeJarSigner, signJar } from './jar-fixtures.js';

async function expectReason(promise: Promise<unknown>, reason: string): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    const error = err as VericertsError;
    expect(error.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(error.context).toMatchObject({ reason });
  }
}

const nowSeconds = Math.floor(Date.now() / 1000);
// Request Object 側の `exp` は交絡させない（検証基準時刻をずらしても有効）。
const farExp = jarClaims({ exp: nowSeconds + 86_400 });

describe('verifyJarSignature: ARF Catalogue の nextUpdate を使用時にも評価する', () => {
  const verifier = makeJarSigner();
  const spki = parseCertificate(verifier.rp.der).spki;
  const entries = [{ id: CLIENT_ID, role: 'relying-party', spki: spkiToBase64(spki) }];
  const nextUpdateIso = new Date((nowSeconds + 60) * 1000).toISOString();

  it('nextUpdate 前の基準時刻なら受理する（対照）', async () => {
    const arfTrustAnchor = await buildArfTrustAnchor(entries, { nextUpdate: nextUpdateIso });
    await expect(
      verifyJarSignature(signJar(verifier, { claims: farExp }), {
        trustAnchors: [],
        arfTrustAnchor,
        now: nowSeconds,
      }),
    ).resolves.toBeUndefined();
  });

  it('ロード後に nextUpdate を過ぎた基準時刻では拒否する（境界ちょうどを含む）', async () => {
    const arfTrustAnchor = await buildArfTrustAnchor(entries, { nextUpdate: nextUpdateIso });
    for (const now of [nowSeconds + 60, nowSeconds + 3600]) {
      await expectReason(
        verifyJarSignature(signJar(verifier, { claims: farExp }), {
          trustAnchors: [],
          arfTrustAnchor,
          now,
        }),
        'rp_cert_untrusted',
      );
    }
  });

  it('解釈不能な nextUpdate は fail-closed で拒否する', async () => {
    const loaded = await buildArfTrustAnchor(entries);
    const arfTrustAnchor = { ...loaded, nextUpdate: 'tomorrow' };
    await expectReason(
      verifyJarSignature(signJar(verifier, { claims: farExp }), {
        trustAnchors: [],
        arfTrustAnchor,
        now: nowSeconds,
      }),
      'rp_cert_untrusted',
    );
  });

  it('nextUpdate を持たない集合は期限なしとして従来どおり受理する', async () => {
    const arfTrustAnchor = await buildArfTrustAnchor(entries);
    await expect(
      verifyJarSignature(signJar(verifier, { claims: farExp }), {
        trustAnchors: [],
        arfTrustAnchor,
        now: nowSeconds + 3600,
      }),
    ).resolves.toBeUndefined();
  });
});

describe('verifyJarSignature: 小数秒の now と rpCertJudgmentCache', () => {
  it('短命証明書でもキャッシュ有無で結果が変わらず成功する', async () => {
    const now = nowSeconds + 0.5;
    const verifier = makeJarSigner({ notAfter: new Date((nowSeconds + 600) * 1000) });
    const jar = signJar(verifier, { claims: farExp });

    await expect(
      verifyJarSignature(jar, { trustAnchors: verifier.anchors, now }),
    ).resolves.toBeUndefined();
    await expect(
      verifyJarSignature(jar, {
        trustAnchors: verifier.anchors,
        now,
        rpCertJudgmentCache: createRpCertJudgmentCache(),
      }),
    ).resolves.toBeUndefined();
  });
});

describe('verifyJarSignature: 非有限の now は 8030 に揃う', () => {
  const verifier = makeJarSigner();

  it.each([
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
  ])('now: %p は invalid_now（TSL 経路・キャッシュ有無とも）', async (now) => {
    const jar = signJar(verifier);
    await expectReason(
      verifyJarSignature(jar, { trustAnchors: verifier.anchors, now }),
      'invalid_now',
    );
    await expectReason(
      verifyJarSignature(jar, {
        trustAnchors: verifier.anchors,
        now,
        rpCertJudgmentCache: createRpCertJudgmentCache(),
      }),
      'invalid_now',
    );
  });
});
