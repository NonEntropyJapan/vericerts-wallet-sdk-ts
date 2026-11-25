/**
 * `verifyJarSignature` の null 値・非オブジェクト entry の防御の回帰テスト。
 *
 * `jar-signature.federation-arf.test.ts` から分割した実体（Linterly 300 行/ファイル上限）。
 *
 * `federationTrustAnchor` / `arfTrustAnchor` に `null` が渡された場合、および `arfTrustAnchor.entries`
 * に `null` が混じる場合に、`jar-trust-evaluation.ts` / `jar-trust-arf.ts` の `ownProperty` 呼び出しが
 * `Object.hasOwn(null, …)` で生の `TypeError` を投げ、`jarFailure('rp_cert_untrusted')`（8030）への
 * 正規化を素通りしてしまわないことを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { spkiToBase64 } from '../../../trust/arf/__tests__/arf-fixtures.js';
import type { ArfTrustAnchorSet } from '../../../trust/arf/index.js';
import { parseCertificate } from '../../../trust/etsi-tsl/index.js';
import type { JarTrustOptions } from '../jar-signature.js';
import { verifyJarSignature } from '../jar-signature.js';
import { buildArfTrustAnchor } from './arf-trust-anchor-fixtures.js';
import { CLIENT_ID, makeJarSigner, signJar } from './jar-fixtures.js';

const VERIFIER = makeJarSigner();

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

describe('verifyJarSignature: null 値・非オブジェクト entry の防御', () => {
  it('arfTrustAnchor: null は生の TypeError ではなく 8030/rp_cert_untrusted に正規化される', async () => {
    // 型上は `ArfTrustAnchorSet` だが、実行時には `null` が渡され得る（DI/設定ミス等）ことを模擬する。
    const arfTrustAnchor = null as unknown as ArfTrustAnchorSet;
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), { trustAnchors: [], arfTrustAnchor }),
      'rp_cert_untrusted',
    );
  });

  it('federationTrustAnchor: null は生の TypeError ではなく 8030/rp_cert_untrusted に正規化される', async () => {
    const federationTrustAnchor = null as unknown as NonNullable<
      JarTrustOptions['federationTrustAnchor']
    >;
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        trustAnchors: [],
        expectedClientId: CLIENT_ID,
        federationTrustAnchor,
      }),
      'rp_cert_untrusted',
    );
  });

  it('arfTrustAnchor.entries に null が混じっていても生の TypeError ではなく正しく検証できる', async () => {
    const spki = parseCertificate(VERIFIER.rp.der).spki;
    const arfTrustAnchor = await buildArfTrustAnchor([
      { id: CLIENT_ID, role: 'relying-party', spki: spkiToBase64(spki) },
    ]);
    // 正当なエントリの手前に `null` を混入させる。修正前は `entries.some` が `null` を先に評価
    // した時点で生の `TypeError` を投げ、後続の正当なエントリまで到達できなかった
    // （`.some` は例外を吸収しないため、以降のエントリを 1 件も評価しない）。
    const polluted: ArfTrustAnchorSet = {
      ...arfTrustAnchor,
      entries: [null as unknown as ArfTrustAnchorSet['entries'][number], ...arfTrustAnchor.entries],
    };
    await expect(
      verifyJarSignature(signJar(VERIFIER), { trustAnchors: [], arfTrustAnchor: polluted }),
    ).resolves.toBeUndefined();
  });
});
