/**
 * `verifyJarSignature` の ES256 high-S 受理。
 *
 * Request Object（JAR）の署名は x5c 先頭証明書の公開鍵に対する WebCrypto の ECDSA 検証で、
 * RFC 7518 §3.4 どおり `s` と `n - s` のどちらも有効（OIDF Conformance Suite 等は high-S を出す）。
 * Node の署名は `s` が乱数的に low / high のどちらにもなるため、署名後に `s ↔ n - s` を反転して
 * 両方の形を明示的に作り、どちらも受理されることを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { verifyJarSignature } from '../jar-signature.js';
import { makeJarSigner, signJar } from './jar-fixtures.js';

const VERIFIER = makeJarSigner();
const TRUST = { trustAnchors: VERIFIER.anchors } as const;

/** JAR の署名を `{ low, high }` の両形に書き換える（`s` を `n - s` へ反転した版を相手側に用意する）。 */
function bothSForms(jar: string): { low: string; high: string } {
  const [header, payload, signature] = jar.split('.') as [string, string, string];
  const sig = p256.Signature.fromBytes(
    new Uint8Array(Buffer.from(signature, 'base64url')),
    'compact',
  );
  const flipped = new p256.Signature(sig.r, p256.Point.Fn.ORDER - sig.s);
  const encode = (value: InstanceType<typeof p256.Signature>): string =>
    `${header}.${payload}.${Buffer.from(value.toBytes('compact')).toString('base64url')}`;
  return sig.hasHighS()
    ? { low: encode(flipped), high: encode(sig) }
    : { low: encode(sig), high: encode(flipped) };
}

describe('verifyJarSignature: ES256 の s の形', () => {
  const { low, high } = bothSForms(signJar(VERIFIER));

  it('low-S の署名を受理する', async () => {
    await expect(verifyJarSignature(low, TRUST)).resolves.toBeUndefined();
  });

  it('high-S の署名を受理する', async () => {
    await expect(verifyJarSignature(high, TRUST)).resolves.toBeUndefined();
  });
});
