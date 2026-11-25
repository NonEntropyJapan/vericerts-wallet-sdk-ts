/**
 * `federationTrustAnchor.trustAnchorJwks`（OIDF Trust Anchor 鍵のピン留め）の JAR 経路回帰テスト。
 *
 * 指定したピン留め鍵で Anchor の Entity Configuration が署名されていなければ OIDF 層は成立せず
 * （`rp_cert_untrusted`）、未指定なら従来どおり自己署名のみで受理される（後方互換）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import {
  makeFetchMock,
  nowFn,
  signStatement,
  toJwk,
  validPeriod,
} from '../../../trust/federation/__tests__/federation-fixtures.js';
import { verifyJarSignature } from '../jar-signature.js';
import { CLIENT_ID, makeJarSigner, signJar, toX5cEntry } from './jar-fixtures.js';

const VERIFIER = makeJarSigner();
const ANCHOR_SIGNING_KEY = new Uint8Array(32).fill(31);
const OTHER_KEY = new Uint8Array(32).fill(37);

/** Leaf = Trust Anchor の 1 段チェーン。EC は `signingKey` で自己署名し、JAR 署名者の x5c を埋め込む。 */
function selfAnchored(signingKey: Uint8Array): Map<string, string> {
  const jwk = { ...toJwk(signingKey, 'leaf-1'), x5c: [toX5cEntry(VERIFIER.rp.der)] };
  const ec = signStatement(
    signingKey,
    { iss: CLIENT_ID, sub: CLIENT_ID, ...validPeriod(), jwks: { keys: [jwk] } },
    { kid: 'leaf-1' },
  );
  return new Map([[`${CLIENT_ID}/.well-known/openid-federation`, ec]]);
}

function verifyWith(
  responses: Map<string, string>,
  trustAnchorJwks?: { keys: unknown[] },
): Promise<void> {
  return verifyJarSignature(signJar(VERIFIER), {
    trustAnchors: [],
    expectedClientId: CLIENT_ID,
    federationTrustAnchor: {
      trustAnchorEntityId: CLIENT_ID,
      deps: { fetchFn: makeFetchMock(responses), now: nowFn },
      ...(trustAnchorJwks === undefined ? {} : { trustAnchorJwks: trustAnchorJwks as never }),
    },
  });
}

async function expectUntrusted(promise: Promise<unknown>): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    const error = err as VericertsError;
    expect(error.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(error.context).toMatchObject({ reason: 'rp_cert_untrusted' });
  }
}

describe('verifyJarSignature: OIDF Trust Anchor 鍵ピン留め', () => {
  it('ピン留め鍵で署名された Anchor EC なら受理する', async () => {
    await expect(
      verifyWith(selfAnchored(ANCHOR_SIGNING_KEY), { keys: [toJwk(ANCHOR_SIGNING_KEY)] }),
    ).resolves.toBeUndefined();
  });

  it('Anchor EC が別鍵で署名されている（TLS 越しの差し替え）場合、ピン留め下では拒否する', async () => {
    const forged = selfAnchored(OTHER_KEY);
    // 前提: ピン留め無しでは受理される（従来挙動・後方互換）。
    await expect(verifyWith(forged)).resolves.toBeUndefined();
    await expectUntrusted(verifyWith(forged, { keys: [toJwk(ANCHOR_SIGNING_KEY)] }));
  });

  it('空の keys など不正なピン留め設定は未指定扱いにせず拒否する', async () => {
    await expectUntrusted(verifyWith(selfAnchored(ANCHOR_SIGNING_KEY), { keys: [] }));
  });
});
