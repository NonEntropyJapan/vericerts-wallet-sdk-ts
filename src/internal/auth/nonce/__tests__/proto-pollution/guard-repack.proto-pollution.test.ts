/**
 * replay guard がリプレイ窓オプションを詰め直す経路の汚染耐性テスト。
 *
 * `assertWithinReplayWindow` 側を `ownProperty` 化しても、**呼び出し側が継承値を新しい
 * オブジェクトリテラルへ詰め直して**渡すと own プロパティに化け、own 限定読み取りが
 * 無意味になる（`own-property.ts` の JSDoc が警告する失敗様式）。
 *
 * `verifyPresentationWithReplayGuard` / `verifySdJwtWithReplayGuard` は `windowOpts` を
 * その形で組み立てていたため、`replayWindowSeconds` を**渡していない**正当な検証でも
 * 継承値（例 `Infinity`）が実効窓になり、古い VP / KB-JWT のリプレイ窓検査が無効化されていた。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { issuePresentation } from '../../../../credential/presentation/issue.js';
import { createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext } from '../../types.js';
import { verifyPresentationWithReplayGuard } from '../../vp-guard.js';

const HOLDER_KEY = new Uint8Array(32).fill(11);
const SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256');

function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const KEY = { publicKeyJwk: toJwk(getP256PublicKey(HOLDER_KEY, false)) } as const;
const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const AUD = 'https://verifier.example/client';
const CTX: NonceContext = { flow: 'oid4vp', clientId: AUD };
/** 発行時刻。実時刻から十分離す（oid4vp の既定窓は 30 秒）。 */
const IAT = 1_700_000_000;

function present(): string {
  return issuePresentation(
    {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: 'did:example:holder',
      verifiableCredential: [],
    },
    SIGNER,
    { audience: AUD, nonce: NONCE, nowSeconds: IAT },
  );
}

describe('replay guard の windowOpts 詰め直し耐性', () => {
  it('継承した replayWindowSeconds ではリプレイ窓を広げられない', async () => {
    const jwt = present();
    // `nowSeconds` は発行から 10 万秒後。既定窓 30 秒なら必ず窓外（4014）。
    // 汚染した `replayWindowSeconds: Infinity` を詰め直して拾うと窓外判定が消えてしまう。
    const store = createNonceStore({ backend: 'memory', now: () => (IAT + 100_000) * 1000 });
    // 汚染値は**有限**の大きな窓にする。非有限だと `assertWithinReplayWindow` 側の
    // fail-closed ガードに先に当たり、詰め直しの有無を区別できなくなるため。
    await withPollutedPrototypeAsync({ replayWindowSeconds: 1_000_000 }, async () => {
      let caught: unknown;
      try {
        await verifyPresentationWithReplayGuard(jwt, {
          key: KEY,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: store,
          nowSeconds: IAT + 100_000,
          // replayWindowSeconds は渡していない。
        });
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(VericertsError);
      expect((caught as VericertsError).code).toBe(ErrorCodes.CLOCK_SKEW_EXCEEDED);
    });
  });

  it('明示的に渡した replayWindowSeconds は従来どおり効く（正常系）', async () => {
    const jwt = present();
    const store = createNonceStore({ backend: 'memory', now: () => (IAT + 100_000) * 1000 });
    const verified = await verifyPresentationWithReplayGuard(jwt, {
      key: KEY,
      nonce: NONCE,
      nonceContext: CTX,
      nonceStore: store,
      nowSeconds: IAT + 100_000,
      replayWindowSeconds: 200_000,
      clockSkewSeconds: 0,
    });
    expect(verified.payload.iss).toBe('did:example:holder');
  });
});
