/**
 * replay 検知経路が「解決した実効 audience」を内包 SD-JWT VC の KB-JWT 検証へ中継することの
 * 回帰テスト。
 *
 * この経路では `expectedAudience` は**任意**で、照合対象は `nonceContext` の束縛値（OID4VP なら
 * `client_id`）である。したがってオプション値をそのまま中継すると、`expectedAudience` を省略した
 * 通常の呼び出しで audience が `undefined` になり、**他所の Verifier 宛の KB-JWT が素通り**する。
 * 中継すべきなのは、guard が束縛値と照合し終えた JWT-VP payload の実測 `aud` である。
 *
 * KB-JWT が証明するのは `cnf.jwk` の鍵保持までなので、`cnf` の鍵は VP 提示鍵と別鍵でよい。
 * このテストでは別々の鍵を使う。
 */

import { describe, expect, it } from 'bun:test';
import type { NonceContext } from '../../../internal/auth/nonce/index.js';
import { createNonceStore } from '../../../internal/auth/nonce/index.js';
import {
  addKeyBinding,
  createPrivateKeySigner,
  VC_V2_CONTEXT,
  type VerifiablePresentation,
} from '../../../internal/credential/index.js';
import type { PublicKeyJwk } from '../../../internal/identity/did.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { getP256PublicKey } from '../../../internal/keymanager/signer.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import { assertPresentationInvalid, embeddedErrorCodes } from '../verification-result.fixtures.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const CLIENT = 'https://verifier.example/client';
const OTHER_CLIENT = 'https://attacker.example/client';
const CTX: NonceContext = { flow: 'oid4vp', clientId: CLIENT };
const VCT = 'https://example.com/credentials/identity';

/** `cnf` に載せる Holder 鍵（VP 提示鍵とは別鍵。KB-JWT の署名鍵でもある）。 */
const KB_PRIVATE_KEY = new Uint8Array(32).fill(21);
const KB_SIGNER = createPrivateKeySigner(KB_PRIVATE_KEY, 'ES256');
const KB_JWK: PublicKeyJwk = (() => {
  const pub = getP256PublicKey(KB_PRIVATE_KEY, false);
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
})();

/** 指定 audience に束縛した KB-JWT 付き SD-JWT VC を内包する JWT-VP を発行する。 */
async function setup(kbAudience: string) {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  const document = await wallet.createDID('key', { keyID: keyPair.id });
  const nowSeconds = Math.floor(Date.now() / 1000);

  const sdJwt = await wallet.issueSdJwt(keyPair.id, {
    vct: VCT,
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
    issuer: document.id,
    cnf: { jwk: KB_JWK },
    nowSeconds,
  });
  const presentedVc = addKeyBinding(sdJwt, KB_SIGNER, {
    audience: kbAudience,
    nonce: NONCE,
    iatSeconds: nowSeconds,
  });

  const vp: VerifiablePresentation = {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiablePresentation'],
    holder: document.id,
    verifiableCredential: [presentedVc],
  };
  const presented = await wallet.issuePresentation(vp, keyPair.id, {
    audience: CLIENT,
    nonce: NONCE,
    nowSeconds,
  });
  return { wallet, presented, nowSeconds };
}

/** `expectedAudience` を渡さない replay 検知経路のオプション（束縛値は `nonceContext` 側）。 */
function guardOpts(nowSeconds: number) {
  return {
    expectedNonce: NONCE,
    nonceStore: createNonceStore({ backend: 'memory' }),
    nonceContext: CTX,
    nowSeconds,
  };
}

describe('replay 検知経路の実効 audience 中継', () => {
  it('別 Verifier 宛の KB-JWT は expectedAudience を省略しても 3012 で弾かれる', async () => {
    const { wallet, presented, nowSeconds } = await setup(OTHER_CLIENT);
    // 実効 audience を中継しないと audience 未指定になり、この KB-JWT が素通りする。
    const verified = assertPresentationInvalid(
      await wallet.verifyPresentation(presented, guardOpts(nowSeconds)),
    );
    expect(verified.presentationValid).toBe(true);
    expect(embeddedErrorCodes(verified.credentialResults[0])).toEqual(['3012']);
  });

  it('束縛値と同じ aud に束縛された KB-JWT は通る（過剰な拒否をしない）', async () => {
    const { wallet, presented, nowSeconds } = await setup(CLIENT);
    const verified = await wallet.verifyPresentation(presented, guardOpts(nowSeconds));
    expect(verified.valid).toBe(true);
    expect(verified.credentialResults[0]).toMatchObject({ valid: true, format: 'dc+sd-jwt' });
  });

  it('requireHolderBinding: true でも束縛が正しい KB-JWT 付き提示は通る', async () => {
    const { wallet, presented, nowSeconds } = await setup(CLIENT);
    const verified = await wallet.verifyPresentation(presented, {
      ...guardOpts(nowSeconds),
      requireHolderBinding: true,
    });
    expect(verified.valid).toBe(true);
  });
});
