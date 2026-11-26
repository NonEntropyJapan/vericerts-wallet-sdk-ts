import {
  createSdJwt,
  credentialInput,
  HOLDER_JWK,
  ISSUER_JWK,
  issuerSigner,
  VCT,
  verifySdJwt,
} from '@vericerts/vericerts-wallet-sdk';
import { ChainVerificationCache } from '@vericerts/vericerts-wallet-sdk/experimental';

// Expected JWK coordinates and signature captured before the browser fix.
const issuer = [
  'WRq3ceu8_W2cuQlNEGUordGmnUTCwfYn8InsWLnGGt8',
  'n05qvw0EXAxpOjxorXyXynK-ZN70om_s0mPdmKkngPA',
];
const holder = [
  'B4EOqXTOpXc-Y7iX83476aCeel_puXGkTRBlrCo6kxE',
  'Y35HpPmUZKD9zkSojsfXA6kYPB0GVS2eLWt2BpSBxXc',
];
const signatureHex =
  '80e1c2274cb2597fa1d249fee98faffc0f7e3993cbc53195364374942e623ac66c4856b28cf718960dd45a2d68105ceb70e1266ebd1e8b850384aca3e35172e3';
for (const [jwk, [x, y]] of [
  [ISSUER_JWK, issuer],
  [HOLDER_JWK, holder],
]) {
  const expected = { kty: 'EC', crv: 'P-256', x, y };
  const fields = Object.entries(jwk);
  if (
    fields.length !== Object.keys(expected).length ||
    fields.some(([key, value]) => !Object.hasOwn(expected, key) || value !== expected[key])
  ) {
    throw new Error('Public interop JWK changed');
  }
}
const signer = issuerSigner();
const signature = signer.sign(new TextEncoder().encode('vericerts-haip-fixture'));
if (Array.from(signature, (b) => b.toString(16).padStart(2, '0')).join('') !== signatureHex) {
  throw new Error('Public interop signature changed');
}
const vc = verifySdJwt(createSdJwt(signer, credentialInput()), {
  issuerKey: ISSUER_JWK,
  expectedVct: VCT,
});
if (vc.cnf?.jwk.x !== HOLDER_JWK.x || vc.claims.nickname !== 'ali')
  throw new Error('SD-JWT verification failed');
if (typeof ChainVerificationCache !== 'function') throw new Error('Experimental entry unavailable');
document.documentElement.dataset.sdkResult = 'pass';
