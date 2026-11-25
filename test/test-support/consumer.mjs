import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  createWallet,
  MemoryStorage,
  MethodIpid,
  resolveBitstringStatus,
  resolveDidJwt,
  resolveDidPeer,
  resolveDidWebVh,
  verifyCredential,
  verifyPresentation,
} from 'vericerts-wallet-sdk';
import { verifyMaterials } from './verify.mjs';

verifyMaterials();
const read = (name) =>
  JSON.parse(readFileSync(new URL(`vectors/${name}.json`, import.meta.url))).cases;
const [credential] = read('credential');
const {
  vc,
  vp,
  foreignIssuerVc,
  nowSeconds,
  issuerDid,
  issuerPublicKeyJwk,
  holderPublicKeyJwk,
  audience,
  nonce,
} = credential;
const options = { key: { publicKeyJwk: issuerPublicKeyJwk }, nowSeconds };
assert.equal(verifyCredential(vc, options).payload.iss, issuerDid);
const vpOptions = {
  key: { publicKeyJwk: holderPublicKeyJwk },
  nowSeconds,
  expectedAudience: audience,
  expectedNonce: nonce,
  credentialKey: ({ issuerDID }) => (issuerDID === issuerDid ? options.key : undefined),
  requireHolderBinding: true,
};
assert.equal(verifyPresentation(vp, vpOptions).valid, true);
// issuer DIDの解決から実署名検証まで公開wallet APIを通す。
const wallet = await createWallet({ storage: new MemoryStorage() });
assert.equal((await wallet.verifyCredentialStrict(vc, { nowSeconds })).payload.iss, issuerDid);
await assert.rejects(
  () => wallet.verifyCredentialStrict(foreignIssuerVc, { nowSeconds }),
  (error) => String(error?.code) === '3010',
);
const code = (expected) => (error) => String(error?.code) === String(expected);
function tamper(token) {
  const [header, payload, signature] = token.split('.');
  const bytes = Buffer.from(signature, 'base64url');
  bytes[0] ^= 1;
  return `${header}.${payload}.${bytes.toString('base64url')}`;
}
assert.throws(() => verifyCredential(tamper(vc), options), code(3010));
assert.throws(
  () => verifyCredential(vc, { ...options, key: { publicKeyJwk: holderPublicKeyJwk } }),
  code(3010),
);
assert.equal(verifyPresentation(vp, { ...vpOptions, credentialKey: () => undefined }).valid, false);
assert.throws(
  () => verifyPresentation(vp, { ...vpOptions, expectedAudience: 'https://other.example' }),
  code(3012),
);
assert.throws(
  () => verifyPresentation(vp, { ...vpOptions, expectedNonce: 'other-nonce' }),
  code(3012),
);

const dids = read('did');
const local = dids[0];
assert.equal(resolveDidJwt(local.jwt, nowSeconds).id, local.jwt);
assert.equal(resolveDidPeer(local.peer).id, local.peer);
const originalFetch = globalThis.fetch;
try {
  globalThis.fetch = async () =>
    new Response(local.ipid.body, { headers: { 'content-type': 'application/json' } });
  assert.equal((await new MethodIpid().resolve(local.ipid.did)).id, local.ipid.did);
  for (const item of dids.slice(1)) {
    globalThis.fetch = async (input) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = item.bodies[url.pathname];
      const response = body
        ? new Response(body.text, { headers: { 'content-type': body.contentType } })
        : new Response('', { status: 404 });
      Object.defineProperty(response, 'url', { value: url.href });
      return response;
    };
    assert.equal((await resolveDidWebVh(item.did)).id, item.did);
    const wrongHost = item.did.replace(item.host, 'other.example');
    await assert.rejects(() => resolveDidWebVh(wrongHost));
  }
} finally {
  globalThis.fetch = originalFetch;
}

for (const { input, expected } of read('status-list')) {
  const verify = { key: { publicKeyJwk: input.issuerPublicKeyJwk }, nowSeconds: input.nowSeconds };
  const resolve = (entry, token = input.statusListCredential) =>
    resolveBitstringStatus(entry, { verify, fetchCredential: async () => token });
  const result = await resolve(input.entry);
  assert.deepEqual(result, expected);
  await assert.rejects(() => resolve(input.entry, tamper(input.statusListCredential)), code(3010));
  await assert.rejects(
    () => resolve({ ...input.entry, statusListCredential: 'https://other.example/status' }),
    code(3010),
  );
}
console.log('test-support: public package consumer passed (positive and negative controls)');
