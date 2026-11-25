/**
 * `did_signMessage`（`verifyMessageJws`）と DIDComm Authcrypt（`unpackMessage` の送信者署名検証）の
 * high-S 受理マトリクス。
 *
 * ES256 は high-S を受理し、ES256K は従来どおり拒否する（signMessage は 3010、DIDComm は 9002）。
 */

import { describe, expect, it } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { base64urlnopad } from '@scure/base';
import { decryptDidCommJwe, encryptDidCommJwe } from '../../../../didcomm/jwe.js';
import { packMessage, unpackMessage } from '../../../../didcomm/pack.js';
import type { DIDCommPlaintextMessage } from '../../../../didcomm/types.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { createDidKey, MethodKey } from '../../../../identity/method-key.js';
import { Resolver } from '../../../../identity/resolver.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../../keymanager/signer.js';
import { signMessageJws, verifyMessageJws } from '../../../did-signing/sign-message.js';
import { type EcdsaAlg, HIGH_S_FIXTURES, toHighS } from './high-s.fixtures.js';

const ALGS: EcdsaAlg[] = ['ES256', 'ES256K'];
const P256_KEY = new Uint8Array(32).fill(51);
const SECP_KEY = new Uint8Array(32).fill(53);

/** alg ごとの `did:key` DID Document（公開鍵は `HIGH_S_FIXTURES` と同じ秘密鍵由来）。 */
function senderDocument(alg: EcdsaAlg) {
  return alg === 'ES256'
    ? createDidKey('P-256', getP256PublicKey(P256_KEY, true))
    : createDidKey('secp256k1', getSecp256k1PublicKey(SECP_KEY, true));
}

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    return (e as VericertsError).code;
  }
  return undefined;
}

describe.each(ALGS)('signMessage の verifyMessageJws（%s）', (alg) => {
  const fx = HIGH_S_FIXTURES[alg];
  const doc = senderDocument(alg);
  const kid = doc.id.concat('#', doc.id.slice('did:key:'.length));
  const resolver = new Resolver();
  resolver.register(new MethodKey());
  const message = 'hello high-s';
  const opts = { message, resolver } as const;

  it('low-S 署名は検証できる', async () => {
    const jws = await signMessageJws(message, { ...fx.signer, kid });
    expect((await verifyMessageJws(jws, opts)).alg).toBe(alg);
  });

  if (alg === 'ES256') {
    it('high-S 署名も検証できる', async () => {
      const jws = toHighS(alg, await signMessageJws(message, { ...fx.signer, kid }));
      expect((await verifyMessageJws(jws, opts)).alg).toBe('ES256');
    });
  } else {
    it('high-S 署名は SIG_INVALID（3010）で拒否される', async () => {
      const jws = toHighS(alg, await signMessageJws(message, { ...fx.signer, kid }));
      expect(await codeOf(verifyMessageJws(jws, opts))).toBe(ErrorCodes.SIG_INVALID);
    });
  }
});

describe.each(ALGS)('DIDComm Authcrypt の送信者署名（%s）', (alg) => {
  const fx = HIGH_S_FIXTURES[alg];
  const doc = senderDocument(alg);
  const recipientKey = new Uint8Array(32).fill(61);
  const uncompressed = p256.getPublicKey(recipientKey, false);
  const recipientJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: base64urlnopad.encode(uncompressed.slice(1, 33)),
    y: base64urlnopad.encode(uncompressed.slice(33)),
  };
  const keyPair = { publicKeyJwk: recipientJwk, privateKey: recipientKey };
  const bob = 'did:example:bob';
  const message: DIDCommPlaintextMessage = {
    id: 'msg-high-s',
    type: 'https://didcomm.org/basicmessage/2.0/message',
    from: doc.id,
    to: [bob],
    body: { content: 'hello' },
  };
  const resolveSender = async () => doc;
  const unpackOpts = { recipientDids: [bob] };

  /** 署名済み JWS を取り出して high-S へ書き換え、同じ受信者へ再暗号化する。 */
  async function repackWithHighS(): Promise<string> {
    const packed = await packMessage(message, recipientJwk, { senderSigner: fx.signer });
    const { plaintext, cty } = await decryptDidCommJwe(packed, recipientKey);
    return encryptDidCommJwe(toHighS(alg, plaintext), recipientJwk, { cty });
  }

  it('low-S 署名は検証できる', async () => {
    const packed = await packMessage(message, recipientJwk, { senderSigner: fx.signer });
    expect((await unpackMessage(packed, keyPair, resolveSender, unpackOpts)).authenticated).toBe(
      true,
    );
  });

  if (alg === 'ES256') {
    it('high-S 署名も検証できる', async () => {
      const result = await unpackMessage(
        await repackWithHighS(),
        keyPair,
        resolveSender,
        unpackOpts,
      );
      expect(result.authenticated).toBe(true);
    });
  } else {
    it('high-S 署名は DIDCOMM_UNPACK_FAILED（9002）で拒否される', async () => {
      expect(
        await codeOf(unpackMessage(await repackWithHighS(), keyPair, resolveSender, unpackOpts)),
      ).toBe(ErrorCodes.DIDCOMM_UNPACK_FAILED);
    });
  }
});
