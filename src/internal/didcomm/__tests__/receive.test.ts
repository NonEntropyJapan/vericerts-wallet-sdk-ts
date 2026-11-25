/**
 * `didcomm/receive.ts`（`receiveDIDCommMessage`）のテスト。
 * `packMessage` で作った JWE を実際に `receiveDIDCommMessage` で往復させ、Anoncrypt / Authcrypt
 * それぞれで復号・署名検証が正しく行われることを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { base64urlnopad } from '@scure/base';
import type { DIDDocument } from '../../identity/did.js';
import {
  createDidPeer2,
  encodePublicKeyMultibase,
  resolveDidPeer,
} from '../../identity/peer/method-peer.js';
import { createSecp256k1CredentialSigner } from '../../keymanager/credential-signer.js';
import { getSecp256k1PublicKey } from '../../keymanager/signer.js';
import { packMessage } from '../pack.js';
import { receiveDIDCommMessage } from '../receive.js';
import type {
  DIDCommKeyAgreementKeyPair,
  DIDCommPlaintextMessage,
  DIDCommResolver,
} from '../types.js';

function buildMyKeyAgreement(seed: number): DIDCommKeyAgreementKeyPair {
  const privateKey = new Uint8Array(32).fill(seed);
  const uncompressed = p256.getPublicKey(privateKey, false);
  return {
    privateKey,
    publicKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      x: base64urlnopad.encode(uncompressed.slice(1, 33)),
      y: base64urlnopad.encode(uncompressed.slice(33)),
    },
  };
}

describe('receiveDIDCommMessage — Anoncrypt', () => {
  it('resolver 未指定でも Anoncrypt メッセージは復号でき、authenticated: false になる', async () => {
    const me = buildMyKeyAgreement(30);
    const message: DIDCommPlaintextMessage = {
      id: 'm1',
      type: 'https://didcomm.org/basicmessage/2.0/message',
      body: { content: 'anonymous hello' },
    };
    const packed = await packMessage(message, me.publicKeyJwk);

    const result = await receiveDIDCommMessage(packed, me);
    expect(result.authenticated).toBe(false);
    expect(result.message.body).toEqual({ content: 'anonymous hello' });
  });
});

describe('receiveDIDCommMessage — Authcrypt', () => {
  it('resolver 経由で送信者署名を検証し、authenticated: true で本文を返す', async () => {
    const me = buildMyKeyAgreement(31);
    const senderPrivateKey = new Uint8Array(32).fill(32);
    const senderSigner = createSecp256k1CredentialSigner(senderPrivateKey);
    const signKey = encodePublicKeyMultibase(
      'secp256k1',
      getSecp256k1PublicKey(senderPrivateKey, true),
    );
    const senderDid = createDidPeer2({
      verificationKeys: [signKey],
      keyAgreementKeys: [],
      services: [],
    });
    const senderDoc: DIDDocument = resolveDidPeer(senderDid);

    const message: DIDCommPlaintextMessage = {
      id: 'm2',
      type: 'https://didcomm.org/basicmessage/2.0/message',
      from: senderDid,
      to: ['did:peer:2.me'],
      body: { content: 'authenticated hello' },
    };
    const packed = await packMessage(message, me.publicKeyJwk, { senderSigner });

    const resolver: DIDCommResolver = {
      resolve: async (did) =>
        did === senderDid
          ? senderDoc
          : (() => {
              throw new Error('unexpected DID');
            })(),
    };

    const result = await receiveDIDCommMessage(packed, me, {
      resolver,
      recipientDids: ['did:peer:2.me'],
    });
    expect(result.authenticated).toBe(true);
    expect(result.message).toEqual(message);
  });

  it('Authcrypt メッセージに resolver が未指定だと DIDCOMM_UNPACK_FAILED で拒否する（fail-closed）', async () => {
    const me = buildMyKeyAgreement(33);
    const senderSigner = createSecp256k1CredentialSigner(new Uint8Array(32).fill(34));
    const message: DIDCommPlaintextMessage = {
      id: 'm3',
      type: 'https://didcomm.org/basicmessage/2.0/message',
      from: 'did:peer:2.sender',
      body: {},
    };
    const packed = await packMessage(message, me.publicKeyJwk, { senderSigner });

    await expect(receiveDIDCommMessage(packed, me)).rejects.toMatchObject({ code: '9002' });
  });
});
