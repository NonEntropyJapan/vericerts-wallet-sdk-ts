/**
 * `didcomm/send.ts`（`sendDIDCommMessage`）のテスト（詳細フロー）。
 * 直接 serviceEndpoint への送信・Mediator 経由のフォールバック・各失敗面を検証する。
 */

import { describe, expect, it, mock } from 'bun:test';
import { VericertsError } from '../../errors.js';
import type { DIDDocument, Service } from '../../identity/did.js';
import {
  createDidPeer2,
  encodePublicKeyMultibase,
  resolveDidPeer,
} from '../../identity/peer/method-peer.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../keymanager/signer.js';
import { sendDIDCommMessage } from '../send.js';
import type { DIDCommPlaintextMessage, DIDCommResolver } from '../types.js';

function buildPeerDoc(seed: number, services: readonly Service[]): DIDDocument {
  const signKey = encodePublicKeyMultibase(
    'secp256k1',
    getSecp256k1PublicKey(new Uint8Array(32).fill(seed), true),
  );
  const encKey = encodePublicKeyMultibase(
    'P-256',
    getP256PublicKey(new Uint8Array(32).fill(seed + 1), true),
  );
  const did = createDidPeer2({ verificationKeys: [signKey], keyAgreementKeys: [encKey], services });
  return resolveDidPeer(did);
}

function buildMessage(): DIDCommPlaintextMessage {
  return {
    id: 'msg-1',
    type: 'https://didcomm.org/basicmessage/2.0/message',
    body: { content: 'hi' },
  };
}

function resolverOf(docsByDid: Record<string, DIDDocument>): DIDCommResolver {
  return {
    resolve: async (did: string) => {
      const doc = docsByDid[did];
      if (doc === undefined) {
        throw new VericertsError('2001');
      }
      return doc;
    },
  };
}

describe('sendDIDCommMessage — 直接 serviceEndpoint', () => {
  it('serviceEndpoint へ HTTP POST し、body が JWE Compact Serialization になる', async () => {
    const recipientDoc = buildPeerDoc(1, [
      {
        id: '#didcomm',
        type: 'DIDCommMessaging',
        serviceEndpoint: 'https://recipient.example.com/didcomm',
      },
    ]);
    const recipientDid = recipientDoc.id;
    const resolver = resolverOf({ [recipientDid]: recipientDoc });
    const fetchImpl = mock(async (url: string | URL, _init?: RequestInit) => {
      expect(url).toBe('https://recipient.example.com/didcomm');
      return new Response(null, { status: 200 });
    });

    await sendDIDCommMessage(buildMessage(), recipientDid, resolver, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(String(init.body).split('.').length).toBe(5);
  });

  it('相手 DID Document に serviceEndpoint も Mediator も無い場合 SERVICE_ENDPOINT_NOT_FOUND', async () => {
    const recipientDoc = buildPeerDoc(2, []);
    const recipientDid = recipientDoc.id;
    const resolver = resolverOf({ [recipientDid]: recipientDoc });

    await expect(sendDIDCommMessage(buildMessage(), recipientDid, resolver)).rejects.toMatchObject({
      code: '9030',
    });
  });

  it('HTTP 配送が失敗（非 2xx）した場合 MEDIATOR_UNREACHABLE', async () => {
    const recipientDoc = buildPeerDoc(3, [
      {
        id: '#didcomm',
        type: 'DIDCommMessaging',
        serviceEndpoint: 'https://recipient.example.com/didcomm',
      },
    ]);
    const recipientDid = recipientDoc.id;
    const resolver = resolverOf({ [recipientDid]: recipientDoc });
    const fetchImpl = mock(async () => new Response(null, { status: 503 }));

    await expect(
      sendDIDCommMessage(buildMessage(), recipientDid, resolver, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: '9020' });
  });

  it('相手 DID の解決自体が失敗した場合 DIDCOMM_PACK_FAILED', async () => {
    const resolver: DIDCommResolver = {
      resolve: async () => {
        throw new VericertsError('2002');
      },
    };
    await expect(
      sendDIDCommMessage(buildMessage(), 'did:peer:2.unknown', resolver),
    ).rejects.toMatchObject({
      code: '9001',
    });
  });

  it('mode: authcrypt に senderSigner 未指定は DIDCOMM_PACKING_FAILED', async () => {
    const recipientDoc = buildPeerDoc(4, [
      {
        id: '#didcomm',
        type: 'DIDCommMessaging',
        serviceEndpoint: 'https://recipient.example.com/didcomm',
      },
    ]);
    const recipientDid = recipientDoc.id;
    const resolver = resolverOf({ [recipientDid]: recipientDoc });

    await expect(
      sendDIDCommMessage(buildMessage(), recipientDid, resolver, { mode: 'authcrypt' }),
    ).rejects.toMatchObject({ code: '9003' });
  });
});

describe('sendDIDCommMessage — Mediator 経由のフォールバック', () => {
  it('相手に直接 serviceEndpoint が無い場合、Mediator の serviceEndpoint へ forward メッセージを送る', async () => {
    const recipientDoc = buildPeerDoc(5, []);
    const recipientDid = recipientDoc.id;
    const mediatorDoc = buildPeerDoc(6, [
      {
        id: '#didcomm',
        type: 'DIDCommMessaging',
        serviceEndpoint: 'https://mediator.example.com/didcomm',
      },
    ]);
    const mediatorDid = mediatorDoc.id;
    const resolver = resolverOf({ [recipientDid]: recipientDoc, [mediatorDid]: mediatorDoc });
    const fetchImpl = mock(async (url: string | URL) => {
      expect(url).toBe('https://mediator.example.com/didcomm');
      return new Response(null, { status: 202 });
    });

    await sendDIDCommMessage(buildMessage(), recipientDid, resolver, {
      mediatorDid,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});
