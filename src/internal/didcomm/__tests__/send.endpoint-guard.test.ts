/**
 * `sendDIDCommMessage` の serviceEndpoint ガード。
 * endpoint は相手が制御する DID Document 由来のため、公開ホスト宛 HTTPS 以外へは fetch しない。
 */

import { afterEach, describe, expect, it, mock } from 'bun:test';
import { VericertsError } from '../../errors.js';
import type { DIDDocument } from '../../identity/did.js';
import {
  createDidPeer2,
  encodePublicKeyMultibase,
  resolveDidPeer,
} from '../../identity/peer/method-peer.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../keymanager/signer.js';
import { sendDIDCommMessage } from '../send.js';
import type { DIDCommPlaintextMessage, DIDCommResolver } from '../types.js';

function buildPeerDoc(seed: number, serviceEndpoint?: string): DIDDocument {
  const signKey = encodePublicKeyMultibase(
    'secp256k1',
    getSecp256k1PublicKey(new Uint8Array(32).fill(seed), true),
  );
  const encKey = encodePublicKeyMultibase(
    'P-256',
    getP256PublicKey(new Uint8Array(32).fill(seed + 1), true),
  );
  const services =
    serviceEndpoint === undefined
      ? []
      : [{ id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint }];
  return resolveDidPeer(
    createDidPeer2({ verificationKeys: [signKey], keyAgreementKeys: [encKey], services }),
  );
}

const message: DIDCommPlaintextMessage = {
  id: 'msg-1',
  type: 'https://didcomm.org/basicmessage/2.0/message',
  body: { content: 'hi' },
};

function resolverOf(...docs: DIDDocument[]): DIDCommResolver {
  return {
    resolve: async (did: string) => {
      const doc = docs.find((d) => d.id === did);
      if (doc === undefined) {
        throw new VericertsError('2001');
      }
      return doc;
    },
  };
}

describe('sendDIDCommMessage — serviceEndpoint の SSRF ガード', () => {
  it.each([
    'http://recipient.example.com/didcomm',
    'file:///etc/passwd',
    'https://localhost:8080/x',
    'https://app.localhost/x',
    'https://127.0.0.1/x',
    'https://169.254.169.254/latest/meta-data',
    'https://10.0.0.5/x',
    'https://192.168.1.1/x',
    'https://172.16.0.1/x',
    'https://[::1]/x',
    'https://[fe80::1]/x',
    'https://[fd00::1]/x',
    'https://[::ffff:7f00:1]/x',
    'https://2130706433/x',
  ])('直接 endpoint %s は fetch せず MEDIATOR_UNREACHABLE', async (endpoint) => {
    const doc = buildPeerDoc(1, endpoint);
    const fetchImpl = mock(async () => new Response(null, { status: 200 }));
    await expect(
      sendDIDCommMessage(message, doc.id, resolverOf(doc), {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: '9020' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('Mediator の endpoint が localhost の場合も fetch しない', async () => {
    const recipient = buildPeerDoc(3);
    const mediator = buildPeerDoc(5, 'https://localhost/didcomm');
    const fetchImpl = mock(async () => new Response(null, { status: 200 }));
    await expect(
      sendDIDCommMessage(message, recipient.id, resolverOf(recipient, mediator), {
        mediatorDid: mediator.id,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: '9020' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('公開 https endpoint へは redirect:manual とタイムアウト signal 付きで POST する', async () => {
    const doc = buildPeerDoc(7, 'https://recipient.example.com/didcomm');
    const fetchImpl = mock(async (_url: string, _init: RequestInit) => new Response(null));
    await sendDIDCommMessage(message, doc.id, resolverOf(doc), {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const init = fetchImpl.mock.calls[0]?.[1] as RequestInit;
    expect(init.redirect).toBe('manual');
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('3xx 応答（redirect:manual）は配送失敗として扱う', async () => {
    const doc = buildPeerDoc(9, 'https://recipient.example.com/didcomm');
    const fetchImpl = mock(
      async () =>
        new Response(null, { status: 307, headers: { location: 'http://169.254.169.254/' } }),
    );
    await expect(
      sendDIDCommMessage(message, doc.id, resolverOf(doc), {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: '9020' });
  });

  describe('Object.prototype 汚染', () => {
    afterEach(() => {
      Reflect.deleteProperty(Object.prototype, 'fetchImpl');
      Reflect.deleteProperty(Object.prototype, 'mediatorDid');
    });

    it('汚染された fetchImpl は採用せずグローバル fetch を使う', async () => {
      const doc = buildPeerDoc(11, 'https://recipient.example.com/didcomm');
      const evil = mock(async () => new Response(null, { status: 200 }));
      const realFetch = mock(async () => new Response(null, { status: 200 }));
      const original = globalThis.fetch;
      globalThis.fetch = realFetch as unknown as typeof fetch;
      Object.defineProperty(Object.prototype, 'fetchImpl', {
        value: evil,
        configurable: true,
        writable: true,
      });
      try {
        await sendDIDCommMessage(message, doc.id, resolverOf(doc));
      } finally {
        globalThis.fetch = original;
      }
      expect(evil).not.toHaveBeenCalled();
      expect(realFetch).toHaveBeenCalledTimes(1);
    });

    it('汚染された mediatorDid は採用しない', async () => {
      const recipient = buildPeerDoc(13);
      const mediator = buildPeerDoc(15, 'https://mediator.example.com/didcomm');
      Object.defineProperty(Object.prototype, 'mediatorDid', {
        value: mediator.id,
        configurable: true,
        writable: true,
      });
      await expect(
        sendDIDCommMessage(message, recipient.id, resolverOf(recipient, mediator)),
      ).rejects.toMatchObject({ code: '9030' });
    });
  });
});
