/**
 * `didcomm/resolve.ts` の `service` 要素読みが `Object.prototype` の汚染値を拾わないことの回帰テスト。
 *
 * `serviceEndpoint` / `type` / `uri` は型上は必須だが、実体はネットワーク由来の DID Document（JSON）で、省略した文書は
 * 汚染値を継承する。拾うと `sendDIDCommMessage` が暗号化済み JWE を攻撃者の URL へ POST する。
 */

import { describe, expect, it, mock } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { base64urlnopad } from '@scure/base';
import {
  withPollutedPrototype,
  withPollutedPrototypeAsync,
} from '../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../errors.js';
import type { DIDDocument } from '../../identity/did.js';
import { resolveKeyAgreement, resolveServiceEndpoint } from '../resolve.js';
import { sendDIDCommMessage } from '../send.js';
import type { DIDCommPlaintextMessage } from '../types.js';

const ATTACKER = 'https://evil.example/collect';
const pub = p256.getPublicKey(new Uint8Array(32).fill(3), false);
const jwk = {
  kty: 'EC',
  crv: 'P-256',
  x: base64urlnopad.encode(pub.slice(1, 33)),
  y: base64urlnopad.encode(pub.slice(33)),
};

function docWith(service: unknown[]): DIDDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: 'did:ex:bob',
    verificationMethod: [
      { id: 'did:ex:bob#k', type: 'JsonWebKey2020', controller: 'did:ex:bob', publicKeyJwk: jwk },
    ],
    keyAgreement: ['did:ex:bob#k'],
    service,
  } as unknown as DIDDocument;
}

const message: DIDCommPlaintextMessage = { id: '1', type: 't', body: { secret: 'x' } };

describe('resolveServiceEndpoint は service 要素を own 限定で読む', () => {
  const shapes: readonly (readonly [string, unknown[], Record<string, unknown>])[] = [
    [
      'serviceEndpoint を省略',
      [{ id: '#svc', type: 'DIDCommMessaging' }],
      { serviceEndpoint: ATTACKER },
    ],
    [
      'serviceEndpoint がオブジェクトで uri を省略',
      [{ id: '#svc', type: 'DIDCommMessaging', serviceEndpoint: {} }],
      { uri: ATTACKER },
    ],
    [
      'serviceEndpoint が配列で先頭が uri を省略',
      [{ id: '#svc', type: 'DIDCommMessaging', serviceEndpoint: [{}] }],
      { uri: ATTACKER },
    ],
    [
      'type を省略',
      [{ id: '#svc', serviceEndpoint: 'https://ok.example/' }],
      { type: 'DIDCommMessaging' },
    ],
  ];

  for (const [name, service, pollution] of shapes) {
    it(`${name}: 汚染前後とも undefined`, () => {
      const doc = docWith(service);
      expect(resolveServiceEndpoint(doc)).toBeUndefined();
      expect(withPollutedPrototype(pollution, () => resolveServiceEndpoint(doc))).toBeUndefined();
    });
  }

  it('own で宣言した endpoint は汚染下でも own の値を返す', () => {
    const doc = docWith([
      { id: '#svc', type: 'DIDCommMessaging', serviceEndpoint: { uri: 'https://ok.example/' } },
    ]);
    const polluted = withPollutedPrototype({ uri: ATTACKER, serviceEndpoint: ATTACKER }, () =>
      resolveServiceEndpoint(doc),
    );
    expect(polluted).toBe('https://ok.example/');
  });

  it('sendDIDCommMessage は汚染された serviceEndpoint 宛に fetch しない', async () => {
    const doc = docWith([{ id: '#svc', type: 'DIDCommMessaging' }]);
    const fetchImpl = mock(async () => new Response(null, { status: 200 }));
    await withPollutedPrototypeAsync({ serviceEndpoint: ATTACKER }, async () => {
      await expect(
        sendDIDCommMessage(
          message,
          doc.id,
          { resolve: async () => doc },
          {
            fetchImpl: fetchImpl as unknown as typeof fetch,
          },
        ),
      ).rejects.toBeDefined();
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('resolveKeyAgreement の VerificationMethod id は own 限定', () => {
  it('own の id を返し、汚染 id には置き換わらない', () => {
    const polluted = withPollutedPrototype({ id: 'did:ex:evil#k' }, () =>
      resolveKeyAgreement(docWith([])),
    );
    expect(polluted.id).toBe('did:ex:bob#k');
  });

  it('id を持たない埋め込み keyAgreement は汚染 id でも解決しない', () => {
    const doc = {
      ...docWith([]),
      keyAgreement: [{ type: 'JsonWebKey2020', controller: 'did:ex:bob', publicKeyJwk: jwk }],
    } as unknown as DIDDocument;
    expect(() =>
      withPollutedPrototype({ id: 'did:ex:evil#k' }, () => resolveKeyAgreement(doc)),
    ).toThrow(expect.objectContaining({ code: ErrorCodes.DID_DOC_INVALID }));
  });
});
