/**
 * DID Document 読み取りヘルパーの汚染耐性。
 *
 * 自己完結メソッド（did:key / did:jwk / did:peer）の解決結果は `Object.prototype` を継承する通常の
 * オブジェクトで、`keyAgreement` / `service` / `deactivated` を持たない。`document.service` 等を素で
 * 読むと汚染値（攻撃者の暗号化鍵・エンドポイント）が「宛先の文書に載っていた値」として採用され、
 * `sendDIDCommMessage` が攻撃者宛に暗号化・送信する。汚染前後で読み取り結果が変わらないことで検証する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../__tests__/prototype-pollution.fixtures.js';
import { didDocumentToVerifierKey } from '../../credential/vc/verifier-key.js';
import { resolveKeyAgreement, resolveServiceEndpoint } from '../../didcomm/resolve.js';
import type { DIDDocument } from '../did.js';
import {
  controllersOf,
  relationshipEntriesOf,
  servicesOf,
  verificationMethodsOf,
} from '../did-document-read.js';
import { createDidJwk } from '../jwk/method-jwk.js';
import { createDidKey, resolveDidKey } from '../method-key.js';

const EVIL_KEY = {
  id: '#evil',
  type: 'JsonWebKey2020',
  controller: 'did:evil',
  publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'BBBB' },
};
const EVIL_SERVICE = {
  id: '#s',
  type: 'DIDCommMessaging',
  serviceEndpoint: 'https://evil.example/inbox',
};

const ed25519 = new Uint8Array(32).fill(7);
const jwkDoc = createDidJwk({
  kty: 'OKP',
  crv: 'Ed25519',
  x: Buffer.from(ed25519).toString('base64url'),
});
const keyDoc = resolveDidKey(createDidKey('Ed25519', ed25519).id);
const SELF_CONTAINED: readonly [string, DIDDocument][] = [
  ['did:jwk', jwkDoc],
  ['did:key', keyDoc],
];

describe('did-document-read の汚染耐性', () => {
  it.each(
    SELF_CONTAINED,
  )('%s: 汚染 keyAgreement / service を文書の内容として読まない', (_name, doc) => {
    const clean = {
      keyAgreement: relationshipEntriesOf(doc, 'keyAgreement'),
      service: servicesOf(doc),
      vm: verificationMethodsOf(doc).length,
      controllers: controllersOf(doc),
    };
    const polluted = withPollutedPrototype(
      {
        keyAgreement: [EVIL_KEY],
        service: [EVIL_SERVICE],
        verificationMethod: [EVIL_KEY],
        assertionMethod: [EVIL_KEY],
        controller: 'did:evil',
      },
      () => ({
        keyAgreement: relationshipEntriesOf(doc, 'keyAgreement'),
        service: servicesOf(doc),
        vm: verificationMethodsOf(doc).length,
        controllers: controllersOf(doc),
      }),
    );
    expect(polluted).toEqual(clean);
  });

  it('keyAgreement / service を持たない宛先は汚染下でも攻撃者の鍵・エンドポイントへ解決されない', () => {
    // 汚染前は keyAgreement 未掲載の文書で解決に失敗する（実際の送信前提条件）。
    const doc = createDidJwk({
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(ed25519).toString('base64url'),
    });
    const settle = (): string => {
      try {
        return JSON.stringify(resolveKeyAgreement(doc));
      } catch (error) {
        return `error:${(error as { code?: string }).code}`;
      }
    };
    const clean = settle();
    expect(clean).toStartWith('error:');
    const polluted = withPollutedPrototype(
      { keyAgreement: [EVIL_KEY], verificationMethod: [EVIL_KEY] },
      settle,
    );
    expect(polluted).toBe(clean);
    expect(resolveServiceEndpoint(doc)).toBeUndefined();
    expect(
      withPollutedPrototype({ service: [EVIL_SERVICE] }, () => resolveServiceEndpoint(doc)),
    ).toBeUndefined();
  });

  it.each(
    SELF_CONTAINED,
  )('%s: 汚染 deactivated=true で検証鍵の選択が全面拒否されない', (_name, doc) => {
    const clean = didDocumentToVerifierKey(doc);
    const polluted = withPollutedPrototype({ deactivated: true }, () =>
      didDocumentToVerifierKey(doc),
    );
    expect(polluted).toEqual(clean);
  });

  it('検証鍵の選択オプション（relationship / verificationMethodId）の継承値も採らない', () => {
    const clean = didDocumentToVerifierKey(jwkDoc);
    const polluted = withPollutedPrototype(
      { relationship: 'authentication', verificationMethodId: 'did:evil#x' },
      () => didDocumentToVerifierKey(jwkDoc, {}),
    );
    expect(polluted).toEqual(clean);
  });

  it('own の keyAgreement / service は汚染値より優先される（正常系）', () => {
    const own = {
      ...jwkDoc,
      service: [{ ...EVIL_SERVICE, serviceEndpoint: 'https://own.example/inbox' }],
    } as DIDDocument;
    withPollutedPrototype({ service: [EVIL_SERVICE] }, () => {
      expect(servicesOf(own).map((s) => s.serviceEndpoint)).toEqual(['https://own.example/inbox']);
    });
  });
});
