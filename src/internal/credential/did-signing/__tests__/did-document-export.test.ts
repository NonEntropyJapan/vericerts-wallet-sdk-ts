/**
 * DID Document の書き出し（`did-document-export.ts`）。ネットワーク書き込みは無い。
 *
 * did:web `did.json` の配置先は did:web 仕様の変換規則（ドメインのみ → `/.well-known/did.json`、
 * パス付き → `/<path>/did.json`、`%3A` はポート区切り）に従う。書き出した文書は SDK の did:web 解決で
 * そのまま読め、公開鍵が一致する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import {
  buildDidCoreDocument,
  buildDidWebDocument,
  didWebDocumentLocation,
  serializeDidDocument,
} from '../did-document-export.js';
import { verifyHeldKeyAgainstDid } from '../key-binding.js';
import { externalKey, newWorld } from './fixtures.js';

const KEY = externalKey('P-256', 61);

describe('didWebDocumentLocation', () => {
  it.each([
    [
      'did:web:example.com',
      'https://example.com/.well-known/did.json',
      'example.com',
      '.well-known/did.json',
    ],
    [
      'did:web:example.com:users:alice',
      'https://example.com/users/alice/did.json',
      'example.com',
      'users/alice/did.json',
    ],
    [
      'did:web:example.com%3A3000:a',
      'https://example.com:3000/a/did.json',
      'example.com:3000',
      'a/did.json',
    ],
  ])('%s', (did, url, host, path) => {
    expect(didWebDocumentLocation(did)).toEqual({ url, host, path });
  });

  it('did:web でない・不正な DID は 2001', () => {
    for (const did of [
      'did:key:z6Mk',
      'did:web:',
      'did:web:exa mple.com',
      'did:web:example.com:..:x',
    ]) {
      expect(() => didWebDocumentLocation(did)).toThrow(
        expect.objectContaining({ code: ErrorCodes.INVALID_DID }),
      );
    }
  });
});

describe('buildDidCoreDocument', () => {
  it('JsonWebKey2020 の検証メソッドを authentication / assertionMethod / capability* に載せる', () => {
    const document = buildDidCoreDocument({
      did: 'did:example:123',
      publicKeyJwk: KEY.publicKeyJwk,
      fragment: 'sig-1',
      controller: 'did:example:org',
    });
    expect(document).toEqual({
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
      id: 'did:example:123',
      controller: 'did:example:org',
      verificationMethod: [
        {
          id: 'did:example:123#sig-1',
          type: 'JsonWebKey2020',
          controller: 'did:example:123',
          publicKeyJwk: KEY.publicKeyJwk,
        },
      ],
      authentication: ['did:example:123#sig-1'],
      assertionMethod: ['did:example:123#sig-1'],
      capabilityInvocation: ['did:example:123#sig-1'],
      capabilityDelegation: ['did:example:123#sig-1'],
    });
  });

  it('秘密鍵（d）を含む JWK は 1003、未対応の鍵種は 1030 で書き出さない', () => {
    expect(() =>
      buildDidCoreDocument({ did: 'did:example:1', publicKeyJwk: KEY.privateKeyJwk }),
    ).toThrow(expect.objectContaining({ code: ErrorCodes.INVALID_PRIVATE_KEY }));
    expect(() =>
      buildDidCoreDocument({
        did: 'did:example:1',
        publicKeyJwk: { kty: 'RSA', n: 'x', e: 'AQAB' },
      }),
    ).toThrow(expect.objectContaining({ code: ErrorCodes.UNSUPPORTED_ALGORITHM }));
  });

  it('serializeDidDocument は 2 スペースインデント・末尾改行の JSON', () => {
    const document = buildDidCoreDocument({ did: 'did:example:1', publicKeyJwk: KEY.publicKeyJwk });
    const text = serializeDidDocument(document);
    expect(text.endsWith('}\n')).toBe(true);
    expect(JSON.parse(text)).toEqual(JSON.parse(JSON.stringify(document)));
    expect(text.split('\n')[1]).toStartWith('  "');
  });
});

describe('buildDidWebDocument', () => {
  it('配置先と内容を返し、配信すれば SDK の did:web 解決で保持鍵と一致する', async () => {
    const exported = buildDidWebDocument({
      did: 'did:web:example.com:team',
      publicKeyJwk: KEY.publicKeyJwk,
    });
    expect(exported.url).toBe('https://example.com/team/did.json');
    expect(JSON.parse(exported.content)).toMatchObject({ id: 'did:web:example.com:team' });

    const world = await newWorld({ files: { [exported.url]: JSON.parse(exported.content) } });
    const match = await verifyHeldKeyAgainstDid(
      world.resolver,
      'did:web:example.com:team',
      KEY.publicKeyJwk,
    );
    expect(match.kid).toBe('did:web:example.com:team#key-1');
    expect(match.allRelationships).toEqual(['authentication', 'assertionMethod']);
  });

  it('did:web 以外の DID は 2001', () => {
    expect(() =>
      buildDidWebDocument({ did: 'did:key:zabc', publicKeyJwk: KEY.publicKeyJwk }),
    ).toThrow(expect.objectContaining({ code: ErrorCodes.INVALID_DID }));
  });
});
