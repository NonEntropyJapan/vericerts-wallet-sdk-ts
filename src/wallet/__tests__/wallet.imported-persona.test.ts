/**
 * 取り込んだ DID（did:web）のペルソナで Wallet ファサードが署名できること。
 *
 * Wallet は秘密鍵を保存しない。`WalletOptions.externalKeyProvider` が DID を指定して鍵を渡し、署名のたびに DID を
 * 解決し直して保持鍵との一致を確かめる（did:web もキャッシュしない。他のメソッドは `did-resolver.uncached.test.ts`）。提供元が無い・鍵を返さない場合は `2007`、
 * DID Document の鍵が替わったら `2017`。
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { externalKey } from '../../internal/credential/did-signing/__tests__/fixtures.js';
import { buildDidWebDocument } from '../../internal/credential/did-signing/did-document-export.js';
import { importPersonaFromDid } from '../../internal/credential/did-signing/import-persona.js';
import type { VerifiableCredential } from '../../internal/credential/index.js';
import { VericertsError } from '../../internal/errors.js';
import { createDidKey } from '../../internal/identity/method-key.js';
import { Resolver } from '../../internal/identity/resolver.js';
import { MethodWeb } from '../../internal/identity/web/method-web.js';
import { KeyManager } from '../../internal/keymanager/keymanager.js';
import { PersonaManager } from '../../internal/persona/persona.js';
import { MemoryStorage } from '../../storage/storage.js';
import { createWallet } from '../factory.js';
import type { WalletOptions } from '../options.js';
import type { Wallet } from '../types.js';

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const DID = 'did:web:example.com';
const FILE_URL = 'https://example.com/.well-known/did.json';
const KEY_A = externalKey('P-256', 71);
const KEY_B = externalKey('P-256', 72);
const CLIENT_ID = 'https://verifier.example.com';
const NONCE = 'n-0S6_WzA2Mj-0123456789';

const files: Record<string, unknown> = {};

/**
 * `did.json` の配信を模した fetch。`Cache-Control` を付けない（did:web の既定 TTL = 600 秒のキャッシュが効く条件）ので、
 * キャッシュありの解決器だと差し替えが反映されない。
 */
const didJsonFetch = (async (input: string | URL | Request) => {
  const url = String(input);
  const body = files[url];
  const response =
    body === undefined
      ? new Response('not found', { status: 404 })
      : new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'content-type': 'application/did+json' },
        });
  Object.defineProperty(response, 'url', { value: url });
  return response;
}) as typeof fetch;
const originalFetch = globalThis.fetch;

beforeEach(() => {
  files[FILE_URL] = buildDidWebDocument({ did: DID, publicKeyJwk: KEY_A.publicKeyJwk }).document;
  globalThis.fetch = didJsonFetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function requestUri(): string {
  const dcql = {
    credentials: [
      { id: 'degree', format: 'jwt_vc_json', claims: [{ path: ['credentialSubject', 'name'] }] },
    ],
  };
  const search = new URLSearchParams({
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: `${CLIENT_ID}/callback`,
    nonce: NONCE,
    state: 'af0ifjsldkj',
    dcql_query: JSON.stringify(dcql),
  });
  return `openid4vp://?${search.toString()}`;
}

const VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'UniversityDegree'],
  issuer: 'did:example:issuer',
  credentialSubject: { name: 'Bob' },
  issuanceDate: '2025-01-01T00:00:00Z',
  id: 'urn:vc:bob',
};

/** did:web を外部鍵（KEY_A）で取り込み、アクティブにした Wallet を用意する。 */
async function walletWithImportedPersona(
  optionsFor: (storage: MemoryStorage) => WalletOptions = (storage) => ({ storage }),
): Promise<Wallet> {
  const storage = new MemoryStorage();
  const wallet = await createWallet(optionsFor(storage));
  await wallet.importMnemonic(MNEMONIC);
  const km = new KeyManager();
  const resolver = new Resolver();
  resolver.register(new MethodWeb());
  const persona = await importPersonaFromDid(
    { personas: new PersonaManager(km, storage, createDidKey), keymanager: km, resolver },
    { did: DID, key: { external: KEY_A.privateKeyJwk } },
  );
  await wallet.setActivePersona(persona.id);
  await wallet.storeCredential(VC);
  return wallet;
}

async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    return (error as VericertsError).code;
  }
  return undefined;
}

describe('Wallet の取り込んだ DID のペルソナ署名', () => {
  it('externalKeyProvider が鍵を渡せば createPresentation で署名でき、検証できる（kid は DID Document の検証メソッド）', async () => {
    const asked: string[] = [];
    const wallet = await walletWithImportedPersona((storage) => ({
      storage,
      externalKeyProvider: async (did) => {
        asked.push(did);
        return KEY_A.privateKeyJwk;
      },
    }));

    const result = await wallet.createPresentation(requestUri(), ['urn:vc:bob']);

    expect(asked).toEqual([DID]);
    expect(result.holder).toBe(DID);
    const header = JSON.parse(
      Buffer.from(result.jwt.split('.')[0] as string, 'base64url').toString(),
    );
    expect(header).toMatchObject({ alg: 'ES256', kid: `${DID}#key-1` });
    const verified = await wallet.verifyPresentationEnvelopeStrict(result.jwt, {
      expectedAudience: CLIENT_ID,
      expectedNonce: NONCE,
    });
    expect(verified.payload.iss).toBe(DID);
    expect(verified.presentation.holder).toBe(DID);
  });

  it('externalKeyProvider が無い / 鍵を返さない / 例外を投げる場合は 2007（fail-closed。例外の内容は伝播しない）', async () => {
    const without = await walletWithImportedPersona();
    expect(await codeOf(() => without.createPresentation(requestUri(), ['urn:vc:bob']))).toBe(
      '2007',
    );

    const empty = await walletWithImportedPersona((storage) => ({
      storage,
      externalKeyProvider: async () => undefined,
    }));
    expect(await codeOf(() => empty.createPresentation(requestUri(), ['urn:vc:bob']))).toBe('2007');

    const failing = await walletWithImportedPersona((storage) => ({
      storage,
      externalKeyProvider: async () => {
        throw new Error('secret-store-offline d=AAAA');
      },
    }));
    expect(await codeOf(() => failing.createPresentation(requestUri(), ['urn:vc:bob']))).toBe(
      '2007',
    );
  });

  it('did.json の鍵が替わったら、次の署名から直ちに 2017 で拒否する（did:web の TTL キャッシュを待たない）', async () => {
    const wallet = await walletWithImportedPersona((storage) => ({
      storage,
      externalKeyProvider: async () => KEY_A.privateKeyJwk,
    }));
    await wallet.createPresentation(requestUri(), ['urn:vc:bob']);

    files[FILE_URL] = buildDidWebDocument({ did: DID, publicKeyJwk: KEY_B.publicKeyJwk }).document;

    expect(await codeOf(() => wallet.createPresentation(requestUri(), ['urn:vc:bob']))).toBe(
      '2017',
    );
  });

  it('提供元が別の鍵（取り違え）を返すと署名しない', async () => {
    const wallet = await walletWithImportedPersona((storage) => ({
      storage,
      externalKeyProvider: async () => KEY_B.privateKeyJwk,
    }));
    expect(await codeOf(() => wallet.createPresentation(requestUri(), ['urn:vc:bob']))).toBe(
      '2017',
    );
  });

  it('提供元はプロトタイプのメソッドでもレシーバ（opts）を保って呼ばれる', async () => {
    class Options {
      readonly secret = KEY_A.privateKeyJwk;
      constructor(readonly storage: MemoryStorage) {}
      async externalKeyProvider(_did: string) {
        return this.secret;
      }
    }
    const wallet = await walletWithImportedPersona((storage) => new Options(storage));
    expect((await wallet.createPresentation(requestUri(), ['urn:vc:bob'])).holder).toBe(DID);
  });
});
