/**
 * 取り込んだ DID（did:web）のペルソナで `generateDIDConfiguration` が署名でき、`verifyDIDConfiguration` を通ること。
 *
 * DLC の JWS ヘッダに `kid` が載らないと検証側は `assertionMethod[0]` を検証鍵に選ぶので、保持鍵が `assertionMethod` の
 * 先頭でない取り込み DID の DLC が落ちる。`assertionMethod` に載っていない（`authentication` のみ）DID は署名しない
 * （エラーコード `2007`）。
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { externalKey } from '../../internal/credential/did-signing/__tests__/fixtures.js';
import { importPersonaFromDid } from '../../internal/credential/did-signing/import-persona.js';
import { VericertsError } from '../../internal/errors.js';
import type { DIDDocument } from '../../internal/identity/did.js';
import { createDidKey } from '../../internal/identity/method-key.js';
import { Resolver } from '../../internal/identity/resolver.js';
import { MethodWeb } from '../../internal/identity/web/method-web.js';
import { KeyManager } from '../../internal/keymanager/keymanager.js';
import { PersonaManager } from '../../internal/persona/persona.js';
import { MemoryStorage } from '../../storage/storage.js';
import { createWallet } from '../factory.js';
import type { Wallet } from '../types.js';

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ORIGIN = 'https://example.com';
const DID = 'did:web:example.com';
const FILE_URL = `${ORIGIN}/.well-known/did.json`;
const OTHER = externalKey('P-256', 81);
const HELD = externalKey('P-256', 82);

const files: Record<string, unknown> = {};
let linked: string[] = [];

const originalFetch = globalThis.fetch;

function documentWith(
  relationships: Partial<Pick<DIDDocument, 'assertionMethod' | 'authentication'>>,
): DIDDocument {
  const vm = (fragment: string, key: typeof HELD) => ({
    id: `${DID}#${fragment}`,
    type: 'JsonWebKey2020',
    controller: DID,
    publicKeyJwk: key.publicKeyJwk,
  });
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: DID,
    verificationMethod: [vm('other', OTHER), vm('held', HELD)],
    ...relationships,
  } as unknown as DIDDocument;
}

beforeEach(() => {
  linked = [];
  globalThis.fetch = (async (input: string | URL | Request) => {
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
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** 保持鍵（HELD）で did:web を取り込み、アクティブにした Wallet を作る（`verifyDIDConfiguration` は `linked` を配信する）。 */
async function walletWithImportedPersona(): Promise<Wallet> {
  const storage = new MemoryStorage();
  const wallet = await createWallet({
    storage,
    externalKeyProvider: async () => HELD.privateKeyJwk,
    didConfigurationFetchImpl: () =>
      Promise.resolve(
        new Response(JSON.stringify({ linked_dids: linked }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      ),
  });
  await wallet.importMnemonic(MNEMONIC);
  const km = new KeyManager();
  const resolver = new Resolver();
  resolver.register(new MethodWeb());
  const persona = await importPersonaFromDid(
    { personas: new PersonaManager(km, storage, createDidKey), keymanager: km, resolver },
    { did: DID, key: { external: HELD.privateKeyJwk } },
  );
  await wallet.setActivePersona(persona.id);
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

describe('Wallet.generateDIDConfiguration: 取り込んだ DID のペルソナ', () => {
  it('保持鍵が assertionMethod の先頭でなくても、kid 付きで署名し verifyDIDConfiguration を通る', async () => {
    files[FILE_URL] = documentWith({
      authentication: [`${DID}#held`],
      assertionMethod: [`${DID}#other`, `${DID}#held`],
    });
    const wallet = await walletWithImportedPersona();

    const configuration = await wallet.generateDIDConfiguration(DID, ORIGIN);
    const jwt = configuration.linked_dids[0] as string;
    const header = JSON.parse(Buffer.from(jwt.split('.')[0] as string, 'base64url').toString());
    expect(header).toMatchObject({ alg: 'ES256', kid: `${DID}#held` });

    linked = [...configuration.linked_dids];
    const result = await wallet.verifyDIDConfiguration(ORIGIN, DID);
    expect(result.linkedDIDs).toHaveLength(1);
    expect(result.linkedDIDs[0]?.valid).toBe(true);
  });

  it('保持鍵が authentication にしか載っていない DID は署名しない（2007）', async () => {
    files[FILE_URL] = documentWith({
      authentication: [`${DID}#held`],
      assertionMethod: [`${DID}#other`],
    });
    const wallet = await walletWithImportedPersona();
    expect(await codeOf(() => wallet.generateDIDConfiguration(DID, ORIGIN))).toBe('2007');
  });

  it('取り込み後に鍵が DID Document から外れたら署名しない（2017 も 2007 に畳む）', async () => {
    files[FILE_URL] = documentWith({ assertionMethod: [`${DID}#held`] });
    const wallet = await walletWithImportedPersona();
    files[FILE_URL] = documentWith({
      assertionMethod: [`${DID}#other`],
      authentication: [`${DID}#other`],
    });
    expect(await codeOf(() => wallet.generateDIDConfiguration(DID, ORIGIN))).toBe('2007');
  });

  it('アクティブなペルソナが無い（2005 / 1041）場合も 2007', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    expect(await codeOf(() => wallet.generateDIDConfiguration(DID, ORIGIN))).toBe('2007');
  });
});
