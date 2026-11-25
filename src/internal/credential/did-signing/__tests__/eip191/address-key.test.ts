/**
 * did:pkh / did:ethr の controller 鍵の署名（EIP-191 / `alg: "ES256K-R"`）。
 *
 * ES256K-R は IANA の JWS alg 登録外で、標準だけで署名する規則（2026-10-28）の例外。範囲は「検証メソッドが公開鍵を
 * 持たず `blockchainAccountId` だけを持つ did:pkh / did:ethr の controller 鍵」に限る。
 *
 * - 取り込み・署名は、保持鍵（secp256k1）のアドレスが `blockchainAccountId` と一致するときだけ。
 * - 署名のたびに DID を解決し直す（did:ethr の controller 変更後は署名しない）。
 * - 範囲外は従来どおり `2017`: アドレス不一致・P-256 / Ed25519 の鍵・did:plc（#atproto は認証用途に載らない）。
 * - 標準の alg の経路（SD-JWT）は ES256K-R を受理しない。ES256K-R は公開鍵 JWK では検証されない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { DIDDocument } from '../../../../identity/did.js';
import { buildDidEthrDocument } from '../../../../identity/ethr/events.js';
import { createDidKey } from '../../../../identity/method-key.js';
import { MethodPkh } from '../../../../identity/pkh/method-pkh.js';
import {
  dataOf,
  directoryFor,
  documentOf,
  genesis,
  makeKey,
  type TestKey,
} from '../../../../identity/plc/__tests__/plc.fixtures.js';
import { MethodPlc } from '../../../../identity/plc/method-plc.js';
import { ethereumAddressOfJwk, verifyEip191Address } from '../../../../keymanager/eip191.js';
import { importPersonaFromDid } from '../../import-persona.js';
import { findHeldKeyInDocument } from '../../key-binding.js';
import { resolvePersonaSigner } from '../../persona-signer.js';
import { signMessageJws, verifyMessageJws } from '../../sign-message.js';
import { ethrDocument, externalKey, NOW, newWorld, stubMethod } from '../fixtures.js';

const SECP = externalKey('secp256k1', 41);
const ADDRESS = ethereumAddressOfJwk(SECP.publicKeyJwk.x, SECP.publicKeyJwk.y) as string;
const PKH_DID = `did:pkh:eip155:1:${ADDRESS}`;
const OTHER_ADDRESS = '0xb9c5714089478a327f09197987f16f9e5d936e8a';

async function reasonOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.DID_KEY_MISMATCH);
    return (error as VericertsError).context?.reason;
  }
  throw new Error('did not throw');
}

async function pkhWorld() {
  const world = await newWorld({ methods: [new MethodPkh()] });
  const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
  return { world, deps };
}

describe('did:pkh の取り込みと署名（ES256K-R）', () => {
  it('保持鍵のアドレスが blockchainAccountId と一致すれば取り込め、署名鍵は ES256K-R で検証メソッドを kid にする', async () => {
    const { world, deps } = await pkhWorld();
    const persona = await importPersonaFromDid(deps, {
      did: PKH_DID,
      key: { external: SECP.privateKeyJwk },
    });
    expect(persona.kid).toBe(`${PKH_DID}#blockchainAccountId`);
    expect(persona.keyType).toBe('secp256k1');
    expect(persona.relationships).toEqual(['authentication', 'assertionMethod']);

    const resolved = await resolvePersonaSigner(world.km, persona, {
      resolver: world.resolver,
      externalKey: SECP.privateKeyJwk,
    });
    expect(resolved.alg).toBe('ES256K-R');
    expect(resolved.kid).toBe(`${PKH_DID}#blockchainAccountId`);
  });

  it('アドレスの大文字小文字（EIP-55）が違っても同じ鍵として扱う', async () => {
    const { deps } = await pkhWorld();
    const checksummed = `0x${ADDRESS.slice(2).toUpperCase()}`;
    const persona = await importPersonaFromDid(deps, {
      did: `did:pkh:eip155:1:${checksummed}`,
      key: { external: SECP.privateKeyJwk },
    });
    expect(persona.kid).toContain('#blockchainAccountId');
  });

  it('アドレスが違う鍵・P-256 / Ed25519 の鍵は取り込めない（2017）', async () => {
    const { world, deps } = await pkhWorld();
    for (const key of [
      externalKey('secp256k1', 42),
      externalKey('P-256', 41),
      externalKey('Ed25519', 41),
    ]) {
      expect(
        await reasonOf(
          importPersonaFromDid(deps, { did: PKH_DID, key: { external: key.privateKeyJwk } }),
        ),
      ).toBe('no_matching_verification_method');
    }
    expect(await world.personas.listPersonas()).toEqual([]);
  });

  it('既定の findHeldKeyInDocument はアドレス鍵を照合しない（明示した経路だけ）', () => {
    const document = new MethodPkh().resolve(PKH_DID) as unknown as Promise<DIDDocument>;
    return document.then((doc) => {
      expect(() => findHeldKeyInDocument(doc, SECP.publicKeyJwk)).toThrow(VericertsError);
      expect(findHeldKeyInDocument(doc, SECP.publicKeyJwk, { allowAddressKey: true }).alg).toBe(
        'ES256K-R',
      );
    });
  });
});

describe('シード由来の secp256k1 鍵（BIP-44）で did:pkh に署名する（ES256K-R）', () => {
  it('ウォレットの Ethereum アドレスの did:pkh を取り込み、署名がそのアドレスの EIP-191 署名になる', async () => {
    const { world, deps } = await pkhWorld();
    const address = (await world.km.deriveKey("m/44'/60'/0'/0/0")).address.toLowerCase();
    const did = `did:pkh:eip155:1:${address}`;
    const persona = await importPersonaFromDid(deps, {
      did,
      key: { seed: { keyType: 'secp256k1', index: 0 } },
    });
    expect(persona.keySource).toBe('seed');
    const { signer, alg } = await resolvePersonaSigner(world.km, persona, {
      resolver: world.resolver,
    });
    expect(alg).toBe('ES256K-R');
    const signingInput = new TextEncoder().encode('header.payload');
    expect(signer.sign(signingInput)).toHaveLength(65);
    expect(verifyEip191Address(signingInput, signer.sign(signingInput), address)).toBe(true);
    // did_signMessage の JWS も同じ鍵・同じアドレスで検証できる。
    const jws = await signMessageJws('seed login', signer);
    expect(
      await verifyMessageJws(jws, { message: 'seed login', resolver: world.resolver }),
    ).toMatchObject({ did, alg: 'ES256K-R' });
  });
});

describe('did:ethr の controller 鍵の署名（ES256K-R）', () => {
  it('controller のアドレスと一致する鍵は取り込め、controller が替わったら署名しない（署名のたびに解決し直す）', async () => {
    const documents: Record<string, DIDDocument> = {};
    const { did, document } = ethrDocument(ADDRESS, []);
    documents[did] = document;
    const world = await newWorld({ methods: [stubMethod('ethr', documents)] });
    const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
    const persona = await importPersonaFromDid(deps, {
      did,
      key: { external: SECP.privateKeyJwk },
    });
    expect(persona.kid).toBe(`${did}#controller`);
    const opts = { resolver: world.resolver, externalKey: SECP.privateKeyJwk };
    expect((await resolvePersonaSigner(world.km, persona, opts)).alg).toBe('ES256K-R');

    // controller を別アドレスへ移した（owner 変更）DID Document。
    documents[did] = buildDidEthrDocument(
      did,
      ADDRESS,
      1,
      {
        ownerChanges: [{ owner: OTHER_ADDRESS, blockNumber: 6, logIndex: 0 }],
        attributeChanges: [],
      },
      NOW,
    );
    expect(await reasonOf(resolvePersonaSigner(world.km, persona, opts))).toBe(
      'no_matching_verification_method',
    );
  });

  it('delegate の公開鍵（publicKeyHex）が一致する DID は従来どおり標準の ES256K（ES256K-R にしない）', async () => {
    const value = `0x${Buffer.from(SECP.publicKey).toString('hex')}`;
    const { did, document } = ethrDocument(OTHER_ADDRESS, [
      { name: 'did/pub/Secp256k1/sigAuth/hex', value },
    ]);
    const world = await newWorld({ methods: [stubMethod('ethr', { [did]: document })] });
    const persona = await importPersonaFromDid(
      { personas: world.personas, keymanager: world.km, resolver: world.resolver },
      { did, key: { external: SECP.privateKeyJwk } },
    );
    const resolved = await resolvePersonaSigner(world.km, persona, {
      resolver: world.resolver,
      externalKey: SECP.privateKeyJwk,
    });
    expect(resolved.alg).toBe('ES256K');
    expect(resolved.kid).not.toContain('#controller');
  });
});

describe('did:plc は署名主体にしない（2017 のまま）', () => {
  it('atproto 鍵と同じ secp256k1 鍵でも、認証用途に載らないので取り込めない', async () => {
    const rotation = makeKey();
    const atproto = { didKey: createDidKey('secp256k1', SECP.publicKey).id } as TestKey;
    const g = await genesis(rotation, dataOf([rotation], atproto));
    const { fetchFn } = directoryFor(g.did, g.entries, documentOf(g.did, g.data));
    const world = await newWorld({ methods: [new MethodPlc({ fetchFn })] });
    const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
    const document = await world.resolver.resolve(g.did);
    // アドレス鍵の許可（ES256K-R）は plc に効かない: 検証メソッドは公開鍵を持つが認証用途に載っていない。
    expect(() =>
      findHeldKeyInDocument(document, SECP.publicKeyJwk, { allowAddressKey: true }),
    ).toThrow(VericertsError);
    expect(
      await reasonOf(
        importPersonaFromDid(deps, { did: g.did, key: { external: SECP.privateKeyJwk } }),
      ),
    ).toBe('relationship_not_granted');
    expect(await world.personas.listPersonas()).toEqual([]);
  });
});
