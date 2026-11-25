/**
 * 既存 DID の取り込みで保存されるメタデータ。
 *
 * シード由来の鍵（index 指定）と外部の秘密鍵 JWK のどちらでも取り込め、メタデータに秘密鍵を含めない。
 * シード由来の取り込みは seed 差し替えの検知（`matchesSeed`）の対象で、外部鍵は seed に依存しない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { buildDidWebDocument } from '../did-document-export.js';
import { importPersonaFromDid } from '../import-persona.js';
import { externalKey, newWorld } from './fixtures.js';

const DID = 'did:web:example.com';
const URL = 'https://example.com/.well-known/did.json';
const OTHER_MNEMONIC =
  'legal winner thank year wave sausage worth useful legal winner thank yellow';

describe('importPersonaFromDid のメタデータ', () => {
  it('シード由来 secp256k1: index・アドレス・kid・検証関係を保存し、秘密鍵は含まない', async () => {
    const probe = await newWorld();
    const seedKey = await probe.km.deriveKey("m/44'/60'/9'/0/0");
    const publicKeyJwk = probe.km.getCredentialSigner(seedKey.id).publicKeyJwk;
    const world = await newWorld({
      files: { [URL]: buildDidWebDocument({ did: DID, publicKeyJwk }).document },
    });
    const persona = await importPersonaFromDid(
      { personas: world.personas, keymanager: world.km, resolver: world.resolver },
      { did: DID, key: { seed: { keyType: 'secp256k1', index: 9 } }, label: '会社' },
    );
    expect(persona).toMatchObject({
      id: DID,
      did: DID,
      index: 9,
      derivationPath: "m/44'/60'/9'/0/0",
      address: seedKey.address,
      method: 'web',
      keyType: 'secp256k1',
      keySource: 'seed',
      kid: `${DID}#key-1`,
      relationships: ['authentication', 'assertionMethod'],
      label: '会社',
    });
    expect(JSON.stringify(persona)).not.toContain('"d"');
    expect(await world.personas.getPersona(DID)).toEqual(persona);

    expect(await world.personas.matchesSeed(persona)).toBe(true);
    const other = await newWorld({ mnemonic: OTHER_MNEMONIC });
    expect(await other.personas.matchesSeed(persona)).toBe(false);
  });

  it('シード由来の取り込みで DID Document の鍵が別の index の鍵なら 2017 で保存しない', async () => {
    const probe = await newWorld();
    const wrong = await probe.km.deriveP256Key("m/9256'/0'/1'/0'");
    const world = await newWorld({
      files: {
        [URL]: buildDidWebDocument({
          did: DID,
          publicKeyJwk: probe.km.getCredentialSigner(wrong.id).publicKeyJwk,
        }).document,
      },
    });
    await expect(
      importPersonaFromDid(
        { personas: world.personas, keymanager: world.km, resolver: world.resolver },
        { did: DID, key: { seed: { keyType: 'P-256', index: 0 } } },
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.DID_KEY_MISMATCH });
    expect(await world.personas.listPersonas()).toEqual([]);
  });

  it('外部鍵: 導出パスは空・index は並び順用の採番で、seed に依存しない（matchesSeed は常に true）', async () => {
    const key = externalKey('Ed25519', 71);
    const world = await newWorld({
      files: { [URL]: buildDidWebDocument({ did: DID, publicKeyJwk: key.publicKeyJwk }).document },
    });
    await world.personas.createPersona();
    const persona = await importPersonaFromDid(
      { personas: world.personas, keymanager: world.km, resolver: world.resolver },
      { did: DID, key: { external: key.privateKeyJwk } },
    );
    expect(persona).toMatchObject({
      index: 1,
      derivationPath: '',
      keySource: 'external',
      keyType: 'Ed25519',
    });
    expect(persona.address).toBeUndefined();
    const other = await newWorld({ mnemonic: OTHER_MNEMONIC });
    expect(await other.personas.matchesSeed(persona)).toBe(true);
  });

  it('秘密鍵 JWK が不正なら保存せず 1003', async () => {
    const world = await newWorld();
    await expect(
      importPersonaFromDid(
        { personas: world.personas, keymanager: world.km, resolver: world.resolver },
        { did: DID, key: { external: { kty: 'EC', crv: 'P-256', d: 'AAAA' } } },
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.INVALID_PRIVATE_KEY });
    expect(await world.personas.listPersonas()).toEqual([]);
  });
});

describe('importPersonaFromDid: 鍵の指定が無い入力', () => {
  it.each([
    ['undefined', undefined],
    ['null', null],
    ['文字列', 'secret'],
  ])('key が %s なら生の TypeError ではなく 1003 で拒否し、何も保存しない', async (_name, key) => {
    const world = await newWorld();
    await expect(
      importPersonaFromDid(
        { personas: world.personas, keymanager: world.km, resolver: world.resolver },
        { did: DID, key } as unknown as Parameters<typeof importPersonaFromDid>[1],
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.INVALID_PRIVATE_KEY });
    expect(await world.personas.listPersonas()).toEqual([]);
  });
});
