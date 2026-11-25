/**
 * 取り込んだ DID の記録が欠けていても、DID Document との照合を迂回して署名しない（fail-closed）。
 *
 * 作成した DID（key / jwk / peer をシードから導出）だけが、DID が公開鍵を自己記述するので再照合なしで署名できる。
 * `method` が key / jwk / peer 以外、または `keySource: 'external'` で `relationships` が無い記録は、検証関係の確認も
 * DID Document の再解決もできないので、署名鍵を返さず `2017` で拒否する（Resolver があっても同じ）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PersonaMetadata } from '../../../persona/types.js';
import { buildDidWebDocument } from '../did-document-export.js';
import { importPersonaFromDid } from '../import-persona.js';
import { resolvePersonaSigner } from '../persona-signer.js';
import { externalKey, newWorld } from './fixtures.js';

const KEY = externalKey('P-256', 51);
const DID = 'did:web:example.com';
const FILE_URL = 'https://example.com/.well-known/did.json';

/** 取り込み直後の記録から `relationships` だけを落とした（壊れた・改ざんされた）記録。 */
function withoutRelationships(persona: PersonaMetadata): PersonaMetadata {
  const { relationships: _dropped, ...rest } = persona;
  return rest;
}

async function importedWebPersona() {
  const world = await newWorld({
    files: {
      [FILE_URL]: buildDidWebDocument({ did: DID, publicKeyJwk: KEY.publicKeyJwk }).document,
    },
  });
  const persona = await importPersonaFromDid(
    { personas: world.personas, keymanager: world.km, resolver: world.resolver },
    { did: DID, key: { external: KEY.privateKeyJwk } },
  );
  return { world, persona };
}

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

describe('resolvePersonaSigner の fail-closed', () => {
  it('外部鍵の取り込み記録（did:web）が relationships を欠くと、鍵と Resolver があっても署名鍵を返さない（2017）', async () => {
    const { world, persona } = await importedWebPersona();
    // 対照: 記録が揃っていれば署名鍵を返す。
    const opts = { resolver: world.resolver, externalKey: KEY.privateKeyJwk };
    expect((await resolvePersonaSigner(world.km, persona, opts)).did).toBe(DID);

    expect(
      await reasonOf(resolvePersonaSigner(world.km, withoutRelationships(persona), opts)),
    ).toBe('relationships_missing');
  });

  it('シード由来で取り込んだ did:web の記録が relationships を欠いても署名鍵を返さない（Resolver の有無に依らない）', async () => {
    const probe = await newWorld();
    const seedKey = await probe.km.deriveP256Key("m/9256'/0'/3'/0'");
    const world = await newWorld({
      files: {
        [FILE_URL]: buildDidWebDocument({
          did: DID,
          publicKeyJwk: probe.km.getCredentialSigner(seedKey.id).publicKeyJwk,
        }).document,
      },
    });
    const persona = await importPersonaFromDid(
      { personas: world.personas, keymanager: world.km, resolver: world.resolver },
      { did: DID, key: { seed: { keyType: 'P-256', index: 3 } } },
    );
    const broken = withoutRelationships(persona);
    expect(await reasonOf(resolvePersonaSigner(world.km, broken))).toBe('relationships_missing');
    expect(
      await reasonOf(resolvePersonaSigner(world.km, broken, { resolver: world.resolver })),
    ).toBe('relationships_missing');
  });

  it('作成した DID（key / jwk / peer）は relationships が無くても従来どおり署名できる', async () => {
    const world = await newWorld();
    for (const method of ['key', 'jwk', 'peer'] as const) {
      const persona = await world.personas.createPersona({ method, keyType: 'P-256' });
      expect(persona.relationships).toBeUndefined();
      expect((await resolvePersonaSigner(world.km, persona)).did).toBe(persona.did);
    }
  });
});

describe('resolvePersonaSigner: 再照合なしで署名できる記録は DID が method と一致するものだけ', () => {
  it('method=key の記録の did が別メソッド（did:web）だと、relationships が無くても署名鍵を返さない（2017）', async () => {
    const world = await newWorld();
    const persona = await world.personas.createPersona({ method: 'key', keyType: 'P-256' });
    // 対照: 記録が揃っていれば署名鍵を返す。
    expect((await resolvePersonaSigner(world.km, persona)).did).toBe(persona.did);

    const mismatched: PersonaMetadata = { ...persona, did: 'did:web:attacker.example' };
    expect(await reasonOf(resolvePersonaSigner(world.km, mismatched))).toBe(
      'relationships_missing',
    );
  });

  it.each([
    ['key', 'did:jwk:'],
    ['jwk', 'did:key:'],
    ['peer', 'did:key:'],
  ] as const)('method=%s の記録の did が %s で始まると署名鍵を返さない', async (method, prefix) => {
    const world = await newWorld();
    const persona = await world.personas.createPersona({ method, keyType: 'P-256' });
    const mismatched: PersonaMetadata = {
      ...persona,
      did: `${prefix}${persona.did.slice(persona.did.lastIndexOf(':') + 1)}`,
    };
    expect(await reasonOf(resolvePersonaSigner(world.km, mismatched))).toBe(
      'relationships_missing',
    );
  });
});
