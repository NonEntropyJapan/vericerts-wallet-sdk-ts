/**
 * did:pkh の ES256K-R（標準外の例外）を使える署名経路は、自分の DID の VP / VC / id_token /
 * signMessage だけ。OID4VCI の proof・EUDI・Status・GDPR ログ・AA などが使う標準の署名鍵の解決は `1030` で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { externalKey, newWorld } from '../../internal/credential/did-signing/__tests__/fixtures.js';
import { importPersonaFromDid } from '../../internal/credential/did-signing/import-persona.js';
import { ErrorCodes } from '../../internal/errors.js';
import { MethodPkh } from '../../internal/identity/pkh/method-pkh.js';
import { ethereumAddressOfJwk } from '../../internal/keymanager/eip191.js';
import {
  resolveActiveHolder,
  resolveActiveOwnDidHolder,
  resolveActiveSigner,
  resolveSignerForDid,
} from '../setup.js';

const KEY = externalKey('secp256k1', 55);
const DID = `did:pkh:eip155:1:${ethereumAddressOfJwk(KEY.publicKeyJwk.x, KEY.publicKeyJwk.y)}`;

async function activePkhPersona() {
  const world = await newWorld({ methods: [new MethodPkh()] });
  const persona = await importPersonaFromDid(
    { personas: world.personas, keymanager: world.km, resolver: world.resolver },
    { did: DID, key: { external: KEY.privateKeyJwk } },
  );
  await world.personas.setActivePersona(persona.id);
  const signing = { resolver: world.resolver, externalKeyProvider: async () => KEY.privateKeyJwk };
  return { world, signing };
}

const NOT_ALLOWED = {
  code: ErrorCodes.UNSUPPORTED_ALGORITHM,
  context: { reason: 'es256k_r_not_allowed' },
};

describe('ES256K-R を使える署名経路', () => {
  it('自分の DID の VP / VC（resolveActiveOwnDidHolder・resolveSignerForDid）は ES256K-R の署名鍵と kid を得る', async () => {
    const { world, signing } = await activePkhPersona();
    const holder = await resolveActiveOwnDidHolder(world.personas, world.km, signing);
    expect(holder).toMatchObject({ did: DID, keyId: `${DID}#blockchainAccountId` });
    expect(holder.signer.alg).toBe('ES256K-R');
    const forDid = await resolveSignerForDid(world.personas, world.km, DID, signing);
    expect(forDid).toMatchObject({ alg: 'ES256K-R', kid: `${DID}#blockchainAccountId` });
  });

  it('それ以外の経路（resolveActiveHolder・resolveActiveSigner）は標準の alg だけで、ES256K-R は 1030 で拒否する', async () => {
    const { world, signing } = await activePkhPersona();
    await expect(resolveActiveHolder(world.personas, world.km, signing)).rejects.toMatchObject(
      NOT_ALLOWED,
    );
    await expect(resolveActiveSigner(world.personas, world.km, signing)).rejects.toMatchObject(
      NOT_ALLOWED,
    );
  });

  it('標準の alg のペルソナ（新規作成の P-256）は従来どおりどの経路でも使える', async () => {
    const world = await newWorld();
    const persona = await world.personas.createPersona({ method: 'key' });
    await world.personas.setActivePersona(persona.id);
    const holder = await resolveActiveHolder(world.personas, world.km);
    expect(holder.signer).toMatchObject({ alg: 'ES256', kid: persona.kid });
    const signer = await resolveActiveSigner(world.personas, world.km);
    expect(signer.signer.alg).toBe('ES256');
    expect(Object.hasOwn(signer.signer, 'kid')).toBe(false);
  });
});
