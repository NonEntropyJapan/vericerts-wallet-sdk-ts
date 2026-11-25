/**
 * `Object.prototype` 汚染下でも、旧レコード（追加項目の欠落）と省略したオプションが継承値で埋まらないこと。
 *
 * 汚染で `keySource` / `relationships` / `keyType` / `kid` が差し替わると、別の鍵種・別の検証メソッドで署名したり、
 * 取り込んだ DID の照合（Resolver 必須）を迂回したりできてしまう。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { buildDidWebDocument } from '../did-document-export.js';
import { importPersonaFromDid } from '../import-persona.js';
import { resolvePersonaSigner } from '../persona-signer.js';
import { signMessageJws, verifyMessageJws } from '../sign-message.js';
import { externalKey, newWorld } from './fixtures.js';

const POLLUTION: Record<string, unknown> = {
  keyType: 'Ed25519',
  keySource: 'external',
  relationships: ['assertionMethod'],
  kid: 'did:evil#1',
  method: 'web',
  relationship: 'assertionMethod',
  resolver: undefined,
  externalKey: { kty: 'OKP', crv: 'Ed25519', d: 'AA' },
  expectedDid: 'did:evil',
  message: 'evil',
  external: { kty: 'OKP', crv: 'Ed25519', d: 'AA' },
  seed: { keyType: 'secp256k1', index: 99 },
  index: 99,
  label: 'evil',
};

async function withPollution<T>(run: () => Promise<T>): Promise<T> {
  const proto = Object.prototype as Record<string, unknown>;
  for (const [key, value] of Object.entries(POLLUTION)) {
    Object.defineProperty(proto, key, { value, configurable: true, writable: true });
  }
  try {
    return await run();
  } finally {
    for (const key of Object.keys(POLLUTION)) {
      delete proto[key];
    }
  }
}

describe('proto 汚染', () => {
  it('旧レコード（did:key + secp256k1）は汚染下でも従来どおり ES256K で署名し、自分の DID を検証できる', async () => {
    const world = await newWorld();
    const persona = await world.personas.restoreLegacyPersona({ index: 0 });
    const kidBefore = `${persona.did}#${persona.did.slice('did:key:'.length)}`;

    const jws = await withPollution(async () => {
      const resolved = await resolvePersonaSigner(world.km, persona);
      expect(resolved.alg).toBe('ES256K');
      expect(resolved.kid).toBe(kidBefore);
      return signMessageJws('m', resolved.signer);
    });
    const verified = await verifyMessageJws(jws, { message: 'm', resolver: world.resolver });
    expect(verified).toMatchObject({ did: persona.did, kid: kidBefore, alg: 'ES256K' });
    // 汚染下の検証でも期待値（expectedDid）は省略扱いで、メッセージは own 限定で読む（継承値に差し替わらない）。
    await withPollution(async () => {
      expect((await verifyMessageJws(jws, { message: 'm', resolver: world.resolver })).did).toBe(
        persona.did,
      );
    });
  });

  it('message を省略した検証は、汚染された Object.prototype.message を拾わず 3010 で拒否する', async () => {
    const world = await newWorld();
    const persona = await world.personas.createPersona({ method: 'key', keyType: 'P-256' });
    const { signer } = await resolvePersonaSigner(world.km, persona);
    const jws = await signMessageJws('evil', signer);
    const opts = { resolver: world.resolver } as unknown as Parameters<typeof verifyMessageJws>[1];
    await withPollution(async () => {
      await expect(verifyMessageJws(jws, opts)).rejects.toMatchObject({
        code: ErrorCodes.SIG_INVALID,
      });
    });
  });

  it('汚染下で作成した P-256 ペルソナも、汚染のない世界の作成と同じ結果になる', async () => {
    const clean = await (await newWorld()).personas.createPersona({ method: 'jwk' });
    const polluted = await withPollution(async () =>
      (await newWorld()).personas.createPersona({ method: 'jwk' }),
    );
    expect(polluted).toEqual(clean);
  });

  const DID = 'did:web:example.com';
  const URL = 'https://example.com/.well-known/did.json';
  const KEY = externalKey('P-256', 61);

  it('取り込み: 汚染された external / index / kid / label / seed を拾わず、渡した外部鍵と自動採番で取り込む', async () => {
    const world = await newWorld({
      files: { [URL]: buildDidWebDocument({ did: DID, publicKeyJwk: KEY.publicKeyJwk }).document },
    });
    await world.personas.createPersona();
    const persona = await withPollution(() =>
      importPersonaFromDid(
        { personas: world.personas, keymanager: world.km, resolver: world.resolver },
        { did: DID, key: { external: KEY.privateKeyJwk } },
      ),
    );
    expect(persona).toMatchObject({
      did: DID,
      keySource: 'external',
      keyType: 'P-256',
      kid: `${DID}#key-1`,
      index: 1,
      relationships: ['authentication', 'assertionMethod'],
    });
    expect(persona.label).toBeUndefined();
    expect(persona.publicKeyJwk).toEqual(KEY.publicKeyJwk);
  });

  it('取り込み: seed 指定のとき、汚染された external に差し替わらず、シード由来の鍵（指定 index）を保持する', async () => {
    const probe = await newWorld();
    const seedKey = await probe.km.deriveP256Key("m/9256'/0'/5'/0'");
    const world = await newWorld({
      files: {
        [URL]: buildDidWebDocument({
          did: DID,
          publicKeyJwk: probe.km.getCredentialSigner(seedKey.id).publicKeyJwk,
        }).document,
      },
    });
    const persona = await withPollution(() =>
      importPersonaFromDid(
        { personas: world.personas, keymanager: world.km, resolver: world.resolver },
        { did: DID, key: { seed: { keyType: 'P-256', index: 5 } } },
      ),
    );
    expect(persona).toMatchObject({ keySource: 'seed', keyType: 'P-256', index: 5 });
  });

  it('取り込み: key に external も seed も無ければ、汚染された external / seed があっても 1003 で保存しない', async () => {
    const world = await newWorld({
      files: { [URL]: buildDidWebDocument({ did: DID, publicKeyJwk: KEY.publicKeyJwk }).document },
    });
    await expect(
      withPollution(() =>
        importPersonaFromDid(
          { personas: world.personas, keymanager: world.km, resolver: world.resolver },
          { did: DID, key: {} as never },
        ),
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.INVALID_PRIVATE_KEY });
    expect(await world.personas.listPersonas()).toEqual([]);
  });

  it('取り込み: seed に keyType / index が無ければ、汚染された値で導出せず 1040 で拒否する', async () => {
    const world = await newWorld();
    await expect(
      withPollution(() =>
        importPersonaFromDid(
          { personas: world.personas, keymanager: world.km, resolver: world.resolver },
          { did: DID, key: { seed: {} as never } },
        ),
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.DERIVATION_PATH_INVALID });
  });

  it('署名: keySource が external で relationships を欠く記録は、汚染された relationships で補われず 2017 で拒否する', async () => {
    const world = await newWorld({
      files: { [URL]: buildDidWebDocument({ did: DID, publicKeyJwk: KEY.publicKeyJwk }).document },
    });
    const persona = await importPersonaFromDid(
      { personas: world.personas, keymanager: world.km, resolver: world.resolver },
      { did: DID, key: { external: KEY.privateKeyJwk } },
    );
    const { relationships: _dropped, ...broken } = persona;
    await expect(
      withPollution(() =>
        resolvePersonaSigner(world.km, broken, {
          resolver: world.resolver,
          externalKey: KEY.privateKeyJwk,
        }),
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.DID_KEY_MISMATCH });
  });
});
