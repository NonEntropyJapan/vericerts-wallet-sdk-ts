/**
 * 保持鍵と DID Document の照合（fail-closed）。
 *
 * - 一致する検証メソッドが無い / 検証関係に列挙されていない / 失効 / 文書 id 不一致は `2017`。
 * - 公開鍵の表現（JWK / multibase / hex / base58）は JWK に揃えて比較する。
 * - 取り込んだ DID は署名のたびに解決し直し、DID Document の鍵が替わったら署名しない。
 * - did:pkh / did:ethr の controller（`blockchainAccountId` のみ）は、アドレスが違う鍵を取り込めない（一致は eip191/）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { DIDDocument } from '../../../identity/did.js';
import { createDidKey } from '../../../identity/method-key.js';
import { MethodPkh } from '../../../identity/pkh/method-pkh.js';
import {
  dataOf,
  directoryFor,
  documentOf,
  genesis,
  makeKey,
  type TestKey,
} from '../../../identity/plc/__tests__/plc.fixtures.js';
import { MethodPlc } from '../../../identity/plc/method-plc.js';
import { buildDidCoreDocument, buildDidWebDocument } from '../did-document-export.js';
import { importPersonaFromDid } from '../import-persona.js';
import { findHeldKeyInDocument, verifyHeldKeyAgainstDid } from '../key-binding.js';
import { resolvePersonaSigner } from '../persona-signer.js';
import { ethrDocument, externalKey, newWorld, stubMethod } from './fixtures.js';

const KEY_A = externalKey('P-256', 31);
const KEY_B = externalKey('P-256', 32);
const DID = 'did:web:example.com';
const FILE_URL = 'https://example.com/.well-known/did.json';

async function reasonOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.DID_KEY_MISMATCH);
    return (error as VericertsError).context?.reason as string;
  }
  throw new Error('did not throw');
}

function reasonOfSync(run: () => unknown): string | undefined {
  try {
    run();
  } catch (error) {
    expect((error as VericertsError).code).toBe(ErrorCodes.DID_KEY_MISMATCH);
    return (error as VericertsError).context?.reason as string;
  }
  throw new Error('did not throw');
}

describe('findHeldKeyInDocument', () => {
  const document = buildDidCoreDocument({ did: DID, publicKeyJwk: KEY_A.publicKeyJwk });

  it('一致した検証メソッドの id・alg・検証関係を返す', () => {
    const match = findHeldKeyInDocument(document, KEY_A.publicKeyJwk);
    expect(match.kid).toBe(`${DID}#key-1`);
    expect(match.alg).toBe('ES256');
    expect(match.relationships).toEqual(['authentication', 'assertionMethod']);
  });

  it('別の鍵なら no_matching_verification_method', () => {
    expect(reasonOfSync(() => findHeldKeyInDocument(document, KEY_B.publicKeyJwk))).toBe(
      'no_matching_verification_method',
    );
  });

  it('keyAgreement にしか載っていない鍵は relationship_not_granted', () => {
    const agreementOnly: DIDDocument = {
      ...document,
      authentication: [],
      assertionMethod: [],
      keyAgreement: [`${DID}#key-1`],
    };
    expect(reasonOfSync(() => findHeldKeyInDocument(agreementOnly, KEY_A.publicKeyJwk))).toBe(
      'relationship_not_granted',
    );
  });

  it('要求した検証関係に載っていなければ relationship_not_granted（authentication のみの鍵で assertionMethod を要求）', () => {
    const authOnly: DIDDocument = { ...document, assertionMethod: [] };
    expect(findHeldKeyInDocument(authOnly, KEY_A.publicKeyJwk).relationships).toEqual([
      'authentication',
    ]);
    expect(
      reasonOfSync(() =>
        findHeldKeyInDocument(authOnly, KEY_A.publicKeyJwk, { relationship: 'assertionMethod' }),
      ),
    ).toBe('relationship_not_granted');
  });

  it('失効した DID は deactivated', () => {
    expect(
      reasonOfSync(() =>
        findHeldKeyInDocument({ ...document, deactivated: true }, KEY_A.publicKeyJwk),
      ),
    ).toBe('deactivated');
  });

  it('相対 id（#key-1）の参照と kid 限定を解決する', () => {
    const relative: DIDDocument = {
      ...document,
      authentication: ['#key-1'],
      assertionMethod: ['#key-1'],
    };
    expect(findHeldKeyInDocument(relative, KEY_A.publicKeyJwk, { kid: '#key-1' }).kid).toBe(
      `${DID}#key-1`,
    );
    expect(
      reasonOfSync(() => findHeldKeyInDocument(relative, KEY_A.publicKeyJwk, { kid: '#other' })),
    ).toBe('no_matching_verification_method');
  });

  it('対応しない鍵種（RSA）の保持鍵は 1030', () => {
    expect(() => findHeldKeyInDocument(document, { kty: 'RSA', n: 'x', e: 'AQAB' })).toThrow(
      new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM),
    );
  });
});

describe('verifyHeldKeyAgainstDid / 取り込み', () => {
  it('解決した DID Document の id が要求した DID と違えば document_id_mismatch', async () => {
    const wrong = buildDidCoreDocument({
      did: 'did:web:evil.example',
      publicKeyJwk: KEY_A.publicKeyJwk,
    });
    const world = await newWorld({ methods: [stubMethod('web', { [DID]: wrong })] });
    expect(await reasonOf(verifyHeldKeyAgainstDid(world.resolver, DID, KEY_A.publicKeyJwk))).toBe(
      'document_id_mismatch',
    );
  });

  it('DID Document に保持鍵が無ければ取り込めず、何も保存しない', async () => {
    const files = {
      [FILE_URL]: buildDidWebDocument({ did: DID, publicKeyJwk: KEY_B.publicKeyJwk }).document,
    };
    const world = await newWorld({ files });
    const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
    expect(
      await reasonOf(
        importPersonaFromDid(deps, { did: DID, key: { external: KEY_A.privateKeyJwk } }),
      ),
    ).toBe('no_matching_verification_method');
    expect(await world.personas.listPersonas()).toEqual([]);
  });

  it('did:ethr の controller（blockchainAccountId のみ）は、アドレスが違う鍵を取り込めない（一致は eip191/）', async () => {
    const { did, document } = ethrDocument('0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb', []);
    const world = await newWorld({ methods: [stubMethod('ethr', { [did]: document })] });
    const secp = externalKey('secp256k1', 33);
    const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
    expect(
      await reasonOf(importPersonaFromDid(deps, { did, key: { external: secp.privateKeyJwk } })),
    ).toBe('no_matching_verification_method');
  });

  it('did:pkh（blockchainAccountId のみ）は、アドレスが違う鍵を取り込めない（一致は eip191/）', async () => {
    const world = await newWorld({ methods: [new MethodPkh()] });
    const secp = externalKey('secp256k1', 34);
    const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
    const did = 'did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a';
    expect(
      await reasonOf(importPersonaFromDid(deps, { did, key: { external: secp.privateKeyJwk } })),
    ).toBe('no_matching_verification_method');
  });

  it('did:plc は既定の DID Document に authentication / assertionMethod が無く、atproto 鍵と同じ鍵でも取り込めない（2017）', async () => {
    const held = externalKey('P-256', 36);
    const rotation = makeKey();
    const atproto = { didKey: createDidKey('P-256', held.publicKey).id } as TestKey;
    const g = await genesis(rotation, dataOf([rotation], atproto));
    const { fetchFn } = directoryFor(g.did, g.entries, documentOf(g.did, g.data));
    const world = await newWorld({ methods: [new MethodPlc({ fetchFn })] });
    // 文書には保持鍵と同じ公開鍵の検証メソッド（#atproto）がある。署名に使える検証関係へ載っていないので拒否する。
    expect((await world.resolver.resolve(g.did)).verificationMethod).toHaveLength(1);
    const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
    expect(
      await reasonOf(
        importPersonaFromDid(deps, { did: g.did, key: { external: held.privateKeyJwk } }),
      ),
    ).toBe('relationship_not_granted');
    expect(await world.personas.listPersonas()).toEqual([]);
  });

  it('同じ DID を二度取り込むと 2008、未対応メソッド・形式不正はそれぞれ 2002 / 2001', async () => {
    const files = {
      [FILE_URL]: buildDidWebDocument({ did: DID, publicKeyJwk: KEY_A.publicKeyJwk }).document,
    };
    const world = await newWorld({ files });
    const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
    const input = { did: DID, key: { external: KEY_A.privateKeyJwk } } as const;
    await importPersonaFromDid(deps, input);
    await expect(importPersonaFromDid(deps, input)).rejects.toMatchObject({
      code: ErrorCodes.PERSONA_ALREADY_EXISTS,
    });
    await expect(
      importPersonaFromDid(deps, {
        did: 'did:unknown:abc',
        key: { external: KEY_A.privateKeyJwk },
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.METHOD_NOT_SUPPORTED });
    await expect(
      importPersonaFromDid(deps, { did: 'not-a-did', key: { external: KEY_A.privateKeyJwk } }),
    ).rejects.toMatchObject({ code: ErrorCodes.INVALID_DID });
  });

  it('署名のたびに DID を解決し直す: DID Document の鍵が替わったら署名しない（キャッシュしない）', async () => {
    const files: Record<string, unknown> = {
      [FILE_URL]: buildDidWebDocument({ did: DID, publicKeyJwk: KEY_A.publicKeyJwk }).document,
    };
    const world = await newWorld({ files });
    const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
    const persona = await importPersonaFromDid(deps, {
      did: DID,
      key: { external: KEY_A.privateKeyJwk },
    });
    const opts = { resolver: world.resolver, externalKey: KEY_A.privateKeyJwk };

    expect((await resolvePersonaSigner(world.km, persona, opts)).did).toBe(DID);
    // 鍵ローテーション（DID Document 側だけが B に替わった）。
    files[FILE_URL] = buildDidWebDocument({ did: DID, publicKeyJwk: KEY_B.publicKeyJwk }).document;
    expect(await reasonOf(resolvePersonaSigner(world.km, persona, opts))).toBe(
      'no_matching_verification_method',
    );
  });

  it('取り込んだ DID は Resolver なし・外部鍵なしでは署名鍵を返さない（2007）、確認していない検証関係も拒否する', async () => {
    const authOnly: DIDDocument = {
      ...buildDidWebDocument({ did: DID, publicKeyJwk: KEY_A.publicKeyJwk }).document,
      assertionMethod: [],
    };
    const world = await newWorld({ files: { [FILE_URL]: authOnly } });
    const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
    const persona = await importPersonaFromDid(deps, {
      did: DID,
      key: { external: KEY_A.privateKeyJwk },
    });
    expect(persona.relationships).toEqual(['authentication']);

    await expect(
      resolvePersonaSigner(world.km, persona, { externalKey: KEY_A.privateKeyJwk }),
    ).rejects.toMatchObject({ code: ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE });
    await expect(
      resolvePersonaSigner(world.km, persona, { resolver: world.resolver }),
    ).rejects.toMatchObject({ code: ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE });
    expect(
      await reasonOf(
        resolvePersonaSigner(world.km, persona, {
          relationship: 'assertionMethod',
          resolver: world.resolver,
          externalKey: KEY_A.privateKeyJwk,
        }),
      ),
    ).toBe('relationship_not_granted');
  });

  it('外部鍵の取り違え（ペルソナは P-256 だが渡した秘密鍵は secp256k1）は署名鍵を返さない', async () => {
    const files = {
      [FILE_URL]: buildDidWebDocument({ did: DID, publicKeyJwk: KEY_A.publicKeyJwk }).document,
    };
    const world = await newWorld({ files });
    const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
    const persona = await importPersonaFromDid(deps, {
      did: DID,
      key: { external: KEY_A.privateKeyJwk },
    });
    await expect(
      resolvePersonaSigner(world.km, persona, {
        resolver: world.resolver,
        externalKey: externalKey('secp256k1', 35).privateKeyJwk,
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE });
  });
});
