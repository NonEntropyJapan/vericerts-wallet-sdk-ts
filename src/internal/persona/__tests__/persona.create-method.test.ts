/**
 * PersonaManager の DID メソッド / 鍵種指定の作成と、旧レコードの後方互換。
 *
 * - 新規に作成する DID は常に P-256（SLIP-0010 `m/9256'/0'/<index>'/0'`）。`createPersona()`（`method` / `keyType` 省略）も
 *   did:key + P-256 で、kid（検証メソッド id）を持ち、EOA アドレスは持たない。secp256k1 の作成は 1030。
 * - 既存の旧レコード（`method` / `keyType` を持たない did:key + secp256k1）は、読み書き・seed 照合と、既存データ専用の
 *   `restoreLegacyPersona`（BIP-32 `m/44'/60'/<index>'/0/0`、メタデータに `method` / `keyType` を載せない）で扱える。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { resolveDidJwk } from '../../identity/jwk/method-jwk.js';
import { createDidKey } from '../../identity/method-key.js';
import { resolveDidPeer } from '../../identity/peer/method-peer.js';
import { KeyManager } from '../../keymanager/keymanager.js';
import { decodeMetadata } from '../codec.js';
import { PersonaManager } from '../persona.js';

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const OTHER_MNEMONIC =
  'legal winner thank year wave sausage worth useful legal winner thank yellow';

async function manager(mnemonic = MNEMONIC, storage = new MemoryStorage()) {
  const km = new KeyManager();
  await km.importMnemonic(mnemonic);
  let tick = 1;
  return { km, storage, personas: new PersonaManager(km, storage, createDidKey, () => tick++) };
}

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
  } catch (error) {
    return error instanceof VericertsError ? error.code : undefined;
  }
  return undefined;
}

describe('createPersona: 既定は P-256（新規に作る DID は P-256 のみ）', () => {
  it('引数なしは did:key + P-256、SLIP-0010 パス、EOA アドレスなし、kid を持つ', async () => {
    const { personas } = await manager();
    const persona = await personas.createPersona();
    expect(persona.derivationPath).toBe("m/9256'/0'/0'/0'");
    expect(persona.address).toBeUndefined();
    expect(persona.did.startsWith('did:key:zDn')).toBe(true);
    expect(persona.method).toBe('key');
    expect(persona.keyType).toBe('P-256');
    expect(persona.kid).toBe(`${persona.did}#${persona.did.slice('did:key:'.length)}`);
  });

  it('ニーモニックだけの復元で index 0 の DID が同一（P-256 の決定的導出）', async () => {
    const first = await (await manager()).personas.createPersona({ index: 0 });
    const restored = await (await manager()).personas.createPersona();
    expect(restored.did).toBe(first.did);
  });

  it('label / index だけの指定でも P-256（secp256k1 には戻らない）', async () => {
    const { personas } = await manager();
    const persona = await personas.createPersona({ index: 3, label: 'x' });
    expect(persona.derivationPath).toBe("m/9256'/0'/3'/0'");
    expect(persona.keyType).toBe('P-256');
  });

  it('secp256k1 の作成は 1030（どの method でも。ペルソナは作られない）', async () => {
    const { personas } = await manager();
    for (const method of [undefined, 'key', 'peer'] as const) {
      const options = { keyType: 'secp256k1', ...(method === undefined ? {} : { method }) };
      const invalid = options as unknown as Parameters<PersonaManager['createPersona']>[0];
      expect(await codeOf(personas.createPersona(invalid))).toBe(ErrorCodes.UNSUPPORTED_ALGORITHM);
    }
    expect(await personas.listPersonas()).toEqual([]);
  });
});

describe('restoreLegacyPersona: 既存の旧レコード（did:key + secp256k1）の復元専用', () => {
  it('BIP-32 パス・アドレス付き・method / keyType / kid を持たない旧レコードと同形で作り直す', async () => {
    const { personas } = await manager();
    const persona = await personas.restoreLegacyPersona({ index: 0, label: 'old' });
    expect(persona.derivationPath).toBe("m/44'/60'/0'/0/0");
    expect(persona.address).toBe('0x9858EfFD232B4033E47d90003D41EC34EcaEda94');
    expect(persona.did.startsWith('did:key:zQ3s')).toBe(true);
    for (const key of ['method', 'keyType', 'keySource', 'kid', 'relationships', 'publicKeyJwk']) {
      expect(Object.hasOwn(persona, key)).toBe(false);
    }
    expect(await personas.getPersona(persona.id)).toEqual(persona);
  });

  it('同じ index の二重復元は 2008、不正な index / label は 1040', async () => {
    const { personas } = await manager();
    await personas.restoreLegacyPersona({ index: 1 });
    expect(await codeOf(personas.restoreLegacyPersona({ index: 1 }))).toBe(
      ErrorCodes.PERSONA_ALREADY_EXISTS,
    );
    expect(await codeOf(personas.restoreLegacyPersona({ index: -1 }))).toBe(
      ErrorCodes.DERIVATION_PATH_INVALID,
    );
    const badLabel = { index: 2, label: 5 } as unknown as Parameters<
      PersonaManager['restoreLegacyPersona']
    >[0];
    expect(await codeOf(personas.restoreLegacyPersona(badLabel))).toBe(
      ErrorCodes.DERIVATION_PATH_INVALID,
    );
  });
});

describe('createPersona: method / keyType 指定', () => {
  it('method だけ指定すると P-256（did:key）。アドレスは持たず、kid は did:key の検証メソッド', async () => {
    const { personas } = await manager();
    const persona = await personas.createPersona({ method: 'key' });
    expect(persona.keyType).toBe('P-256');
    expect(persona.method).toBe('key');
    expect(persona.derivationPath).toBe("m/9256'/0'/0'/0'");
    expect(persona.address).toBeUndefined();
    expect(persona.did.startsWith('did:key:zDn')).toBe(true);
    expect(persona.kid).toBe(`${persona.did}#${persona.did.slice('did:key:'.length)}`);
  });

  it('keyType だけ P-256 を指定しても did:key', async () => {
    const { personas } = await manager();
    const persona = await personas.createPersona({ keyType: 'P-256', index: 2 });
    expect(persona.method).toBe('key');
    expect(persona.keyType).toBe('P-256');
    expect(persona.derivationPath).toBe("m/9256'/0'/2'/0'");
    expect(persona.address).toBeUndefined();
  });

  it('did:jwk は P-256 の JWK から作られ kid は #0', async () => {
    const { personas } = await manager();
    const persona = await personas.createPersona({ method: 'jwk' });
    expect(persona.did.startsWith('did:jwk:')).toBe(true);
    expect(persona.kid).toBe(`${persona.did}#0`);
    expect(resolveDidJwk(persona.did).verificationMethod[0]?.publicKeyJwk).toMatchObject({
      kty: 'EC',
      crv: 'P-256',
    });
  });

  it('did:peer（numalgo 2）は P-256 の署名鍵を .V に持ち、kid は解決した検証メソッド', async () => {
    const { personas } = await manager();
    const persona = await personas.createPersona({ method: 'peer' });
    expect(persona.keyType).toBe('P-256');
    expect(persona.did.startsWith('did:peer:2.V')).toBe(true);
    const document = resolveDidPeer(persona.did);
    expect(persona.kid).toBe(document.verificationMethod[0]?.id);
    expect(document.authentication).toContain(persona.kid as string);
  });

  it('index 省略時は最大 index + 1 を採番し、同じ index では別の鍵になる（P-256）', async () => {
    const { personas } = await manager();
    const a = await personas.createPersona({ method: 'key' });
    const b = await personas.createPersona({ method: 'key' });
    expect([a.index, b.index]).toEqual([0, 1]);
    expect(a.did).not.toBe(b.did);
  });

  it('ニーモニックだけで同じ P-256 のペルソナが復元できる', async () => {
    const created = await (await manager()).personas.createPersona({ method: 'jwk', index: 4 });
    const restored = await (await manager()).personas.createPersona({ method: 'jwk', index: 4 });
    expect(restored.did).toBe(created.did);
    expect(
      await codeOf(
        (await manager(OTHER_MNEMONIC)).personas.createPersona({ method: 'jwk', index: 4 }),
      ),
    ).toBeUndefined();
  });

  it('同じ鍵（導出パス）を別のメソッドで再利用すると 2008（ペルソナ間の連結を防ぐ）', async () => {
    const { personas } = await manager();
    await personas.createPersona({ method: 'key', index: 0 });
    expect(await codeOf(personas.createPersona({ method: 'jwk', index: 0 }))).toBe(
      ErrorCodes.PERSONA_ALREADY_EXISTS,
    );
    expect(await codeOf(personas.createPersona({ method: 'key', index: 0 }))).toBe(
      ErrorCodes.PERSONA_ALREADY_EXISTS,
    );
  });

  it('未対応のメソッド・P-256 以外の鍵の種類は 1030（did:jwk × secp256k1 を含む）', async () => {
    const { personas } = await manager();
    const jwkSecp = { method: 'jwk', keyType: 'secp256k1' } as unknown as Parameters<
      PersonaManager['createPersona']
    >[0];
    expect(await codeOf(personas.createPersona(jwkSecp))).toBe(ErrorCodes.UNSUPPORTED_ALGORITHM);
    const invalid = { method: 'web' } as unknown as Parameters<PersonaManager['createPersona']>[0];
    expect(await codeOf(personas.createPersona(invalid))).toBe(ErrorCodes.UNSUPPORTED_ALGORITHM);
    const proto = { keyType: 'Ed25519' } as unknown as Parameters<
      PersonaManager['createPersona']
    >[0];
    expect(await codeOf(personas.createPersona(proto))).toBe(ErrorCodes.UNSUPPORTED_ALGORITHM);
    expect(await personas.listPersonas()).toEqual([]);
  });

  it('メタデータは storage に保存・復号でき、method / keyType / kid が保たれる', async () => {
    const { personas } = await manager();
    const created = await personas.createPersona({ method: 'peer', label: '仕事' });
    expect(await personas.getPersona(created.id)).toEqual(created);
    expect((await personas.setActivePersona(created.id)).kid).toBe(created.kid);
  });
});

describe('後方互換: 旧レコード（method / keyType 等を持たない）', () => {
  const OLD_RECORD = {
    id: 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUkhPJhPKN',
    index: 0,
    did: 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUkhPJhPKN',
    address: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94',
    derivationPath: "m/44'/60'/0'/0/0",
    createdAt: 1,
    lastUsedAt: 1,
  };

  it('そのまま復号でき、追加項目は欠落のまま', () => {
    const decoded = decodeMetadata(new TextEncoder().encode(JSON.stringify(OLD_RECORD)));
    expect(decoded).toEqual(OLD_RECORD);
    expect(decoded.keyType).toBeUndefined();
  });

  it('新項目の型・値が不正なら 2005（破損として拒否）', () => {
    for (const patch of [
      { method: 'nope' },
      { keyType: 5 },
      { keySource: 'cloud' },
      { relationships: ['capabilityDelegation'] },
      { kid: 1 },
      { address: 5 },
    ]) {
      expect(() =>
        decodeMetadata(new TextEncoder().encode(JSON.stringify({ ...OLD_RECORD, ...patch }))),
      ).toThrow(expect.objectContaining({ code: ErrorCodes.PERSONA_NOT_FOUND }));
    }
  });

  it('旧レコードのペルソナを切り替えても、追加項目を足さずに更新できる', async () => {
    const { personas, storage } = await manager();
    await storage.set(
      `persona/${OLD_RECORD.id}`,
      new TextEncoder().encode(JSON.stringify(OLD_RECORD)),
    );
    const updated = await personas.setActivePersona(OLD_RECORD.id);
    expect(updated.derivationPath).toBe(OLD_RECORD.derivationPath);
    expect('method' in updated).toBe(false);
    expect('keyType' in updated).toBe(false);
  });
});

describe('matchesSeed（seed 差し替えの検知）', () => {
  it('同じ seed なら全ての種類のペルソナで一致し、別 seed なら不一致', async () => {
    const { personas } = await manager();
    // 旧レコード（secp256k1）と新規作成（P-256）の両方が seed 照合できる。
    const created = [
      await personas.restoreLegacyPersona({ index: 0 }),
      await personas.createPersona(),
      await personas.createPersona({ method: 'jwk' }),
      await personas.createPersona({ method: 'peer' }),
    ];
    for (const persona of created) {
      expect(await personas.matchesSeed(persona)).toBe(true);
    }
    const other = (await manager(OTHER_MNEMONIC)).personas;
    for (const persona of created) {
      expect(await other.matchesSeed(persona)).toBe(false);
    }
  });
});
