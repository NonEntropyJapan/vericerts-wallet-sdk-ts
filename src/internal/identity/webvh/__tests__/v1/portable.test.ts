/**
 * portable（DID の移動）の検証（did:webvh v1.0、spec: DID Portability、`portable` パラメータ、The DID Log File の
 * 「検証に失敗する例」5）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { restoreFetch, signEntry } from '../webvh-fixtures.js';
import {
  appendSigned,
  forgeNext,
  INVALID_DID,
  resolveLog,
  signedGenesis,
  stateOf,
} from './log-builders.js';

afterEach(() => {
  restoreFetch();
});

const NEW_HOST = ':new.example.com';

describe('portable な DID の移動', () => {
  it('portable: true の DID は、alsoKnownAs に前の DID を入れれば host を変えられ、新しい DID で解決できる', async () => {
    const { key, did, genesis } = signedGenesis({ portable: true });
    const newDid = did.replace(':vericerts.io', NEW_HOST);
    const moved = appendSigned([genesis], key, {
      state: stateOf(newDid, { alsoKnownAs: [did] }),
    });
    const { document, metadata } = await resolveLog(newDid, [genesis, moved]);
    expect(document.id).toBe(newDid);
    expect(document.alsoKnownAs).toEqual([did]);
    expect(metadata.portable).toBe(true);
    // SCID は移動しても変わらない。
    expect(metadata.scid).toBe(genesis.parameters.scid as string);
    // 移動前の DID（古い場所の識別子）では、移動後の DID Document を返さない。
    await expect(resolveLog(did, [genesis, moved])).rejects.toThrow(INVALID_DID);
    // 移動前の版は、移動前の DID で引ける（ピン）。
    const past = await resolveLog(did, [genesis, moved], { versionNumber: 1 });
    expect(past.document.id).toBe(did);
  });

  it('path の変更も移動として扱われ、同じ条件が要る', async () => {
    const { key, did, genesis } = signedGenesis({ portable: true });
    const newDid = `${did}:moved`;
    const moved = appendSigned([genesis], key, { state: stateOf(newDid, { alsoKnownAs: [did] }) });
    const { document } = await resolveLog(newDid, [genesis, moved]);
    expect(document.id).toBe(newDid);
  });

  it('portable でない DID の移動は拒否される（検証側もビルダーも）', async () => {
    const { key, did, genesis } = signedGenesis();
    const newDid = did.replace(':vericerts.io', NEW_HOST);
    const state = stateOf(newDid, { alsoKnownAs: [did] });
    expect(() => appendSigned([genesis], key, { state })).toThrow(INVALID_DID);
    const forged = signEntry(forgeNext(genesis, state, { updateKeys: [key.multikey] }), key);
    await expect(resolveLog(newDid, [genesis, forged])).rejects.toThrow(INVALID_DID);
  });

  it('alsoKnownAs に前の DID を含めない移動は拒否される', async () => {
    const { key, did, genesis } = signedGenesis({ portable: true });
    const newDid = did.replace(':vericerts.io', NEW_HOST);
    expect(() => appendSigned([genesis], key, { state: stateOf(newDid) })).toThrow(INVALID_DID);
    const forged = signEntry(
      forgeNext(genesis, stateOf(newDid), { updateKeys: [key.multikey] }),
      key,
    );
    await expect(resolveLog(newDid, [genesis, forged])).rejects.toThrow(INVALID_DID);
  });

  it('portable: false を宣言すると移動できなくなり、後から true には戻せない', async () => {
    const { key, did, genesis } = signedGenesis({ portable: true });
    const v2 = appendSigned([genesis], key, { portable: false });
    const newDid = did.replace(':vericerts.io', NEW_HOST);
    const moved = signEntry(
      forgeNext(v2, stateOf(newDid, { alsoKnownAs: [did] }), { updateKeys: [key.multikey] }),
      key,
    );
    await expect(resolveLog(newDid, [genesis, v2, moved])).rejects.toThrow(INVALID_DID);
    const revive = signEntry(
      forgeNext(v2, stateOf(did), { updateKeys: [key.multikey], portable: true }),
      key,
    );
    await expect(resolveLog(did, [genesis, v2, revive])).rejects.toThrow(INVALID_DID);
  });

  it('後続の版で portable: true にする版は、それまでの履歴にかかわらず拒否される', async () => {
    const { key, did, genesis } = signedGenesis();
    const forged = signEntry(
      forgeNext(genesis, stateOf(did), { updateKeys: [key.multikey], portable: true }),
      key,
    );
    await expect(resolveLog(did, [genesis, forged])).rejects.toThrow(INVALID_DID);
  });
});
