/**
 * 既存 DID の取り込み（`PersonaManager.registerImportedPersona`）で保存するメタデータの組み立て。
 *
 * 取り込んだ DID は、保持鍵と DID Document の検証メソッドが一致することを確認済み（呼び出し側の責務）。
 * ここでは鍵の出所に応じて導出パス・アドレスを決めるだけで、検証はしない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import type { KeyManager } from '../keymanager/keymanager.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { personaKeyPath } from './persona-key.js';
import type { ImportPersonaInput, PersonaMetadata } from './types.js';

/**
 * 取り込み入力から保存用メタデータを組み立てる。
 *
 * @param nextIndex 外部鍵で index 省略時に採番する関数（既存最大 index + 1）。
 * @throws `seed` で index が無い・不正（`1040`）、seed 導出できない鍵の種類（`1030`）、seed 未設定（`1041`）。
 */
export async function buildImportedMetadata(
  keymanager: KeyManager,
  input: ImportPersonaInput,
  nextIndex: () => Promise<number>,
  timestamp: number,
): Promise<PersonaMetadata> {
  // 任意項目は own 限定で読む（`Object.prototype` 汚染で index / label が差し替わらない）。
  const label = ownProperty<string>(input, 'label');
  const index = ownProperty<number>(input, 'index');
  const common = {
    id: input.did,
    did: input.did,
    ...(label !== undefined ? { label } : {}),
    createdAt: timestamp,
    lastUsedAt: timestamp,
    method: input.method,
    keyType: input.keyType,
    keySource: input.keySource,
    kid: input.kid,
    relationships: [...input.relationships],
    publicKeyJwk: input.publicKeyJwk,
  } as const;
  if (input.keySource === 'external') {
    return { ...common, index: index ?? (await nextIndex()), derivationPath: '' };
  }
  if (index === undefined) {
    throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
  }
  const path = personaKeyPath(input.keyType, index);
  if (input.keyType === 'secp256k1') {
    const keyPair = await keymanager.deriveKey(path);
    return {
      ...common,
      index,
      derivationPath: keyPair.derivationPath,
      address: keyPair.address,
    };
  }
  const keyPair = await keymanager.deriveP256Key(path);
  return { ...common, index, derivationPath: keyPair.derivationPath };
}
