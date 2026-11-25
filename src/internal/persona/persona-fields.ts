/**
 * ペルソナメタデータの own 限定の読み取り。
 *
 * 後から追加した任意項目（`method` / `keyType` / `keySource` / `kid` / `relationships` / `publicKeyJwk`）は旧レコードで
 * 欠落する。欠落を `Object.prototype` 汚染の継承値で埋めないよう、メタデータは本関数経由で読む
 * （鍵の種類・出所・検証メソッドの選択が汚染で変わると、別の鍵・別の DID で署名しうる）。
 */

import { ownProperty } from '../prototype-safety/own-property.js';
import type {
  PersonaDidMethod,
  PersonaKeyType,
  PersonaMetadata,
  PersonaRelationship,
} from './types.js';

/** 既定値（旧レコードの解釈）を適用したペルソナの読み取り結果。 */
export interface PersonaFields {
  readonly did: string;
  readonly derivationPath: string;
  readonly address: string | undefined;
  /** 欠落は `secp256k1`（旧レコード）。 */
  readonly keyType: PersonaKeyType;
  /** 欠落は `key`（旧レコード）。 */
  readonly method: PersonaDidMethod;
  /** 欠落は `seed`。 */
  readonly keySource: 'seed' | 'external';
  readonly kid: string | undefined;
  readonly relationships: readonly PersonaRelationship[] | undefined;
  readonly publicKeyJwk: Readonly<Record<string, unknown>> | undefined;
}

/** ペルソナのメタデータを own 限定で読み、旧レコードの既定値を適用する。 */
export function personaFields(persona: PersonaMetadata): PersonaFields {
  return {
    did: ownProperty<string>(persona, 'did') ?? '',
    derivationPath: ownProperty<string>(persona, 'derivationPath') ?? '',
    address: ownProperty<string>(persona, 'address'),
    keyType: ownProperty<PersonaKeyType>(persona, 'keyType') ?? 'secp256k1',
    method: ownProperty<PersonaDidMethod>(persona, 'method') ?? 'key',
    keySource: ownProperty<'seed' | 'external'>(persona, 'keySource') ?? 'seed',
    kid: ownProperty<string>(persona, 'kid'),
    relationships: ownProperty<readonly PersonaRelationship[]>(persona, 'relationships'),
    publicKeyJwk: ownProperty<Readonly<Record<string, unknown>>>(persona, 'publicKeyJwk'),
  };
}
