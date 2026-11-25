/**
 * 既存 DID をペルソナとして取り込む。
 *
 * 取り込めるのは、SDK の Resolver が解決する DID のうち、DID Document に**保持鍵と同じ公開鍵の検証メソッド**が
 * `authentication` または `assertionMethod` に列挙されているもの（`verifyHeldKeyAgainstDid`）。一致しなければ
 * `2017` で拒否し、何も保存しない。鍵は次のどちらかで渡す。
 * - `external`: 秘密鍵 JWK（RFC 7517。P-256 / secp256k1 / Ed25519）。SDK は保存しない（呼び出し側が保持する）。
 * - `seed`: シードから導出した鍵（`keyType` = `P-256` / `secp256k1` と `index`）。
 *
 * did:pkh と did:ethr の controller 鍵は、検証メソッドが公開鍵を持たず `blockchainAccountId`（CAIP-10）だけを持つ。保持鍵が
 * secp256k1 で、そのアドレスが `blockchainAccountId` と一致すれば取り込める（署名は `alg: "ES256K-R"`。IANA の JWS alg
 * 登録外で、標準だけで署名する規則の例外）。取り込めない DID: did:plc（既定の DID Document に
 * `authentication` / `assertionMethod` が無い。atproto 署名鍵を認証用途に使うのは AT Protocol の慣行で DID Core にも
 * did:plc 仕様にも定義が無い）。いずれも `2017` になる。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DidResolverLike } from '../../identity/bounded-resolver.js';
import type { KeyManager } from '../../keymanager/keymanager.js';
import type { PersonaManager } from '../../persona/persona.js';
import { personaKeyPath } from '../../persona/persona-key.js';
import {
  PERSONA_DID_METHODS,
  type PersonaDidMethod,
  type PersonaKeyType,
  type PersonaMetadata,
} from '../../persona/types.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { createExternalKeySigner, type PrivateKeyJwk } from './external-key.js';
import { type SigningRelationship, verifyHeldKeyAgainstDid } from './key-binding.js';

/** 取り込みに使う鍵。 */
export type ImportedKeySource =
  | { readonly external: PrivateKeyJwk }
  | { readonly seed: { readonly keyType: 'P-256' | 'secp256k1'; readonly index: number } };

/** `importPersonaFromDid` の入力。 */
export interface ImportPersonaFromDidInput {
  /** 取り込む DID。 */
  readonly did: string;
  /** 保持している鍵。 */
  readonly key: ImportedKeySource;
  /** 一致を確認する検証メソッドの DID URL を限定する（省略時は一致した検証メソッドから決める）。 */
  readonly kid?: string;
  /** 取り込みに必須の検証関係（省略時は `authentication` / `assertionMethod` のいずれか）。 */
  readonly relationship?: SigningRelationship;
  /** 表示用ラベル。 */
  readonly label?: string;
  /** 外部鍵の並び順用 index（省略時は既存最大 index + 1）。 */
  readonly index?: number;
}

/** `importPersonaFromDid` の依存。 */
export interface ImportPersonaDeps {
  readonly personas: PersonaManager;
  readonly keymanager: KeyManager;
  /** DID Resolver（`createDidResolver` の戻り値など）。 */
  readonly resolver: DidResolverLike;
}

/** DID 文字列から DID メソッド名を取り出す。未対応のメソッドは `2002`、形式不正は `2001`。 */
function methodOf(did: string): PersonaDidMethod {
  const match = /^did:([a-z0-9]+):.+/.exec(did);
  if (match === null) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const method = match[1] as string;
  if (!(PERSONA_DID_METHODS as readonly string[]).includes(method)) {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }
  return method as PersonaDidMethod;
}

/** 保持鍵（署名鍵）の公開鍵 JWK・種類・出所を解決する。鍵の指定は own 限定で読む（継承値で別の鍵に差し替わらない）。 */
async function heldKey(deps: ImportPersonaDeps, input: ImportPersonaFromDidInput) {
  // 鍵の指定が無い・オブジェクトでない（`undefined` / `null` / プリミティブ）なら、`ownProperty` の生の TypeError にせず 1003。
  if (typeof input.key !== 'object' || input.key === null) {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  const external = ownProperty<PrivateKeyJwk>(input.key, 'external');
  if (external !== undefined) {
    const signer = createExternalKeySigner(external);
    const keyType: PersonaKeyType =
      signer.alg === 'ES256' ? 'P-256' : signer.alg === 'ES256K' ? 'secp256k1' : 'Ed25519';
    return {
      publicKeyJwk: signer.publicKeyJwk,
      keyType,
      keySource: 'external' as const,
      index: undefined,
    };
  }
  const seed = ownProperty<{ keyType: 'P-256' | 'secp256k1'; index: number }>(input.key, 'seed');
  const keyType =
    seed === undefined ? undefined : ownProperty<'P-256' | 'secp256k1'>(seed, 'keyType');
  const index = seed === undefined ? undefined : ownProperty<number>(seed, 'index');
  if (
    seed === undefined ||
    (keyType !== 'P-256' && keyType !== 'secp256k1') ||
    index === undefined
  ) {
    // 外部鍵もシード指定も無い（または不正）。
    throw new VericertsError(
      seed === undefined ? ErrorCodes.INVALID_PRIVATE_KEY : ErrorCodes.DERIVATION_PATH_INVALID,
    );
  }
  const path = personaKeyPath(keyType, index);
  const keyId =
    keyType === 'P-256'
      ? (await deps.keymanager.deriveP256Key(path)).id
      : (await deps.keymanager.deriveKey(path)).id;
  return {
    publicKeyJwk: deps.keymanager.getCredentialSigner(keyId).publicKeyJwk,
    keyType,
    keySource: 'seed' as const,
    index,
  };
}

/**
 * DID を解決して保持鍵との一致を確かめ、一致したらペルソナとして保存する。
 *
 * @returns 保存したペルソナのメタデータ（`kid` / `relationships` を含む）。
 * @throws 一致しない（`2017`）、DID 形式不正（`2001`）・未対応メソッド（`2002`）・解決失敗（`2003` / `2010`）、
 *         既に同じ DID のペルソナがある（`2008`）、秘密鍵 JWK が不正・鍵の指定が無い（`1003`）、seed の指定が不正（`1040`）、
 *         seed 未設定（`1041`）。鍵の指定（`external` / `seed` / `keyType` / `index`）は自身のプロパティだけを読む。
 */
export async function importPersonaFromDid(
  deps: ImportPersonaDeps,
  input: ImportPersonaFromDidInput,
): Promise<PersonaMetadata> {
  const method = methodOf(input.did);
  const held = await heldKey(deps, input);
  // 任意項目は own 限定で読む（`Object.prototype` 汚染で一致条件・index・label が差し替わらない）。
  const kid = ownProperty<string>(input, 'kid');
  const relationship = ownProperty<SigningRelationship>(input, 'relationship');
  const label = ownProperty<string>(input, 'label');
  const match = await verifyHeldKeyAgainstDid(deps.resolver, input.did, held.publicKeyJwk, {
    ...(kid !== undefined ? { kid } : {}),
    ...(relationship !== undefined ? { relationship } : {}),
    // did:pkh / did:ethr の controller 鍵（`blockchainAccountId` のみ）は保持鍵のアドレスと照合する（ES256K-R）。
    allowAddressKey: true,
  });
  const index = held.index ?? ownProperty<number>(input, 'index');
  return deps.personas.registerImportedPersona({
    did: input.did,
    method,
    keyType: held.keyType,
    kid: match.kid,
    relationships: match.allRelationships,
    publicKeyJwk: held.publicKeyJwk,
    keySource: held.keySource,
    ...(index !== undefined ? { index } : {}),
    ...(label !== undefined ? { label } : {}),
  });
}
