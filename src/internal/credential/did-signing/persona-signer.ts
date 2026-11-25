/**
 * ペルソナから「その DID として署名する」署名鍵を解決する。
 *
 * VP / VC / SIOPv2 id_token / signMessage の JWS 署名はすべて本関数が返す署名鍵（`alg` + `kid`）で行う。
 * `alg` は鍵の種類で決まる（P-256 → ES256、secp256k1 → ES256K、Ed25519 → EdDSA）。`kid` は DID Document 上の
 * 検証メソッドの DID URL（`did#fragment`）で、検証側が DID Document から公開鍵を引くために使う。
 *
 * 鍵の出所:
 * - `seed`（既定）: `KeyManager` がシードから導出する（secp256k1 = BIP-32、P-256 = SLIP-0010）。
 * - `external`: 取り込んだ秘密鍵 JWK（`opts.externalKey`。SDK は保存しない）。
 *
 * **取り込んだ DID**（`persona.relationships` を持つ）は、署名のたびに DID を解決し直して保持鍵が、要求した
 * 検証関係に列挙された検証メソッドと一致することを確かめる（ここでは記憶しない。`opts.resolver` が DID Document を
 * 記憶しないことは呼び出し側の責務で、`createWallet` は did:web / did:ebsi / did:ion / did:cheqd も含めてキャッシュなしの
 * `Resolver.resolveUncached` を渡す）。`kid` は一致した検証メソッドで、
 * 取り込み時の `persona.kid` が使えればそれを優先する。`opts.resolver` が無い・要求した検証関係が確認済みの集合に無い・
 * 一致しない場合は署名鍵を返さない（fail-closed）。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DidResolverLike } from '../../identity/bounded-resolver.js';
import { ES256K_R_ALG, eip191Digest } from '../../keymanager/eip191.js';
import type { KeyManager } from '../../keymanager/keymanager.js';
import { type PersonaFields, personaFields } from '../../persona/persona-fields.js';
import type { PersonaDidMethod, PersonaKeyType, PersonaMetadata } from '../../persona/types.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { CredentialAlg, CredentialSignerAlg } from '../vc/jws.js';
import type { CredentialSigner } from '../vc/signer.js';
import {
  createExternalEip191Signer,
  createExternalKeySigner,
  type PrivateKeyJwk,
} from './external-key.js';
import { type SigningRelationship, verifyHeldKeyAgainstDid } from './key-binding.js';

/** `resolvePersonaSigner` のオプション。 */
export interface PersonaSignerOptions {
  /** 署名の用途に必要な検証関係。VP / SIOPv2 / signMessage は `authentication`（既定）、VC 発行は `assertionMethod`。 */
  readonly relationship?: SigningRelationship;
  /** 取り込んだ DID の再照合に使う DID Resolver（取り込んだ DID では必須）。 */
  readonly resolver?: DidResolverLike;
  /** `keySource: 'external'` のペルソナの秘密鍵 JWK。 */
  readonly externalKey?: PrivateKeyJwk;
}

/** 解決した署名鍵。 */
export interface PersonaSigner {
  /** `alg` / `publicKeyJwk` / `kid` / `sign` を持つ署名鍵（JWS ヘッダに `kid` が載る）。 */
  readonly signer: CredentialSigner<CredentialSignerAlg>;
  /** ペルソナの DID。 */
  readonly did: string;
  /** 署名に使う検証メソッドの DID URL（`signer.kid` と同じ）。 */
  readonly kid: string;
  /** JWS `alg`。 */
  readonly alg: CredentialSignerAlg;
}

/**
 * did:key の検証メソッド id（`<did>#<method-specific-id>`）。`kid` を持たない旧ペルソナ（did:key + secp256k1）用。
 */
export function didKeyKid(did: string): string {
  return `${did}#${did.slice(did.lastIndexOf(':') + 1)}`;
}

/** ペルソナの署名用検証メソッド id。保存値があればそれ、無ければ did:key の規則（旧レコード）。 */
export function personaKid(persona: PersonaMetadata): string {
  const { kid, did } = personaFields(persona);
  return kid ?? didKeyKid(did);
}

/** ペルソナの鍵の種類 → JWS `alg`。 */
const ALG_BY_KEY_TYPE: Readonly<Record<PersonaKeyType, CredentialAlg>> = {
  'P-256': 'ES256',
  secp256k1: 'ES256K',
  Ed25519: 'EdDSA',
};

/** `2007`（署名鍵が利用できない）。 */
function unavailable(): VericertsError {
  return new VericertsError(ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE);
}

/** 新規作成（シード導出）できる DID メソッド。DID が公開鍵を自己記述するため、署名時の再照合は不要。 */
const CREATED_DID_METHODS: readonly PersonaDidMethod[] = ['key', 'jwk', 'peer'];

/** シード由来の署名鍵（`KeyManager` の鍵を非公開のまま包んだもの）。 */
async function seedSigner(keymanager: KeyManager, fields: PersonaFields) {
  if (fields.keyType === 'secp256k1') {
    return keymanager.getCredentialSigner((await keymanager.deriveKey(fields.derivationPath)).id);
  }
  if (fields.keyType === 'P-256') {
    return keymanager.getCredentialSigner(
      (await keymanager.deriveP256Key(fields.derivationPath)).id,
    );
  }
  // Ed25519 はシードから導出しない（取り込んだ秘密鍵のみ）。
  throw unavailable();
}

/**
 * ペルソナの鍵そのもの（DID Document とは照合しない署名鍵）を解決する。
 *
 * 鍵の出所（シード導出 / 取り込んだ外部鍵）と鍵の種類（`alg`）の整合だけを確かめる。DID との照合・`kid` の決定は
 * 呼び出し側（`resolvePersonaSigner` は自分の DID、`resolveDelegatedSigner` は委任 DID の文書）が行う。
 *
 * @throws 外部鍵が未提供・鍵の種類と鍵が食い違う（code `2007`）、導出失敗（`1040` / `1041`）。
 */
export async function resolvePersonaKey(
  keymanager: KeyManager,
  persona: PersonaMetadata,
  externalKey?: PrivateKeyJwk,
): Promise<{ readonly base: CredentialSigner; readonly fields: PersonaFields }> {
  const fields = personaFields(persona);
  let base: CredentialSigner;
  if (fields.keySource === 'external') {
    if (externalKey === undefined) {
      throw unavailable();
    }
    base = createExternalKeySigner(externalKey);
  } else {
    base = await seedSigner(keymanager, fields);
  }
  // 鍵の種類（欠落 = secp256k1）と実際に得た署名鍵の alg が食い違う（外部鍵の取り違えなど）なら使わない。
  if (base.alg !== ALG_BY_KEY_TYPE[fields.keyType]) {
    throw unavailable();
  }
  return { base, fields };
}

/**
 * 同じ鍵の `alg: "ES256K-R"` 署名鍵（EIP-191 の recoverable 署名。IANA 登録外の標準外の例外）。
 * secp256k1 のペルソナだけ（それ以外の鍵種は `2007`）。
 */
async function eip191Signer(
  keymanager: KeyManager,
  fields: PersonaFields,
  externalKey: PrivateKeyJwk | undefined,
): Promise<CredentialSigner<CredentialSignerAlg>> {
  if (fields.keyType !== 'secp256k1') {
    throw unavailable();
  }
  if (fields.keySource === 'external') {
    if (externalKey === undefined) {
      throw unavailable();
    }
    return createExternalEip191Signer(externalKey);
  }
  // シード由来の鍵は秘密鍵を取り出さず、`KeyManager` の登録鍵でダイジェストへ署名する（鍵が失効していれば署名のたびに `1004`）。
  const keyId = (await keymanager.deriveKey(fields.derivationPath)).id;
  return {
    alg: ES256K_R_ALG,
    publicKeyJwk: keymanager.getCredentialSigner(keyId).publicKeyJwk,
    sign: (signingInput) => keymanager.signRawDigest(keyId, eip191Digest(signingInput)).signature,
  };
}

/**
 * ペルソナの署名鍵を解決する。
 *
 * @param keymanager シードを保持する `KeyManager`。
 * @param persona 署名に使うペルソナのメタデータ。
 * @param opts 検証関係・Resolver・外部秘密鍵。
 * @returns `kid` 付きの署名鍵。
 * @throws 外部鍵が未提供・取り込んだ DID で Resolver が無い（code `2007`）、要求した検証関係を確認していない・
 *         DID Document と保持鍵が一致しない（code `2017`）、導出失敗（`1040` / `1041`）、DID 解決の失敗。
 */
export async function resolvePersonaSigner(
  keymanager: KeyManager,
  persona: PersonaMetadata,
  opts: PersonaSignerOptions = {},
): Promise<PersonaSigner> {
  // オプションとペルソナは own 限定で読む（`Object.prototype` 汚染で検証関係・鍵の種類・出所が変わらない）。
  const relationship = ownProperty<SigningRelationship>(opts, 'relationship') ?? 'authentication';
  const resolver = ownProperty<DidResolverLike>(opts, 'resolver');
  const externalKey = ownProperty<PrivateKeyJwk>(opts, 'externalKey');
  const { base, fields } = await resolvePersonaKey(keymanager, persona, externalKey);
  let signing: CredentialSigner<CredentialSignerAlg> = base;
  let kid = fields.kid ?? didKeyKid(fields.did);
  if (fields.relationships === undefined) {
    // 作成した DID（key / jwk / peer をシード導出）だけが再照合なしで署名できる。DID が公開鍵を自己記述するので、記録の
    // `did` がそのメソッドの DID であること（`method` と食い違う記録を通さない）も確かめる。取り込んだ DID の記録が
    // `relationships` を欠く（壊れた・改ざんされた）場合は、DID Document との一致を確認できないので拒否する。
    if (
      fields.keySource === 'external' ||
      !CREATED_DID_METHODS.includes(fields.method) ||
      !fields.did.startsWith(`did:${fields.method}:`)
    ) {
      throw new VericertsError(ErrorCodes.DID_KEY_MISMATCH, {
        context: { reason: 'relationships_missing' },
      });
    }
  } else {
    // 取り込んだ DID: 確認済みの検証関係に含まれ、かつ今の DID Document でも一致することを毎回確かめる。
    if (!fields.relationships.includes(relationship)) {
      throw new VericertsError(ErrorCodes.DID_KEY_MISMATCH, {
        context: { reason: 'relationship_not_granted', relationship },
      });
    }
    if (resolver === undefined) {
      throw unavailable();
    }
    // 同じ鍵が複数の検証メソッドに載る DID（did:ethr の veriKey / sigAuth など）では、用途に合う検証メソッドを使う。
    const match = await verifyHeldKeyAgainstDid(resolver, fields.did, base.publicKeyJwk, {
      preferKid: kid,
      relationship,
      // did:pkh / did:ethr の controller 鍵（公開鍵を持たず `blockchainAccountId` だけ）は ES256K-R（標準外の例外）で署名する。
      allowAddressKey: true,
    });
    kid = match.kid;
    if (match.alg === ES256K_R_ALG) {
      signing = await eip191Signer(keymanager, fields, externalKey);
    }
  }
  const signer: CredentialSigner<CredentialSignerAlg> = {
    alg: signing.alg,
    publicKeyJwk: signing.publicKeyJwk,
    kid,
    sign: (signingInput) => signing.sign(signingInput),
  };
  return { signer, did: fields.did, kid, alg: signer.alg };
}
