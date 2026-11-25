/**
 * ペルソナ鍵の導出と DID 生成（`PersonaManager.createPersona` の実体）。
 *
 * 新規に作成する DID は常に P-256（ES256）で、ニーモニックから SLIP-0010 "Nist256p1 seed"（全 hardened、
 * `m/9256'/0'/<index>'/0'`）で決定的に導出する。作成できる DID メソッドは次のとおり
 * （DID メソッド仕様が許す範囲。secp256k1 / Ed25519 の新規作成は無い）:
 *
 * | method | 備考                                                    |
 * | ------ | ------------------------------------------------------- |
 * | `key`  | `did:key:<multibase>`、kid = `<did>#<multibase>`        |
 * | `jwk`  | EC P-256 の JWK。kid = `<did>#0`                        |
 * | `peer` | numalgo 2（`.V` 署名鍵）。kid = `<did>#key-1`           |
 *
 * `method` / `keyType` を省略した既定は did:key + P-256（最初の既定ペルソナ index 0 も同じ）。
 *
 * レガシー（method / keyType の無い既存レコード = did:key + secp256k1、BIP-32 `m/44'/60'/<index>'/0/0`）は
 * **既存データの復元専用**の内部経路 {@link LEGACY_SECP256K1_CREATION}（`PersonaManager.restoreLegacyPersona`）でだけ
 * 作り直せる。新規作成の入口（`createPersona` / UI / メッセージ）には無い。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import type { DIDDocument, DidKeyType } from '../identity/did.js';
import { relationshipEntriesOf, relationshipId } from '../identity/did-document-read.js';
import { createDidJwk } from '../identity/jwk/method-jwk.js';
import {
  createDidPeer2,
  encodePublicKeyMultibase,
  resolveDidPeer,
} from '../identity/peer/method-peer.js';
import { p256DidPath } from '../keymanager/derivation/slip10.js';
import { ethereumPath } from '../keymanager/hd.js';
import type { KeyManager } from '../keymanager/keymanager.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { personaFields } from './persona-fields.js';
import type {
  CreatablePersonaMethod,
  CreatePersonaOptions,
  PersonaKeyType,
  PersonaMetadata,
} from './types.js';

/** did:key 生成手段（`createDidKey` と同じシグネチャ。`PersonaManager` の DI）。 */
export type CreateDidKeyFn = (keyType: DidKeyType, publicKey: Uint8Array) => DIDDocument;

/** 作成できる DID メソッド（いずれも P-256 のみ）。範囲外は `1030`。 */
const CREATABLE_METHODS: readonly CreatablePersonaMethod[] = ['key', 'jwk', 'peer'];

/** 作成条件を解決した結果。`legacy` は既存レコードの復元専用経路（did:key + secp256k1。メタデータに method / keyType を載せない）。 */
export interface ResolvedCreation {
  readonly method: CreatablePersonaMethod;
  readonly keyType: PersonaKeyType;
  readonly legacy: boolean;
}

/** 既存のレガシーレコード（did:key + secp256k1）を作り直すための内部専用の作成条件。新規作成には使わない。 */
export const LEGACY_SECP256K1_CREATION: ResolvedCreation = {
  method: 'key',
  keyType: 'secp256k1',
  legacy: true,
};

/**
 * 作成オプションの `method` / `keyType` を解決する。省略側の既定は `method = key` / `keyType = P-256`。
 * 新規作成は P-256 のみで、他の鍵の種類（`secp256k1` を含む）は拒否する。
 *
 * @throws 未知の値・P-256 以外・DID メソッドが対応しない組の場合（VericertsError、code `1030`）。
 */
export function resolveCreation(
  method: CreatePersonaOptions['method'],
  keyType: CreatePersonaOptions['keyType'],
): ResolvedCreation {
  const resolvedMethod = method ?? 'key';
  if (!CREATABLE_METHODS.includes(resolvedMethod) || (keyType ?? 'P-256') !== 'P-256') {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  return { method: resolvedMethod, keyType: 'P-256', legacy: false };
}

/**
 * ペルソナ index と鍵の種類から、シード導出パスを組み立てる。
 *
 * @throws index が範囲外・seed から導出できない鍵の種類（`Ed25519`）の場合（VericertsError、code `1040` / `1030`）。
 */
export function personaKeyPath(keyType: PersonaKeyType, index: number): string {
  if (keyType === 'secp256k1') {
    return ethereumPath(index, 0);
  }
  if (keyType === 'P-256') {
    return p256DidPath(index);
  }
  throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
}

/** 導出・生成した鍵と DID。 */
export interface CreatedPersonaKey {
  readonly document: DIDDocument;
  readonly derivationPath: string;
  /** secp256k1 のときだけ持つ EIP-55 アドレス。 */
  readonly address?: string;
  /** DID Document 上の署名用検証メソッド id（`authentication[0]`）。 */
  readonly kid: string;
}

/**
 * 解決済みオプションに従って鍵を導出し、DID Document を生成する。
 *
 * @throws seed 未設定（`1041`）・パス不正（`1040`）・DID 生成失敗（`2001`）。
 */
export async function createPersonaKey(
  keymanager: KeyManager,
  createDidKey: CreateDidKeyFn,
  index: number,
  creation: ResolvedCreation,
): Promise<CreatedPersonaKey> {
  const path = personaKeyPath(creation.keyType, index);
  if (creation.keyType === 'secp256k1') {
    const keyPair = await keymanager.deriveKey(path);
    const document = buildDocument(createDidKey, creation, keyPair.publicKey);
    return withKid({ document, derivationPath: keyPair.derivationPath, address: keyPair.address });
  }
  const keyPair = await keymanager.deriveP256Key(path);
  const publicKeyJwk = keymanager.getCredentialSigner(keyPair.id).publicKeyJwk;
  const document = buildDocument(createDidKey, creation, keyPair.publicKey, publicKeyJwk);
  return withKid({ document, derivationPath: keyPair.derivationPath });
}

/** メソッドごとに DID Document を生成する（`jwk` は公開鍵 JWK が要る。did:jwk は JWK そのものが DID になる）。 */
function buildDocument(
  createDidKey: CreateDidKeyFn,
  { method, keyType }: ResolvedCreation,
  publicKey: Uint8Array,
  publicKeyJwk?: Readonly<Record<string, unknown>>,
): DIDDocument {
  if (method === 'key') {
    return createDidKey(keyType, publicKey);
  }
  if (method === 'jwk') {
    if (publicKeyJwk === undefined) {
      throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
    }
    return createDidJwk(publicKeyJwk);
  }
  const did = createDidPeer2({ verificationKeys: [encodePublicKeyMultibase(keyType, publicKey)] });
  return resolveDidPeer(did);
}

/** DID Document の `authentication[0]` を kid として添える。無ければ DID Document 不正（`2010`）。 */
function withKid(created: Omit<CreatedPersonaKey, 'kid'>): CreatedPersonaKey {
  const first = relationshipEntriesOf(created.document, 'authentication')?.[0];
  const kid = first === undefined ? undefined : relationshipId(first);
  if (kid === undefined) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  return { ...created, kid };
}

/** 2 つの EC 公開鍵 JWK の座標（`x` / `y`）が一致するか。 */
function sameCoordinates(
  a: Readonly<Record<string, unknown>>,
  b: Readonly<Record<string, unknown>>,
): boolean {
  return (
    ownProperty<unknown>(a, 'x') === ownProperty<unknown>(b, 'x') &&
    ownProperty<unknown>(a, 'y') === ownProperty<unknown>(b, 'y')
  );
}

/**
 * 保存済みペルソナが現在の seed から導出した鍵と一致するか（seed 差し替えの検知用）。
 *
 * - `keySource: 'external'`（取り込んだ秘密鍵）や Ed25519 は seed に依存しないため常に `true`。
 * - secp256k1: 導出アドレスと保存アドレスの比較（従来どおり）。
 * - P-256: 保存した公開鍵 JWK（取り込み）または同じ method で再生成した DID（作成）との比較。
 *
 * @throws 導出に失敗した場合（VericertsError、`1040` / `1041`）。
 */
export async function personaMatchesSeed(
  keymanager: KeyManager,
  createDidKey: CreateDidKeyFn,
  persona: PersonaMetadata,
): Promise<boolean> {
  const fields = personaFields(persona);
  const { keyType } = fields;
  if (fields.keySource === 'external' || keyType === 'Ed25519') {
    return true;
  }
  if (keyType === 'secp256k1') {
    const keyPair = await keymanager.deriveKey(fields.derivationPath);
    return keyPair.address === fields.address;
  }
  const keyPair = await keymanager.deriveP256Key(fields.derivationPath);
  const publicKeyJwk = keymanager.getCredentialSigner(keyPair.id).publicKeyJwk;
  if (fields.publicKeyJwk !== undefined) {
    return sameCoordinates(fields.publicKeyJwk, publicKeyJwk);
  }
  const { method } = fields;
  if (method !== 'key' && method !== 'jwk' && method !== 'peer') {
    // 取り込んだ DID なのに公開鍵 JWK が無い（想定外のレコード）。照合できないため不一致として扱う（fail-closed）。
    return false;
  }
  const creation: ResolvedCreation = { method, keyType, legacy: false };
  const document = buildDocument(createDidKey, creation, keyPair.publicKey, publicKeyJwk);
  return ownProperty<string>(document, 'id') === fields.did;
}
