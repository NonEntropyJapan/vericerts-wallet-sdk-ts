/**
 * `KeyManager` が返す署名器（Signer / CredentialSigningKey）を「鍵がレジストリに登録されている間だけ
 * 署名できる」形に包む純粋ヘルパ。
 *
 * 導出時点の `keyPair.privateKey` をそのまま捕捉すると、`zeroize()` 後（または同一鍵の再登録後）も
 * 旧オブジェクトを握ったシグナーが署名し続けられる。署名のたびに レジストリを引き直し、
 * 失効していれば `KEY_NOT_FOUND`（1004）で失敗させる。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { keccak256 } from './address.js';
import {
  type CredentialSigningKey,
  createP256CredentialSigner,
  createSecp256k1CredentialSigner,
} from './credential-signer.js';
import { requireRegisteredKey, requireRegisteredSecp256k1 } from './key-registry.js';
import { type RecoverableSignature, signSecp256k1Recoverable } from './signer.js';
import type { KeyPair, RegisteredKeyPair, Signer } from './types.js';

/** `KeyManager.keys`（id → 鍵ペア）。`zeroize()` で空になり、再導出で別オブジェクトに入れ替わる。 */
export type KeyRegistry = ReadonlyMap<string, RegisteredKeyPair>;

function assertLive<T extends RegisteredKeyPair>(registry: KeyRegistry, keyPair: T): T {
  if (registry.get(keyPair.id) !== keyPair) {
    throw new VericertsError(ErrorCodes.KEY_NOT_FOUND);
  }
  return keyPair;
}

/** `Signer`（keccak256 + recoverable 署名）を生存確認付きで構築する。 */
export function createLiveSigner(keyPair: KeyPair, registry: KeyRegistry): Signer {
  return {
    // async にすることで同期 throw も rejected Promise に正規化される（不正鍵・失効時など）。
    sign: async (data: Uint8Array): Promise<Uint8Array> => {
      const digest = keccak256(data);
      return signSecp256k1Recoverable(digest, assertLive(registry, keyPair).privateKey).signature;
    },
    publicKey: (): Uint8Array => keyPair.publicKey,
    address: (): string => keyPair.address,
  };
}

/**
 * JWS 署名鍵を生存確認付きで構築する（署名ロジックは `createSecp256k1CredentialSigner` /
 * `createP256CredentialSigner`）。鍵の `algorithm` で ES256K / ES256 を選ぶ。
 */
export function createLiveCredentialSigner(
  keyPair: RegisteredKeyPair,
  registry: KeyRegistry,
): CredentialSigningKey {
  const signer =
    keyPair.algorithm === 'P-256'
      ? createP256CredentialSigner(keyPair.privateKey)
      : createSecp256k1CredentialSigner(keyPair.privateKey);
  return {
    ...signer,
    sign: (signingInput: Uint8Array): Uint8Array => {
      assertLive(registry, keyPair);
      return signer.sign(signingInput);
    },
  };
}

/** 登録済みの secp256k1 鍵の `Signer`。未登録は `1004`、P-256 鍵は `1030`（`KeyManager.getSigner`）。 */
export function signerFor(registry: KeyRegistry, keyId: string): Signer {
  return createLiveSigner(requireRegisteredSecp256k1(registry, keyId), registry);
}

/** 登録済み鍵の JWS 署名鍵。未登録は `1004`（`KeyManager.getCredentialSigner`）。 */
export function credentialSignerFor(registry: KeyRegistry, keyId: string): CredentialSigningKey {
  return createLiveCredentialSigner(requireRegisteredKey(registry, keyId), registry);
}

/** 登録済みの secp256k1 鍵で digest に直接 recoverable 署名する（`KeyManager.signRawDigest`）。 */
export function signDigestFor(
  registry: KeyRegistry,
  keyId: string,
  digest: Uint8Array,
): RecoverableSignature {
  return signSecp256k1Recoverable(digest, requireRegisteredSecp256k1(registry, keyId).privateKey);
}
