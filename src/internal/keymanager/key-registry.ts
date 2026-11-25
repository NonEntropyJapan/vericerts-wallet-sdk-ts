/**
 * `KeyManager` の導出済み鍵レジストリ（key id → 鍵ペア）に対する純粋ヘルパ。
 *
 * `keymanager.ts` の行数上限（CI 規約）に対応するための分離。レジストリ本体（`Map`）は KeyManager が
 * 所有し、署名器（`live-signers.ts`）が「登録されている間だけ署名できる」判定に同じ `Map` を参照する。
 * レジストリには secp256k1（BIP-32）と P-256（SLIP-0010）の鍵が同居する。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { computeKeyId, deriveEip55Address } from './address.js';
import { deriveSlip10Nist256p1 } from './derivation/slip10.js';
import { deriveKeyFromSeed } from './hd.js';
import { sealPrivateKey } from './secret-key-field.js';
import type { KeyPair, P256KeyPair, RegisteredKeyPair } from './types.js';

/** マスターシードを返す。未設定なら `1041`。 */
function requireSeed(masterSeed: Uint8Array | null): Uint8Array {
  if (masterSeed === null) {
    throw new VericertsError(ErrorCodes.MASTER_SEED_NOT_INITIALIZED);
  }
  return masterSeed;
}

/**
 * マスターシードから BIP-32 パスで secp256k1 鍵を導出し、レジストリに登録して返す。
 *
 * 同一鍵の再導出は登録済みの KeyPair をそのまま返す（上書きすると旧秘密鍵が `zeroizeRegistry` の
 * 走査から漏れて残留する）。
 */
export function deriveAndRegister(
  keys: Map<string, RegisteredKeyPair>,
  masterSeed: Uint8Array | null,
  path: string,
): KeyPair {
  const derived = deriveKeyFromSeed(requireSeed(masterSeed), path);
  const id = computeKeyId(derived.publicKey);
  const existing = keys.get(id);
  if (existing !== undefined) {
    derived.privateKey.fill(0);
    return requireSecp256k1(existing);
  }
  const keyPair: KeyPair = sealPrivateKey({
    id,
    algorithm: 'secp256k1',
    privateKey: derived.privateKey,
    publicKey: derived.publicKey,
    address: deriveEip55Address(derived.privateKey),
    derivationPath: derived.derivationPath,
  });
  keys.set(id, keyPair);
  return keyPair;
}

/**
 * マスターシードから SLIP-0010（Nist256p1）パスで P-256 鍵を導出し、レジストリに登録して返す。
 *
 * DID 鍵用に hardened のみのパス（`m/<n>'/…'`）を要求する（SLIP-0010 は通常の導出も定義するが、本ウォレットは方針として許さない）。通常（non-hardened）の子鍵が混じるパスは
 * 親の公開鍵と子の秘密鍵から親の秘密鍵が計算できてしまうため、`1040` で拒否する。
 * 再導出が登録済み鍵を返す規則は {@link deriveAndRegister} と同じ。
 *
 * @throws マスターシード未設定（`1041`）、パスが hardened のみでない・不正な場合（code `1040`）。
 */
export function deriveAndRegisterP256(
  keys: Map<string, RegisteredKeyPair>,
  masterSeed: Uint8Array | null,
  path: string,
): P256KeyPair {
  if (!/^m(\/\d+')+$/.test(path)) {
    throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
  }
  const derived = deriveSlip10Nist256p1(requireSeed(masterSeed), path);
  const id = computeKeyId(derived.publicKey);
  const existing = keys.get(id);
  if (existing !== undefined) {
    derived.privateKey.fill(0);
    return requireP256(existing);
  }
  const keyPair: P256KeyPair = sealPrivateKey({
    id,
    algorithm: 'P-256',
    privateKey: derived.privateKey,
    publicKey: derived.publicKey,
    derivationPath: derived.derivationPath,
  });
  keys.set(id, keyPair);
  return keyPair;
}

/** 登録済みの鍵を返す。未登録（破棄済みを含む）なら `1004`。 */
export function requireRegisteredKey(
  keys: ReadonlyMap<string, RegisteredKeyPair>,
  keyId: string,
): RegisteredKeyPair {
  const keyPair = keys.get(keyId);
  if (keyPair === undefined) {
    throw new VericertsError(ErrorCodes.KEY_NOT_FOUND);
  }
  return keyPair;
}

/** 登録済みの secp256k1 鍵を返す。未登録は `1004`、P-256 鍵は `1030`（keccak256 + recoverable 署名の経路用）。 */
export function requireRegisteredSecp256k1(
  keys: ReadonlyMap<string, RegisteredKeyPair>,
  keyId: string,
): KeyPair {
  return requireSecp256k1(requireRegisteredKey(keys, keyId));
}

/**
 * secp256k1 鍵であることを確認する（keccak256 + recoverable 署名など、secp256k1 前提の経路用）。
 * P-256 鍵は `1030` で拒否する。
 */
function requireSecp256k1(keyPair: RegisteredKeyPair): KeyPair {
  if (keyPair.algorithm !== 'secp256k1') {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  return keyPair;
}

/** P-256 鍵であることを確認する。secp256k1 鍵と同じ id になることは通常ないが、型を絞るために検査する。 */
function requireP256(keyPair: RegisteredKeyPair): P256KeyPair {
  if (keyPair.algorithm !== 'P-256') {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  return keyPair;
}

/**
 * 全ての秘密鍵を `fill(0)` してレジストリを空にする（`zeroize()` と seed 切替が共有）。
 * 以降、旧 keyId の署名器は `1004` で失効する。
 */
export function zeroizeRegistry(keys: Map<string, RegisteredKeyPair>): void {
  for (const keyPair of keys.values()) {
    keyPair.privateKey.fill(0);
  }
  keys.clear();
}
