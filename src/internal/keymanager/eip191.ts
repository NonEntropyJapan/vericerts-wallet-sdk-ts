/**
 * EIP-191（ERC-191 version `0x45`、`personal_sign`）の署名・検証と、JWS `alg: "ES256K-R"` の署名プリミティブ。
 *
 * **標準外の例外**: `ES256K-R`（署名から公開鍵を復元する secp256k1）は IANA の「JSON Web Signature and
 * Encryption Algorithms」レジストリに登録が無い。2026-10-28 の「署名は標準仕様だけで行う」規則の例外として、
 * did:pkh と did:ethr の controller 鍵（検証メソッドが公開鍵を持たず `blockchainAccountId`＝CAIP-10 の
 * アドレスだけを持つ）に限って採用する。
 *
 * 形式（JWS の `alg: "ES256K-R"`）:
 * - 署名対象: JWS signing-input（`base64url(header).base64url(payload)` の UTF-8 バイト列）を EIP-191 の
 *   `personal_sign` メッセージとして扱う。ダイジェストは
 *   `keccak256("\x19Ethereum Signed Message:\n" ‖ ASCII10進(len(message)) ‖ message)`。
 * - 署名: 65 バイトの `r(32) ‖ s(32) ‖ recovery(1)`（`recovery` は 0 / 1。low-S）。JWS の `signature` セグメントへ
 *   base64url で載せる。
 * - 検証: ダイジェストと署名から公開鍵を復元し、検証メソッドのアドレス（`keccak256(公開鍵 64 バイト)` の下位 20
 *   バイト）または公開鍵と一致することを確かめる。
 *
 * EIP-191 のプレフィックスを付けるのは、同じ secp256k1 鍵が `ES256K`（signing-input の SHA-256 への署名）や
 * トランザクション署名に使われても、署名が互いに流用できないようにするため（ドメイン分離）。逆方向（ウォレットの
 * `personal_sign` に JWS の signing-input を渡して署名を得る攻撃）は {@link looksLikeEs256kRSigningInput} で防ぐ。
 *
 * セキュリティ上の注意: 秘密鍵・メッセージ・署名を例外へ含めない。
 */

import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { base64urlnopad } from '@scure/base';
import { ownProperty } from '../prototype-safety/own-property.js';
import { recoverSecp256k1PublicKey, signSecp256k1Recoverable, verifySecp256k1 } from './signer.js';

/** JWS `alg` の値（IANA JWS alg レジストリ外。本モジュール冒頭を参照）。 */
export const ES256K_R_ALG = 'ES256K-R';

/** `ES256K-R` 署名の長さ（`r ‖ s ‖ recovery`）。 */
export const ES256K_R_SIGNATURE_LENGTH = 65;

const encoder = new TextEncoder();
const UNCOMPRESSED_LENGTH = 65;
const UNCOMPRESSED_PREFIX = 0x04;

/** EIP-191（`0x45`）の署名対象バイト列 `"\x19Ethereum Signed Message:\n" ‖ len ‖ message`（ダイジェスト前）。署名・検証・`personal_sign` が共有する。 */
export function eip191SignedBytes(message: Uint8Array): Uint8Array {
  const prefix = encoder.encode(`\x19Ethereum Signed Message:\n${message.length}`);
  return concatBytes(prefix, message);
}

/** EIP-191（`0x45`）のダイジェスト `keccak256("\x19Ethereum Signed Message:\n" ‖ len ‖ message)`。 */
export function eip191Digest(message: Uint8Array): Uint8Array {
  return keccak_256(eip191SignedBytes(message));
}

/**
 * メッセージに EIP-191 で署名する（65 バイト `r ‖ s ‖ recovery`、recovery は 0 / 1）。
 *
 * @throws 秘密鍵が不正な場合（VericertsError、code `1003`）。
 */
export function signEip191(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return signSecp256k1Recoverable(eip191Digest(message), privateKey).signature;
}

/** 非圧縮公開鍵（`0x04 ‖ x ‖ y`、65 バイト）から小文字の Ethereum アドレス（`0x` + 40 hex）を求める。 */
export function ethereumAddressOfPublicKey(uncompressed: Uint8Array): string {
  const hash = keccak_256(uncompressed.subarray(1));
  return `0x${bytesToHex(hash.subarray(hash.length - 20))}`;
}

/** EC secp256k1 公開鍵 JWK（`x` / `y` が各 32 バイトの base64url）から小文字のアドレスを求める。不正なら `undefined`。 */
export function ethereumAddressOfJwk(x: unknown, y: unknown): string | undefined {
  if (typeof x !== 'string' || typeof y !== 'string') {
    return undefined;
  }
  try {
    const xb = base64urlnopad.decode(x.replace(/=+$/, ''));
    const yb = base64urlnopad.decode(y.replace(/=+$/, ''));
    if (xb.length !== 32 || yb.length !== 32) {
      return undefined;
    }
    const uncompressed = new Uint8Array(UNCOMPRESSED_LENGTH);
    uncompressed[0] = UNCOMPRESSED_PREFIX;
    uncompressed.set(xb, 1);
    uncompressed.set(yb, 33);
    return ethereumAddressOfPublicKey(uncompressed);
  } catch {
    return undefined;
  }
}

/**
 * EIP-191 署名から復元した公開鍵（非圧縮 65 バイト）を返す。
 *
 * 署名が 65 バイトでない・復元できない・low-S でない・recovery が 0 / 1 でない場合は `undefined`（fail-closed）。
 */
export function recoverEip191PublicKey(
  message: Uint8Array,
  signature: Uint8Array,
): Uint8Array | undefined {
  if (signature.length !== ES256K_R_SIGNATURE_LENGTH) {
    return undefined;
  }
  const digest = eip191Digest(message);
  let publicKey: Uint8Array;
  try {
    publicKey = recoverSecp256k1PublicKey(digest, signature, false);
  } catch {
    return undefined;
  }
  // 復元した鍵に対して正準形（low-S・recovery が実際にその鍵を復元する）を確かめ直す。
  return verifySecp256k1(digest, signature, publicKey, { encoding: 'recovered' })
    ? publicKey
    : undefined;
}

/** EIP-191 署名が、指定の Ethereum アドレス（大文字小文字を区別しない）の鍵によるものか。 */
export function verifyEip191Address(
  message: Uint8Array,
  signature: Uint8Array,
  address: string,
): boolean {
  const publicKey = recoverEip191PublicKey(message, signature);
  return publicKey !== undefined && ethereumAddressOfPublicKey(publicKey) === address.toLowerCase();
}

/** EIP-191 署名が、指定の公開鍵（圧縮 33 / 非圧縮 65 バイト）の鍵によるものか。 */
export function verifyEip191PublicKey(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (signature.length !== ES256K_R_SIGNATURE_LENGTH) {
    return false;
  }
  return verifySecp256k1(eip191Digest(message), signature, publicKey, { encoding: 'recovered' });
}

/**
 * メッセージが `alg: "ES256K-R"` の JWS signing-input（`base64url(header).…`）に見えるか。
 *
 * ウォレットの `personal_sign` は EIP-191 でメッセージに署名する。ES256K-R の JWS 署名も同じ EIP-191 署名なので、
 * 呼び出し元（dApp）が signing-input そのものを `personal_sign` へ渡すと、利用者の DID の署名（VP / VC / id_token）を
 * 偽造できてしまう。`personal_sign` の入力でこの形を拒否するための判定（ヘッダの先頭セグメントが `alg: "ES256K-R"`
 * の JSON なら `true`）。
 */
export function looksLikeEs256kRSigningInput(message: Uint8Array): boolean {
  const dot = message.indexOf(0x2e);
  // JWS ヘッダ（`{"alg":"ES256K-R",…}`）の base64url は 2 文字以上。長さの上限は置かない（検証側の `decodeCompactJws` にヘッダ長の
  // 上限が無く、上限を置くとヘッダを水増しした signing-input でこの判定を迂回できる）。走査は先頭セグメントだけで message 長に線形。
  if (dot < 2) {
    return false;
  }
  try {
    const segment = new TextDecoder('utf-8', { fatal: true }).decode(message.subarray(0, dot));
    const header: unknown = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(base64urlnopad.decode(segment)),
    );
    return (
      typeof header === 'object' &&
      header !== null &&
      ownProperty<unknown>(header, 'alg') === ES256K_R_ALG
    );
  } catch {
    return false;
  }
}
