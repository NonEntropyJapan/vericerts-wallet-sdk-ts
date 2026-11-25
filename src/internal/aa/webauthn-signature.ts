/**
 * WebAuthn assertion を ERC-4337 の Passkey Validator 用署名に変換する。
 *
 * `PasskeyValidator` は ERC-4337 v0.7 の単一 Validator
 * 署名形式 `abi.encode(address validator, bytes innerSig)`（`ERC4337Account._validateSignature`
 * / `emergency-revoke.ts` が使う ECDSAValidator 経路と同一 envelope）を要求し、`innerSig` は
 * Solady `WebAuthn.WebAuthnAuth`（`bytes authenticatorData, string clientDataJSON,
 * uint256 challengeIndex, uint256 typeIndex, bytes32 r, bytes32 s`）の ABI エンコードである。
 *
 * ethers / viem / permissionless を含まない拡張でも使えるよう、ABI エンコードを手組みする
 * （`asset/legacy-tx-serializer.ts` が RLP を手組みするのと同じ方針）。`@noble/curves` の
 * `p256.Signature` で DER → raw(r, s) 変換のみを借りる（署名検証はしない。それは
 * `PasskeyValidator.validateUserOpSignature` がチェーン上で行う）。
 *
 * `challengeIndex` / `typeIndex` の意味は Solady `WebAuthn.verify` のインラインアセンブリが定める
 * （Solady の `WebAuthn.verify`）: `typeIndex` は `clientDataJSON` 中の
 * 完全一致部分文字列 `"type":"webauthn.get"` の開始位置、`challengeIndex` は
 * `"challenge":"..."` の開始位置（`"challenge":"` の 13 文字ちょうどで始まる）。本モジュールは
 * ブラウザが実際に生成した `clientDataJSON` からこれらの位置を探すのみで、challenge の値自体が
 * 期待する UserOpHash と一致するかは検証しない（envelope 組み立てはあくまで「表現」の責務であり、
 * 真正性の判定はチェーン上の `PasskeyValidator` / `P256.verifySignature` が fail-closed で行う。
 * ECDSAValidator 経路の `encodeValidatorSignature` も同様に検証しない）。
 *
 * セキュリティ上の注意:
 * - DER 署名のデコード失敗・`clientDataJSON` 内に必須部分文字列が無い場合は、入力値を例外に
 *   含めず `VericertsError`（code `7150`、P256_SIG_INVALID）に正規化する。
 */

import { p256 } from '@noble/curves/nist.js';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { isValidEvmAddress } from '../evm-format.js';
import type { Hex, UserOperationV07 } from './types.js';

/**
 * WebAuthn API（`navigator.credentials.get`）から取得した assertion。
 *
 * `clientDataJSON` / `signature` はブラウザの `AuthenticatorAssertionResponse` が返す生バイト列
 * そのもの（`signature` は ASN.1 DER エンコードの P-256 (secp256r1) ECDSA 署名）。
 * `vericerts-wallet-sdk/aa` から公開する契約。
 */
export interface WebAuthnAssertion {
  readonly authenticatorData: Uint8Array;
  readonly clientDataJSON: Uint8Array;
  readonly signature: Uint8Array;
}

const WORD_SIZE = 32;
const TYPE_NEEDLE = '"type":"webauthn.get"';
const CHALLENGE_NEEDLE_PREFIX = '"challenge":"';

/** 32 バイト未満のバイト列を ABI ワード（左パディング）へ揃える。32 バイト超は不正入力として拒否する。 */
function padWord(bytes: Uint8Array): Uint8Array {
  if (bytes.length > WORD_SIZE) throw new VericertsError(ErrorCodes.P256_SIG_INVALID);
  const out = new Uint8Array(WORD_SIZE);
  out.set(bytes, WORD_SIZE - bytes.length);
  return out;
}

/** 非負整数を uint256 の ABI ワードへエンコードする（バイト長・文字列インデックス用途に限定）。 */
function uint256Word(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new VericertsError(ErrorCodes.P256_SIG_INVALID);
  return padWord(hexToBytes(value.toString(16).padStart(WORD_SIZE * 2, '0')));
}

/** `0x` + 40 hex の EVM アドレスを ABI ワード（左パディング 20 バイト）へエンコードする。 */
function addressWord(address: string): Uint8Array {
  if (!isValidEvmAddress(address)) {
    throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
  }
  return padWord(hexToBytes(address.slice(2)));
}

/** 動的 `bytes` の ABI エンコード本体（長さワード + 32 バイト境界へ右パディングした本体）。 */
function encodeDynamicBytesTail(bytes: Uint8Array): Uint8Array {
  const lengthWord = uint256Word(bytes.length);
  const paddedLength = Math.ceil(bytes.length / WORD_SIZE) * WORD_SIZE;
  const body = new Uint8Array(paddedLength);
  body.set(bytes);
  return concatBytes(lengthWord, body);
}

/**
 * DER エンコードの P-256 ECDSA 署名を raw `(r, s)`（各 32 バイト）へ変換する。不正な DER は 7150。
 * オンチェーン `P256.verifySignature` は `s > N/2` を malleability 対策として拒否し、認証器は low-s を
 * 保証しないため、高 s は `s' = N - s` へ正規化する（(r, s') も同一メッセージ・公開鍵で有効）。
 */
function decodeDerSignature(der: Uint8Array): { r: Uint8Array; s: Uint8Array } {
  try {
    const parsed = p256.Signature.fromBytes(der, 'der');
    const normalized = parsed.hasHighS()
      ? new p256.Signature(parsed.r, p256.Point.Fn.ORDER - parsed.s)
      : parsed;
    const compact = normalized.toBytes('compact');
    return { r: compact.slice(0, WORD_SIZE), s: compact.slice(WORD_SIZE, WORD_SIZE * 2) };
  } catch {
    throw new VericertsError(ErrorCodes.P256_SIG_INVALID);
  }
}

/** `clientDataJSON` 中の `"challenge":"..."` / `"type":"webauthn.get"` の開始位置を探す。無ければ 7150。 */
function findAuthIndices(clientDataJSON: string): { challengeIndex: number; typeIndex: number } {
  const challengeIndex = clientDataJSON.indexOf(CHALLENGE_NEEDLE_PREFIX);
  const typeIndex = clientDataJSON.indexOf(TYPE_NEEDLE);
  if (challengeIndex === -1 || typeIndex === -1)
    throw new VericertsError(ErrorCodes.P256_SIG_INVALID);
  return { challengeIndex, typeIndex };
}

/**
 * Solady `WebAuthn.WebAuthnAuth` タプルの ABI エンコード
 * （`(bytes authenticatorData, string clientDataJSON, uint256 challengeIndex, uint256 typeIndex,
 * bytes32 r, bytes32 s)`）。`PasskeyValidator._tryDecode` は `abi.decode(signature, (WebAuthn.WebAuthnAuth))`
 * で読む —— 単一の動的タプル引数として、実体の前に「タプル本体へのオフセット」ワード（常に `0x20`）が
 * 付く標準 ABI エンコードのため、タプル自身の head（6 ワード）より前にこのオフセットワードを 1 つ余分に置く
 * （`abi.encode(struct)` と `abi.encode(tuple(...))` が同じ動的型の扱いを受けることに対応。ethers
 * `AbiCoder.encode(['tuple(...)'], [obj])` の出力と一致することをテストで固定する）。
 */
function encodeWebAuthnAuth(params: {
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  challengeIndex: number;
  typeIndex: number;
  r: Uint8Array;
  s: Uint8Array;
}): Uint8Array {
  const HEAD_WORDS = 6;
  const headSize = HEAD_WORDS * WORD_SIZE;
  const authDataTail = encodeDynamicBytesTail(params.authenticatorData);
  const clientDataTail = encodeDynamicBytesTail(params.clientDataJSON);
  const clientDataOffset = headSize + authDataTail.length;
  const tuple = concatBytes(
    uint256Word(headSize), // authenticatorData のオフセット（先頭ダイナミックフィールド、タプル本体先頭からの相対値）。
    uint256Word(clientDataOffset), // clientDataJSON のオフセット。
    uint256Word(params.challengeIndex),
    uint256Word(params.typeIndex),
    padWord(params.r),
    padWord(params.s),
    authDataTail,
    clientDataTail,
  );
  return concatBytes(uint256Word(WORD_SIZE), tuple); // 単一動的タプル引数の先頭オフセットワード（常に 0x20）。
}

/**
 * 単一 Validator 形式の UserOperation 署名 envelope（`abi.encode(address validator, bytes innerSig)`）
 * を組み立てる（`validator-abi.ts` の `encodeValidatorSignature` と同一 envelope）。
 */
function encodeValidatorEnvelope(validatorAddress: string, innerSig: Uint8Array): Hex {
  const head = concatBytes(addressWord(validatorAddress), uint256Word(2 * WORD_SIZE));
  const tail = encodeDynamicBytesTail(innerSig);
  return `0x${bytesToHex(concatBytes(head, tail))}` as Hex;
}

/**
 * WebAuthn assertion と Validator のアドレスから署名を組み立て、署名済みの UserOperation を同期的に返す。
 *
 * @param userOp 署名対象の UserOperation（`signature` 以外は確定済み。呼び出し側が事前に
 *   `getUserOpHash(userOp, chainId)` を challenge として WebAuthn assertion を取得済みである前提。
 *   本関数はその一致を再検証しない — 真正性の判定はチェーン上の `PasskeyValidator` が行う）。
 * @param assertion WebAuthn API から取得した assertion。
 * @param validatorAddress 検証に使う `PasskeyValidator` インスタンスのアドレス。
 * @returns `signature` を設定した UserOperation の複製。
 * @throws DER 署名のデコード失敗、または `clientDataJSON` に `"type":"webauthn.get"` /
 *   `"challenge":"..."` の部分文字列が無い場合（VericertsError、code `7150`）。
 * @throws `validatorAddress` が `0x` + 40 hex 形式でない場合（VericertsError、code `4070`）。
 */
export function signUserOpWithPasskey(
  userOp: UserOperationV07,
  assertion: WebAuthnAssertion,
  validatorAddress: string,
): UserOperationV07 {
  const clientDataJSON = new TextDecoder().decode(assertion.clientDataJSON);
  const { challengeIndex, typeIndex } = findAuthIndices(clientDataJSON);
  const { r, s } = decodeDerSignature(assertion.signature);
  const innerSig = encodeWebAuthnAuth({
    authenticatorData: assertion.authenticatorData,
    clientDataJSON: utf8ToBytes(clientDataJSON),
    challengeIndex,
    typeIndex,
    r,
    s,
  });
  return { ...userOp, signature: encodeValidatorEnvelope(validatorAddress, innerSig) };
}
