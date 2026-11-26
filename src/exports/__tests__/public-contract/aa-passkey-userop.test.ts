/**
 * Passkey による UserOperation 署名の公開契約。`@vericerts/vericerts-wallet-sdk/aa` から引いた公開面だけで、
 * 組込先が UserOperation と WebAuthn assertion を組み立てて署名 envelope を得られることを固定する。
 * 内部パス経由では「公開したつもりの面」が通っているかを確かめられないので `../../aa.js` を使う。
 * ABI の参照実装とのバイト一致・往復・DER の各種異常は内部テスト（`internal/aa/__tests__/webauthn-signature.test.ts`）
 * が担い、ここでは公開面から見た入出力の形と既知入力に対する出力の固定だけを扱う。
 */

import { describe, expect, test } from 'bun:test';
import {
  ENTRY_POINT_V07_ADDRESS,
  type Hex,
  signUserOpWithPasskey,
  type UserOperationV07,
  type WebAuthnAssertion,
} from '../../aa.js';
import { VericertsError } from '../../common.js';

const VALIDATOR = '0x1111111111111111111111111111111111111111';

const USER_OP: UserOperationV07 = {
  sender: '0x2222222222222222222222222222222222222222',
  nonce: 5n,
  callData: '0xabcdef',
  callGasLimit: 100_000n,
  verificationGasLimit: 200_000n,
  preVerificationGas: 50_000n,
  maxFeePerGas: 1_000_000_000n,
  maxPriorityFeePerGas: 100_000_000n,
  signature: '0x',
};

const CLIENT_DATA_JSON =
  '{"type":"webauthn.get","challenge":"c2FtcGxl","origin":"https://wallet.example"}';

/**
 * 内部テストと同じ P-256 署名（秘密鍵 0x09 × 32・メッセージ 0x03 × 32 の決定論的署名、low-s）の DER。
 * 内部テストはこの入力に対する出力が ethers `AbiCoder` の参照実装とバイト一致することを確かめている。
 */
const SIGNATURE_DER =
  '3045022100a27b82e1bfc5f7e558373b488d8e622f3e1d14906f53f6cf036e6a73620d9585' +
  '02203709f677efa8c1e102f8cf4667784e0bab34a51c03fc14c298ed0a34fd955ceb';

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function assertion(clientDataJSON = CLIENT_DATA_JSON): WebAuthnAssertion {
  return {
    authenticatorData: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    clientDataJSON: new TextEncoder().encode(clientDataJSON),
    signature: hexToBytes(SIGNATURE_DER),
  };
}

/** `abi.encode(address validator, bytes innerSig)`（innerSig は Solady `WebAuthn.WebAuthnAuth`）の 32 バイト単位の期待値。 */
const EXPECTED_SIGNATURE_WORDS = [
  '0000000000000000000000001111111111111111111111111111111111111111', // validator
  '0000000000000000000000000000000000000000000000000000000000000040', // innerSig のオフセット
  '00000000000000000000000000000000000000000000000000000000000001a0', // innerSig の長さ（416 バイト）
  '0000000000000000000000000000000000000000000000000000000000000020', // タプル本体へのオフセット
  '00000000000000000000000000000000000000000000000000000000000000c0', // authenticatorData のオフセット
  '0000000000000000000000000000000000000000000000000000000000000100', // clientDataJSON のオフセット
  '0000000000000000000000000000000000000000000000000000000000000017', // challengeIndex（23）
  '0000000000000000000000000000000000000000000000000000000000000001', // typeIndex（1）
  'a27b82e1bfc5f7e558373b488d8e622f3e1d14906f53f6cf036e6a73620d9585', // r
  '3709f677efa8c1e102f8cf4667784e0bab34a51c03fc14c298ed0a34fd955ceb', // s
  '0000000000000000000000000000000000000000000000000000000000000008', // authenticatorData の長さ
  '0102030405060708000000000000000000000000000000000000000000000000', // authenticatorData 本体
  '0000000000000000000000000000000000000000000000000000000000000050', // clientDataJSON の長さ（80）
  '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e67', // clientDataJSON 本体
  '65223a22633246746347786c222c226f726967696e223a2268747470733a2f2f',
  '77616c6c65742e6578616d706c65227d00000000000000000000000000000000',
];

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    return (error as VericertsError).code;
  }
  throw new Error('例外が発生しなかった');
}

describe('@vericerts/vericerts-wallet-sdk/aa: Passkey UserOperation 署名の公開契約', () => {
  test('ENTRY_POINT_V07_ADDRESS は EntryPoint v0.7 の決定論的アドレスである', () => {
    expect(ENTRY_POINT_V07_ADDRESS).toBe('0x0000000071727De22E5E9d8BAf0edAc6f37da032');
  });

  test('公開型だけで組み立てた入力に署名し、入力を変えずに signature だけ差し替えた別オブジェクトを返す', () => {
    const input = { ...USER_OP };
    const passkey = assertion();
    const signed: UserOperationV07 = signUserOpWithPasskey(input, passkey, VALIDATOR);

    expect(signed).not.toBe(input);
    expect(input).toEqual(USER_OP);
    expect(passkey).toEqual(assertion());
    const { signature, ...rest } = signed;
    const { signature: _unsigned, ...inputRest } = USER_OP;
    expect(rest).toEqual(inputRest);
    expect(signature).not.toBe(USER_OP.signature);
  });

  test('既知の入力に対する signature 全体が固定値と一致する', () => {
    const { signature } = signUserOpWithPasskey(USER_OP, assertion(), VALIDATOR);
    const expected: Hex = `0x${EXPECTED_SIGNATURE_WORDS.join('')}`;
    expect(signature).toBe(expected);
  });

  test('clientDataJSON に challenge が無ければ VericertsError（7150）で拒否する', () => {
    const run = () =>
      signUserOpWithPasskey(USER_OP, assertion('{"type":"webauthn.get"}'), VALIDATOR);
    expect(codeOf(run)).toBe('7150');
  });

  test('validatorAddress が EVM アドレス形式でなければ VericertsError（4070）で拒否する', () => {
    const run = () => signUserOpWithPasskey(USER_OP, assertion(), '0x1234');
    expect(codeOf(run)).toBe('4070');
  });
});
