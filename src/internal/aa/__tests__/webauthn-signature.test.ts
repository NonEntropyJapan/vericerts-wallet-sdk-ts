/**
 * `signUserOpWithPasskey` のユニットテスト。
 *
 * ABI エンコードの正しさは ethers `AbiCoder`（本番実装は使わない参照実装）との独立エンコードで
 * バイト一致を確認する（`validator-abi.test.ts` と同方針）。DER→raw(r,s) 変換は `@noble/curves`
 * の署名で実データを作り、往復させて検証する。
 */

import { describe, expect, test } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { AbiCoder } from 'ethers';
import { VericertsError } from '../../errors.js';
import type { Hex, UserOperationV07 } from '../types.js';
import { signUserOpWithPasskey, type WebAuthnAssertion } from '../webauthn-signature.js';

const VALIDATOR = '0x1111111111111111111111111111111111111111';
const SENDER = '0x2222222222222222222222222222222222222222' as Hex;

const BASE_USER_OP: UserOperationV07 = {
  sender: SENDER,
  nonce: 5n,
  callData: '0xabcdef' as Hex,
  callGasLimit: 100_000n,
  verificationGasLimit: 200_000n,
  preVerificationGas: 50_000n,
  maxFeePerGas: 1_000_000_000n,
  maxPriorityFeePerGas: 100_000_000n,
  signature: '0x' as Hex,
};

const CLIENT_DATA_JSON =
  '{"type":"webauthn.get","challenge":"c2FtcGxl","origin":"https://wallet.example"}';
const AUTHENTICATOR_DATA = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

function buildAssertion(
  overrides?: Partial<{ clientDataJSON: string; signatureDer: Uint8Array }>,
): {
  assertion: WebAuthnAssertion;
  r: bigint;
  s: bigint;
} {
  const privateKey = new Uint8Array(32).fill(9);
  const message = new Uint8Array(32).fill(3);
  const sig = p256.sign(message, privateKey, { format: 'der' });
  const parsed = p256.Signature.fromBytes(sig, 'der');
  const clientDataJSON = overrides?.clientDataJSON ?? CLIENT_DATA_JSON;
  return {
    assertion: {
      authenticatorData: AUTHENTICATOR_DATA,
      clientDataJSON: new TextEncoder().encode(clientDataJSON),
      signature: overrides?.signatureDer ?? sig,
    },
    r: parsed.r,
    s: parsed.s,
  };
}

/** ethers を使い、参照実装として envelope + WebAuthnAuth の期待バイト列を独立に組み立てる。 */
function expectedSignatureHex(params: {
  validator: string;
  authenticatorData: Uint8Array;
  clientDataJSON: string;
  challengeIndex: number;
  typeIndex: number;
  r: bigint;
  s: bigint;
}): string {
  const coder = AbiCoder.defaultAbiCoder();
  const innerSig = coder.encode(
    [
      'tuple(bytes authenticatorData, string clientDataJSON, uint256 challengeIndex, uint256 typeIndex, bytes32 r, bytes32 s)',
    ],
    [
      {
        authenticatorData: `0x${Buffer.from(params.authenticatorData).toString('hex')}`,
        clientDataJSON: params.clientDataJSON,
        challengeIndex: params.challengeIndex,
        typeIndex: params.typeIndex,
        r: `0x${params.r.toString(16).padStart(64, '0')}`,
        s: `0x${params.s.toString(16).padStart(64, '0')}`,
      },
    ],
  );
  return coder.encode(['address', 'bytes'], [params.validator, innerSig]);
}

describe('signUserOpWithPasskey', () => {
  test('WebAuthnAuth envelope が ethers 参照実装とバイト一致する', () => {
    const { assertion, r, s } = buildAssertion();
    const signed = signUserOpWithPasskey(BASE_USER_OP, assertion, VALIDATOR);

    const expected = expectedSignatureHex({
      validator: VALIDATOR,
      authenticatorData: AUTHENTICATOR_DATA,
      clientDataJSON: CLIENT_DATA_JSON,
      challengeIndex: CLIENT_DATA_JSON.indexOf('"challenge":"'),
      typeIndex: CLIENT_DATA_JSON.indexOf('"type":"webauthn.get"'),
      r,
      s,
    });
    expect(signed.signature.toLowerCase()).toBe(expected.toLowerCase());
  });

  test('signature 以外のフィールドは変更しない', () => {
    const { assertion } = buildAssertion();
    const signed = signUserOpWithPasskey(BASE_USER_OP, assertion, VALIDATOR);
    expect({ ...signed, signature: undefined }).toEqual({ ...BASE_USER_OP, signature: undefined });
  });

  test('ethers でデコードすると r / s / 各インデックスが元の値に一致する（往復確認）', () => {
    const { assertion, r, s } = buildAssertion();
    const signed = signUserOpWithPasskey(BASE_USER_OP, assertion, VALIDATOR);

    const coder = AbiCoder.defaultAbiCoder();
    const [validator, innerSig] = coder.decode(['address', 'bytes'], signed.signature);
    expect((validator as string).toLowerCase()).toBe(VALIDATOR.toLowerCase());
    const [auth] = coder.decode(
      [
        'tuple(bytes authenticatorData, string clientDataJSON, uint256 challengeIndex, uint256 typeIndex, bytes32 r, bytes32 s)',
      ],
      innerSig as string,
    );
    expect(auth.clientDataJSON).toBe(CLIENT_DATA_JSON);
    expect(BigInt(auth.r)).toBe(r);
    expect(BigInt(auth.s)).toBe(s);
    expect(Number(auth.challengeIndex)).toBe(CLIENT_DATA_JSON.indexOf('"challenge":"'));
    expect(Number(auth.typeIndex)).toBe(CLIENT_DATA_JSON.indexOf('"type":"webauthn.get"'));
  });

  test('clientDataJSON に "challenge":" が無ければ 7150 で拒否する', () => {
    const { assertion } = buildAssertion({ clientDataJSON: '{"type":"webauthn.get"}' });
    expect(() => signUserOpWithPasskey(BASE_USER_OP, assertion, VALIDATOR)).toThrow(VericertsError);
    try {
      signUserOpWithPasskey(BASE_USER_OP, assertion, VALIDATOR);
    } catch (e) {
      expect((e as VericertsError).code).toBe('7150');
    }
  });

  test('clientDataJSON の type が webauthn.get でなければ 7150 で拒否する', () => {
    const { assertion } = buildAssertion({
      clientDataJSON: '{"type":"webauthn.create","challenge":"c2FtcGxl"}',
    });
    expect(() => signUserOpWithPasskey(BASE_USER_OP, assertion, VALIDATOR)).toThrow(VericertsError);
  });

  test('不正な DER 署名は 7150 で拒否する', () => {
    const { assertion } = buildAssertion({
      signatureDer: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    });
    expect(() => signUserOpWithPasskey(BASE_USER_OP, assertion, VALIDATOR)).toThrow(VericertsError);
  });

  test('validatorAddress が不正な EVM アドレス形式なら 4070 で拒否する', () => {
    const { assertion } = buildAssertion();
    try {
      signUserOpWithPasskey(BASE_USER_OP, assertion, 'not-an-address');
      throw new Error('unreachable');
    } catch (e) {
      expect((e as VericertsError).code).toBe('4070');
    }
  });

  test('高 s の DER 署名は s <= N/2 へ正規化され、同一メッセージ・公開鍵で low-s 検証が通る', () => {
    const privateKey = new Uint8Array(32).fill(9);
    const message = new Uint8Array(32).fill(3);
    const publicKey = p256.getPublicKey(privateKey);
    const n = p256.Point.Fn.ORDER;
    const low = p256.Signature.fromBytes(p256.sign(message, privateKey, { format: 'der' }), 'der');
    const high = new p256.Signature(low.r, n - low.s);
    expect(high.hasHighS()).toBe(true);

    const { assertion } = buildAssertion({ signatureDer: high.toBytes('der') });
    const signed = signUserOpWithPasskey(BASE_USER_OP, assertion, VALIDATOR);

    const coder = AbiCoder.defaultAbiCoder();
    const [, innerSig] = coder.decode(['address', 'bytes'], signed.signature);
    const [auth] = coder.decode(
      [
        'tuple(bytes authenticatorData, string clientDataJSON, uint256 challengeIndex, uint256 typeIndex, bytes32 r, bytes32 s)',
      ],
      innerSig as string,
    );
    const r = BigInt(auth.r);
    const s = BigInt(auth.s);
    expect(s <= n / 2n).toBe(true);
    expect(s).toBe(low.s);
    expect(r).toBe(low.r);
    const compact = new p256.Signature(r, s).toBytes('compact');
    expect(p256.verify(compact, message, publicKey, { lowS: true })).toBe(true);
  });
});
