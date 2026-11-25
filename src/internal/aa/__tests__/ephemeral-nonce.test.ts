/**
 * ephemeral nonce クレーム束縛値生成のユニットテスト。
 *
 * 束縛定義 `keccak256(abi.encodePacked(ephemeralSigner)) % r` が、
 * コントラクト SsoSignature.ephemeralCommitment、認証回路、テストベクタ生成処理
 * の 3 者と同一値を生成することを、確定した既知ベクタで検証する（swapped-signer 対策の要）。
 */

import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../errors.js';
import {
  BN254_SCALAR_FIELD,
  ephemeralNonceClaim,
  ephemeralNonceValue,
} from '../ephemeral-nonce.js';

// Groth16 検証用ベクタの EPHEMERAL_ADDRESS と NONCE。
// NONCE = SsoSignature.ephemeralCommitment(EPHEMERAL_ADDRESS)
//       = keccak256(abi.encodePacked(addr)) % BN254_r。ここと必ず一致させる。
const FIXTURE_ADDRESS = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const FIXTURE_NONCE = '87116170846203849283213838599994667515279361563011690949839595195930248640';

describe('ephemeralNonceValue', () => {
  test('フィクスチャ address が ZKValidator/回路と同じ束縛値を生成する', () => {
    expect(ephemeralNonceValue(FIXTURE_ADDRESS)).toBe(BigInt(FIXTURE_NONCE));
  });

  test('BN254 スカラー域 r 未満に還元される', () => {
    // 複数のアドレスで域内であることを確認。
    for (const addr of [
      '0x0000000000000000000000000000000000000000',
      '0xffffffffffffffffffffffffffffffffffffffff',
      FIXTURE_ADDRESS,
    ]) {
      const v = ephemeralNonceValue(addr);
      expect(v).toBeGreaterThanOrEqual(0n);
      expect(v).toBeLessThan(BN254_SCALAR_FIELD);
    }
  });

  test('EIP-55 チェックサムの大文字小文字は値に影響しない', () => {
    expect(ephemeralNonceValue(FIXTURE_ADDRESS)).toBe(
      ephemeralNonceValue(FIXTURE_ADDRESS.toLowerCase()),
    );
  });

  test('0x プレフィックスの有無で値が変わらない', () => {
    expect(ephemeralNonceValue(FIXTURE_ADDRESS)).toBe(
      ephemeralNonceValue(FIXTURE_ADDRESS.slice(2)),
    );
  });

  test('異なる ephemeral signer は異なる束縛値になる', () => {
    expect(ephemeralNonceValue(FIXTURE_ADDRESS)).not.toBe(
      ephemeralNonceValue('0x0000000000000000000000000000000000000001'),
    );
  });

  test('長さ・文字種が不正なアドレスは拒否する', () => {
    expect(() => ephemeralNonceValue('0x1234')).toThrow();
    expect(() => ephemeralNonceValue('0xZZ997970C51812dc3A010C7d01b50e0d17dc79C8')).toThrow();
    expect(() => ephemeralNonceValue('')).toThrow();
  });

  test('不正なアドレスの拒否は VericertsError（code 4070）である', () => {
    // aa/user-operation.ts の EVM アドレス形式不正と同じエラー契約に揃える。
    // 素の Error のままだと instanceof VericertsError で分岐する呼び出し側をすり抜ける。
    try {
      ephemeralNonceValue('0x1234');
      throw new Error('unreachable: 不正なアドレスで例外が投げられなかった');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('4070');
    }
  });
});

describe('ephemeralNonceClaim', () => {
  test('正準 10 進文字列（先頭 0 なし）を返す', () => {
    const claim = ephemeralNonceClaim(FIXTURE_ADDRESS);
    expect(claim).toBe(FIXTURE_NONCE);
    expect(claim).toBe(ephemeralNonceValue(FIXTURE_ADDRESS).toString(10));
    expect(/^(0|[1-9][0-9]*)$/.test(claim)).toBe(true);
    expect(claim.length).toBeLessThanOrEqual(78);
  });

  test('claim 文字列を整数化すると束縛値に戻る（回路の整数化と可逆）', () => {
    expect(BigInt(ephemeralNonceClaim(FIXTURE_ADDRESS))).toBe(ephemeralNonceValue(FIXTURE_ADDRESS));
  });
});
