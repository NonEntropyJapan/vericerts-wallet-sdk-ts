/**
 * issSubCommitment 束縛値生成のユニットテスト。
 *
 * 束縛定義 `uint256(keccak256(iss || 0x00 || sub)) % r` が、
 * ZKValidator.issSubCommitment / AccountFactory.computeSalt（同一プリイメージ）/
 * forge フィクスチャ（sso_commit.circom → Groth16Fixture.COMMITMENT）と同一値を生成することを、
 * 確定した既知ベクタで検証する（griefing 占有拒否の要）。
 */

import { describe, expect, test } from 'bun:test';
import { BN254_SCALAR_FIELD } from '../ephemeral-nonce.js';
import { issSubCommitmentClaim, issSubCommitmentValue } from '../iss-sub-commitment.js';

// Groth16 検証用ベクタの FIXTURE_ISS / FIXTURE_SUB / COMMITMENT。
// COMMITMENT = uint256(keccak256(iss || 0x00 || sub)) % BN254_r（onInstall のオンチェーン再計算値）。
const FIXTURE_ISS = 'https://accounts.google.com';
const FIXTURE_SUB = 'victim-subject-1234567890';
const FIXTURE_COMMITMENT =
  '4793899124926785715621364425698394726868086629774101797556905148630191284855';

describe('issSubCommitmentValue', () => {
  test('フィクスチャ iss+sub が ZKValidator/回路/Factory と同じ束縛値を生成する', () => {
    expect(issSubCommitmentValue(FIXTURE_ISS, FIXTURE_SUB)).toBe(BigInt(FIXTURE_COMMITMENT));
  });

  test('BN254 スカラー域 r 未満に還元される', () => {
    for (const [iss, sub] of [
      ['', ''],
      ['https://appleid.apple.com', '001234.abcdef'],
      [FIXTURE_ISS, FIXTURE_SUB],
    ] as const) {
      const v = issSubCommitmentValue(iss, sub);
      expect(v).toBeGreaterThanOrEqual(0n);
      expect(v).toBeLessThan(BN254_SCALAR_FIELD);
    }
  });

  test('異なる iss+sub は異なる束縛値になる', () => {
    expect(issSubCommitmentValue(FIXTURE_ISS, FIXTURE_SUB)).not.toBe(
      issSubCommitmentValue(FIXTURE_ISS, 'other-subject'),
    );
    expect(issSubCommitmentValue(FIXTURE_ISS, FIXTURE_SUB)).not.toBe(
      issSubCommitmentValue('https://other.example', FIXTURE_SUB),
    );
  });

  test('区切り子 0x00 により長さ拡張衝突を防ぐ（("ab","c") ≠ ("a","bc")）', () => {
    // computeSalt = keccak256(iss || 0x00 || sub) と同一プリイメージなので境界衝突しない。
    expect(issSubCommitmentValue('ab', 'c')).not.toBe(issSubCommitmentValue('a', 'bc'));
  });

  // iss/sub 自体に区切り子 \x00 が含まれると、境界がずれて別の (iss, sub) の組が
  // 同一プリイメージに潰れ得る（例: iss="A",sub="B\x00C" と iss="A\x00B",sub="C" は
  // 共に "A\x00B\x00C" になる）。AccountFactory.computeSalt はこれを revert で拒否するため、
  // SDK 側も同じ入力を throw で拒否し前提を揃える。
  test('sub に 0x00 が含まれると throw する', () => {
    expect(() => issSubCommitmentValue('A', 'B\x00C')).toThrow(/NUL byte/);
  });

  test('iss に 0x00 が含まれると throw する', () => {
    expect(() => issSubCommitmentValue('A\x00B', 'C')).toThrow(/NUL byte/);
  });
});

describe('issSubCommitmentClaim', () => {
  test('正準 10 進文字列（先頭 0 なし）を返す', () => {
    const claim = issSubCommitmentClaim(FIXTURE_ISS, FIXTURE_SUB);
    expect(claim).toBe(FIXTURE_COMMITMENT);
    expect(claim).toBe(issSubCommitmentValue(FIXTURE_ISS, FIXTURE_SUB).toString(10));
    expect(/^(0|[1-9][0-9]*)$/.test(claim)).toBe(true);
  });

  test('claim 文字列を整数化すると束縛値に戻る（可逆）', () => {
    expect(BigInt(issSubCommitmentClaim(FIXTURE_ISS, FIXTURE_SUB))).toBe(
      issSubCommitmentValue(FIXTURE_ISS, FIXTURE_SUB),
    );
  });
});
