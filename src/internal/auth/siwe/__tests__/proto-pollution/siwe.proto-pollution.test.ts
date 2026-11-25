/**
 * `parseSiweMessage` の `Object.prototype` 汚染耐性テスト。
 *
 * viem/siwe の `parseSiweMessage`（siwe.ts では `viemParse` としてラップ）は、メッセージ中に
 * 対応する行が無いフィールドをキー自体が存在しない形で返す。`Chain ID:` 行を欠くと
 * suffixRegex 全体が不一致になり、uri / version / chainId / nonce / issuedAt が軒並み欠落する。
 * この戻り値を分割代入・プロパティアクセスで読むとプロトタイプ鎖を辿るため、
 * `Object.prototype` が汚染された環境ではこの欠落メッセージでも継承値を「存在する」
 * フィールドとして読んでしまい、必須フィールド欠落の検査（8041）を素通りし得る。
 *
 * 検証内容:
 * - データ / アクセサ両汚染で、必須フィールド欠落メッセージが引き続き 8041 で拒否されること。
 * - データ / アクセサ両汚染下でも、明示的にフィールドを含む正当なメッセージは自身の値で
 *   パースできること（可用性・誤検知防止）。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { generateSiweMessage, parseSiweMessage, type SiweParams } from '../../siwe.js';

const TEST_ADDRESS = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

const baseParams: SiweParams = {
  domain: 'example.com',
  address: TEST_ADDRESS,
  uri: 'https://example.com/login',
  nonce: 'abcd1234',
  chainId: 1,
  statement: 'Sign in with Ethereum',
  issuedAt: new Date('2026-07-02T00:00:00.000Z'),
};

function expectCode(fn: () => unknown, code: VericertsError['code']): void {
  try {
    fn();
    throw new Error('should have thrown');
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(code);
  }
}

function missingChainIdMessage(): string {
  return generateSiweMessage(baseParams).replace(/Chain ID: \d+\n/, '');
}

describe('parseSiweMessage: Object.prototype 汚染', () => {
  const pollutedFields = {
    domain: baseParams.domain,
    address: TEST_ADDRESS,
    uri: baseParams.uri,
    version: '1',
    chainId: baseParams.chainId,
    nonce: baseParams.nonce,
    issuedAt: baseParams.issuedAt,
  };

  it('データ汚染: Chain ID 行欠落のメッセージは継承値を採用せず 8041', () => {
    withPollutedPrototype(pollutedFields, () => {
      expectCode(() => parseSiweMessage(missingChainIdMessage()), ErrorCodes.SIWE_MESSAGE_INVALID);
    });
  });

  it('アクセサ汚染: Chain ID 行欠落のメッセージは継承値を採用せず 8041', () => {
    const getters = Object.fromEntries(
      Object.entries(pollutedFields).map(([key, value]) => [key, () => value]),
    );
    withPollutedPrototypeAccessor(getters, () => {
      expectCode(() => parseSiweMessage(missingChainIdMessage()), ErrorCodes.SIWE_MESSAGE_INVALID);
    });
  });

  it('データ汚染: 正当なメッセージは汚染下でも自身のフィールドでパースできる（可用性）', () => {
    const msg = generateSiweMessage(baseParams);
    const parsed = withPollutedPrototype(
      { domain: 'evil.example', chainId: 999, nonce: 'evilnonce-evil' },
      () => parseSiweMessage(msg),
    );
    expect(parsed.domain).toBe(baseParams.domain);
    expect(parsed.chainId).toBe(baseParams.chainId);
    expect(parsed.nonce).toBe(baseParams.nonce);
  });

  it('アクセサ汚染: 正当なメッセージは汚染下でも自身のフィールドでパースできる（可用性）', () => {
    const msg = generateSiweMessage(baseParams);
    const parsed = withPollutedPrototypeAccessor(
      {
        domain: () => 'evil.example',
        chainId: () => 999,
        nonce: () => 'evilnonce-evil',
      },
      () => parseSiweMessage(msg),
    );
    expect(parsed.domain).toBe(baseParams.domain);
    expect(parsed.chainId).toBe(baseParams.chainId);
    expect(parsed.nonce).toBe(baseParams.nonce);
  });
});
