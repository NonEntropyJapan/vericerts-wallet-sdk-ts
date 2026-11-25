import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../errors.js';
import {
  ASSET_CHAIN_IDS,
  type AssetChain,
  isSupportedChainId,
  resolveChainId,
  resolveChainName,
} from '../chains.js';

describe('asset chains（マルチチェーン解決）', () => {
  test('対応チェーン名をそれぞれの Chain ID に解決する', () => {
    expect(ASSET_CHAIN_IDS.mainnet).toBe(1);
    expect(ASSET_CHAIN_IDS.arbitrum).toBe(42161);
    expect(ASSET_CHAIN_IDS.soneium).toBe(1868);
    expect(ASSET_CHAIN_IDS.filecoin).toBe(314);
  });

  test('resolveChainId はチェーン名から Chain ID を返す', () => {
    expect(resolveChainId('mainnet')).toBe(1);
    expect(resolveChainId('arbitrum')).toBe(42161);
    expect(resolveChainId('soneium')).toBe(1868);
    expect(resolveChainId('filecoin')).toBe(314);
  });

  test('resolveChainName は Chain ID からチェーン名を返す', () => {
    expect(resolveChainName(1)).toBe('mainnet');
    expect(resolveChainName(42161)).toBe('arbitrum');
    expect(resolveChainName(1868)).toBe('soneium');
    expect(resolveChainName(314)).toBe('filecoin');
  });

  test('resolveChainName は名前 → ID → 名前で往復一致する', () => {
    const chains: AssetChain[] = ['mainnet', 'arbitrum', 'soneium', 'filecoin'];
    for (const chain of chains) {
      expect(resolveChainName(resolveChainId(chain))).toBe(chain);
    }
  });

  test('resolveChainName は未対応 Chain ID で 4071 を投げる', () => {
    // 137 = Polygon（未対応）。
    expect(() => resolveChainName(137)).toThrow(VericertsError);
    try {
      resolveChainName(137);
    } catch (error) {
      expect((error as VericertsError).code).toBe('4071');
    }
  });

  test('isSupportedChainId は対応/未対応を判定する', () => {
    expect(isSupportedChainId(1)).toBe(true);
    expect(isSupportedChainId(42161)).toBe(true);
    expect(isSupportedChainId(1868)).toBe(true);
    expect(isSupportedChainId(314)).toBe(true);
    expect(isSupportedChainId(137)).toBe(false);
    expect(isSupportedChainId(0)).toBe(false);
  });
});
