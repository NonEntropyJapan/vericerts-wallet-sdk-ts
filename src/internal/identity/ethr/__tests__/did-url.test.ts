/**
 * parseDidEthr の検証。
 *
 * 省略形（chainId = 1）/ chainId 指定 / アドレス大小文字保持 / 各種形式不正
 * （プレフィックス・長さ・非数字・0x hex chainId・余分セグメント）が
 * VericertsError(2001) になることを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { parseDidEthr } from '../did-url.js';

/** EIP-55 チェックサム形式のサンプルアドレス。 */
const CHECKSUM_ADDRESS = '0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb';
/** 小文字形式の同一アドレス。 */
const LOWERCASE_ADDRESS = '0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb';

const expectInvalidDid = (fn: () => unknown): void => {
  expect(fn).toThrow(VericertsError);
  try {
    fn();
  } catch (e) {
    expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
  }
};

describe('parseDidEthr', () => {
  it('省略形は chainId = 1（Mainnet）にパースする', () => {
    expect(parseDidEthr(`did:ethr:${CHECKSUM_ADDRESS}`)).toEqual({
      chainId: 1,
      address: CHECKSUM_ADDRESS,
    });
  });

  it('chainId 指定をパースする（Arbitrum One = 42161）', () => {
    expect(parseDidEthr(`did:ethr:42161:${CHECKSUM_ADDRESS}`)).toEqual({
      chainId: 42161,
      address: CHECKSUM_ADDRESS,
    });
  });

  it('chainId = 1 を明示指定できる', () => {
    expect(parseDidEthr(`did:ethr:1:${CHECKSUM_ADDRESS}`)).toEqual({
      chainId: 1,
      address: CHECKSUM_ADDRESS,
    });
  });

  it('アドレスの大小文字を保持する', () => {
    expect(parseDidEthr(`did:ethr:${LOWERCASE_ADDRESS}`).address).toBe(LOWERCASE_ADDRESS);
    expect(parseDidEthr(`did:ethr:1:${CHECKSUM_ADDRESS}`).address).toBe(CHECKSUM_ADDRESS);
  });

  it('プレフィックス不正は INVALID_DID', () => {
    expectInvalidDid(() => parseDidEthr(`did:pkh:${CHECKSUM_ADDRESS}`));
  });

  it('アドレス長さ不正は INVALID_DID', () => {
    expectInvalidDid(() => parseDidEthr('did:ethr:0xabc'));
  });

  it('アドレス非 hex は INVALID_DID', () => {
    expectInvalidDid(() => parseDidEthr('did:ethr:0xZZ16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb'));
  });

  it('chainId 非数字は INVALID_DID', () => {
    expectInvalidDid(() => parseDidEthr(`did:ethr:mainnet:${CHECKSUM_ADDRESS}`));
  });

  it('0x hex chainId は INVALID_DID', () => {
    expectInvalidDid(() => parseDidEthr(`did:ethr:0x1:${CHECKSUM_ADDRESS}`));
  });

  it('Number.MAX_SAFE_INTEGER 超の chainId は INVALID_DID（精度劣化防止）', () => {
    // 9007199254740993 = MAX_SAFE_INTEGER + 2（Number で正確に表現できない）。
    expectInvalidDid(() => parseDidEthr(`did:ethr:9007199254740993:${CHECKSUM_ADDRESS}`));
  });

  it('余分なセグメントは INVALID_DID', () => {
    expectInvalidDid(() => parseDidEthr(`did:ethr:1:${CHECKSUM_ADDRESS}:extra`));
  });
});
