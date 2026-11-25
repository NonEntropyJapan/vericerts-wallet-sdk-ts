import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { parseDidEthr } from '../../identity/ethr/did-url.js';
import { formatEthrDid, parseEthrDid } from '../did-ethr.js';

const ADDR_A = '0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa';
const LOWER_ADDR = '0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb';

/** 受け付ける形と、そのパース結果。 */
const ACCEPTED: Array<[string, { chainId: number; address: string }]> = [
  [`did:ethr:${ADDR_A}`, { chainId: 1, address: ADDR_A }],
  [`did:ethr:${LOWER_ADDR}`, { chainId: 1, address: LOWER_ADDR }],
  [`did:ethr:1:${ADDR_A}`, { chainId: 1, address: ADDR_A }],
  [`did:ethr:0:${ADDR_A}`, { chainId: 0, address: ADDR_A }],
  [`did:ethr:42161:${ADDR_A}`, { chainId: 42161, address: ADDR_A }],
  [`did:ethr:9007199254740991:${ADDR_A}`, { chainId: 9007199254740991, address: ADDR_A }],
];

/** 拒否する形（いずれも 2001）。 */
const REJECTED: string[] = [
  `did:pkh:${ADDR_A}`,
  `DID:ethr:${ADDR_A}`,
  'did:ethr:',
  'did:ethr:0x1234',
  'did:ethr:0xZZ16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb',
  // EIP-55 チェックサム不一致の大小文字混在。
  'did:ethr:0xAb16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb',
  `did:ethr::${ADDR_A}`,
  `did:ethr:1:`,
  `did:ethr:mainnet:${ADDR_A}`,
  `did:ethr:0x1:${ADDR_A}`,
  `did:ethr:01:${ADDR_A}`,
  `did:ethr:-1:${ADDR_A}`,
  `did:ethr:9007199254740992:${ADDR_A}`,
  `did:ethr:99999999999999999999:${ADDR_A}`,
  `did:ethr:1:2:${ADDR_A}`,
  `did:ethr:1:${ADDR_A}:extra`,
];

// did:ethr のパースは identity/ethr の parseDidEthr に一本化している。
// 公開名が 2 つあるため、両方が同じ形を受け付け・拒否することを固定する。
describe.each([
  ['parseEthrDid', parseEthrDid],
  ['parseDidEthr', parseDidEthr],
] as const)('%s の受理・拒否', (_name, parse) => {
  test.each(ACCEPTED)('%s を受け付ける', (did, expected) => {
    expect(parse(did)).toEqual(expected);
  });

  test.each(REJECTED)('%s は 2001', (did) => {
    let caught: unknown;
    try {
      parse(did);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
  });
});

describe('parseEthrDid', () => {
  test('chainId 省略は Mainnet（1）として解釈', () => {
    expect(parseEthrDid(`did:ethr:${ADDR_A}`)).toEqual({ chainId: 1, address: ADDR_A });
  });

  test('chainId 付き did:ethr を分解', () => {
    expect(parseEthrDid(`did:ethr:42161:${ADDR_A}`)).toEqual({
      chainId: 42161,
      address: ADDR_A,
    });
  });

  test('安全整数を超える chainId は 2001（identity/ethr の parseDidEthr と同じ受理範囲）', () => {
    for (const chainId of ['99999999999999999999', '9007199254740993', '9007199254740992']) {
      expect(() => parseEthrDid(`did:ethr:${chainId}:${ADDR_A}`)).toThrow(VericertsError);
    }
    expect(parseEthrDid(`did:ethr:9007199254740991:${ADDR_A}`).chainId).toBe(9007199254740991);
  });

  test('プレフィックス不正は 2001', () => {
    expect(() => parseEthrDid(`did:key:${ADDR_A}`)).toThrow(VericertsError);
    try {
      parseEthrDid(`did:key:${ADDR_A}`);
    } catch (e) {
      expect((e as VericertsError).code).toBe('2001');
    }
  });

  test('アドレス形式不正（桁数）は 2001', () => {
    expect(() => parseEthrDid('did:ethr:0x1234')).toThrow(VericertsError);
  });

  test('chainId 先頭ゼロは 2001', () => {
    expect(() => parseEthrDid(`did:ethr:01:${ADDR_A}`)).toThrow(VericertsError);
  });

  test('3 セグメント以上は 2001', () => {
    expect(() => parseEthrDid(`did:ethr:1:2:${ADDR_A}`)).toThrow(VericertsError);
  });

  test('例外メッセージに DID 文字列・アドレスを含めない', () => {
    try {
      parseEthrDid('did:ethr:0xBAD');
    } catch (e) {
      const err = e as VericertsError;
      expect(err.message).not.toContain('0xBAD');
      expect(err.message).not.toContain('did:ethr');
    }
  });
});

describe('formatEthrDid', () => {
  test('chainId 1 はアドレスのみ', () => {
    expect(formatEthrDid({ chainId: 1, address: ADDR_A })).toBe(`did:ethr:${ADDR_A}`);
  });

  test('chainId !=1 は chainId 付き', () => {
    expect(formatEthrDid({ chainId: 42161, address: ADDR_A })).toBe(`did:ethr:42161:${ADDR_A}`);
  });

  test('parse と format は往復する', () => {
    const did = `did:ethr:11155111:${ADDR_A}`;
    expect(formatEthrDid(parseEthrDid(did))).toBe(did);
  });
});
