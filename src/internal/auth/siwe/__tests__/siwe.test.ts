/**
 * SIWE（EIP-4361）+ ERC-1271 のユニットテスト。
 *
 * 検証内容:
 * - generateSiweMessage: EIP-4361 準拠のメッセージ生成 / 必須フィールド / nonce・アドレス検証。
 * - parseSiweMessage: 構造化マッピング / 必須欠落・version 不正・nonce 形式で 8041。
 *   `Object.prototype` 汚染下の挙動は proto-pollution/siwe.proto-pollution.test.ts を参照。
 * - validateSiweMessage: domain 一致 / expirationTime 未来 / notBefore 過去（期限・nonce・期限検証）。
 * - verifyEoaSignature: 実鍵の ERC-191 署名検証（正/誤アドレス）。
 * - verifyErc1271Signature: モック Erc1271Rpc でスマートアカウント署名検証（magicValue 一致/不一致/RPC 失敗）。
 */

import { describe, expect, it } from 'bun:test';
import { hashMessage, Interface, Wallet } from 'ethers';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  ERC1271_MAGIC_VALUE,
  type Erc1271Rpc,
  generateSiweMessage,
  type Hex,
  parseSiweMessage,
  type SiweParams,
  validateSiweMessage,
} from '../siwe.js';
import { verifyEoaSignature, verifyErc1271Signature } from '../siwe-verify.js';

// Anvil の 2 番目の既知テスト鍵（公開のダミー鍵。実運用鍵ではない）。
const TEST_PRIVATE_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
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

describe('generateSiweMessage', () => {
  it('EIP-4361 準拠のメッセージを生成する', () => {
    const msg = generateSiweMessage(baseParams);
    expect(msg).toContain('example.com wants you to sign in with your Ethereum account:');
    expect(msg).toContain(TEST_ADDRESS);
    expect(msg).toContain('Sign in with Ethereum');
    expect(msg).toContain('URI: https://example.com/login');
    expect(msg).toContain('Version: 1');
    expect(msg).toContain('Chain ID: 1');
    expect(msg).toContain('Nonce: abcd1234');
    expect(msg).toContain('Issued At: 2026-07-02T00:00:00.000Z');
  });

  it('生成したメッセージは parseSiweMessage で往復できる', () => {
    const parsed = parseSiweMessage(generateSiweMessage(baseParams));
    expect(parsed.domain).toBe('example.com');
    expect(parsed.address).toBe(TEST_ADDRESS);
    expect(parsed.nonce).toBe('abcd1234');
    expect(parsed.version).toBe('1');
    expect(parsed.chainId).toBe(1);
  });

  it('小文字アドレスを ERC-55 チェックサムへ正規化する', () => {
    const msg = generateSiweMessage({ ...baseParams, address: TEST_ADDRESS.toLowerCase() });
    expect(msg).toContain(TEST_ADDRESS);
  });

  it('アドレス形式が不正なら 4070', () => {
    expectCode(
      () => generateSiweMessage({ ...baseParams, address: '0xnope' }),
      ErrorCodes.INVALID_EVM_ADDRESS,
    );
  });

  it('nonce が 8 文字未満なら 8041', () => {
    expectCode(
      () => generateSiweMessage({ ...baseParams, nonce: 'abc123' }),
      ErrorCodes.SIWE_MESSAGE_INVALID,
    );
  });

  it('nonce に記号が含まれると 8041', () => {
    expectCode(
      () => generateSiweMessage({ ...baseParams, nonce: 'abcd-123' }),
      ErrorCodes.SIWE_MESSAGE_INVALID,
    );
  });
});

describe('parseSiweMessage', () => {
  it('必須・任意フィールドを構造化する', () => {
    const msg = generateSiweMessage({
      ...baseParams,
      expirationTime: new Date('2026-07-02T01:00:00.000Z'),
      notBefore: new Date('2026-07-01T00:00:00.000Z'),
      requestId: 'req-1',
      resources: ['https://example.com/a', 'https://example.com/b'],
    });
    const parsed = parseSiweMessage(msg);
    expect(parsed.expirationTime).toBe('2026-07-02T01:00:00.000Z');
    expect(parsed.notBefore).toBe('2026-07-01T00:00:00.000Z');
    expect(parsed.requestId).toBe('req-1');
    expect(parsed.resources).toEqual(['https://example.com/a', 'https://example.com/b']);
  });

  it('空文字列は 8041', () => {
    expectCode(() => parseSiweMessage(''), ErrorCodes.SIWE_MESSAGE_INVALID);
  });

  it('SIWE 形式でない文字列は 8041', () => {
    expectCode(() => parseSiweMessage('just some random text'), ErrorCodes.SIWE_MESSAGE_INVALID);
  });

  it('version が "2" だと 8041', () => {
    const bad = generateSiweMessage(baseParams).replace('Version: 1', 'Version: 2');
    expectCode(() => parseSiweMessage(bad), ErrorCodes.SIWE_MESSAGE_INVALID);
  });

  it('nonce 欠落だと 8041', () => {
    const bad = generateSiweMessage(baseParams).replace(/Nonce: abcd1234\n/, '');
    expectCode(() => parseSiweMessage(bad), ErrorCodes.SIWE_MESSAGE_INVALID);
  });

  it('statement 無しのメッセージも往復できる（構造検査が statement 任意を許す）', () => {
    const { statement: _statement, ...withoutStatement } = baseParams;
    const parsed = parseSiweMessage(generateSiweMessage(withoutStatement));
    expect(parsed.statement).toBeUndefined();
    expect(parsed.nonce).toBe('abcd1234');
  });

  it('statement に埋め込んだ偽の URI/Nonce/Issued At/Expiration Time ブロックは 8041', () => {
    const injected = [
      'hello',
      'URI: https://fake',
      'Version: 1',
      'Chain ID: 1',
      'Nonce: abcdefgh',
      'Issued At: 2999-01-01T00:00:00Z',
      'Expiration Time: 2999-01-02T00:00:00Z',
    ].join('\n');
    const message = generateSiweMessage({
      ...baseParams,
      statement: 'PLACEHOLDER',
      issuedAt: new Date('2020-01-01T00:00:00.000Z'),
      expirationTime: new Date('2020-01-02T00:00:00.000Z'),
    }).replace('PLACEHOLDER', injected);
    expectCode(() => parseSiweMessage(message), ErrorCodes.SIWE_MESSAGE_INVALID);
  });

  it('statement が複数行なら（フィールド行を含まなくても）8041（EIP-4361 ABNF）', () => {
    const message = generateSiweMessage({ ...baseParams, statement: 'PLACEHOLDER' }).replace(
      'PLACEHOLDER',
      'line1\nline2',
    );
    expectCode(() => parseSiweMessage(message), ErrorCodes.SIWE_MESSAGE_INVALID);
  });

  it('Expiration Time / Not Before / Request ID 行の重複は 8041', () => {
    const message = generateSiweMessage({
      ...baseParams,
      expirationTime: new Date('2026-07-02T01:00:00.000Z'),
    });
    const duplicated = message.replace(
      /Expiration Time: .+/,
      (line) => `${line}\nExpiration Time: 2999-01-02T00:00:00.000Z`,
    );
    expectCode(() => parseSiweMessage(duplicated), ErrorCodes.SIWE_MESSAGE_INVALID);
  });

  it('address が全小文字・全大文字・チェックサム不一致の混在表記なら 4070（正規化して受理しない）', () => {
    const message = generateSiweMessage(baseParams);
    const withAddress = (address: string): string => message.replace(TEST_ADDRESS, address);
    const body = TEST_ADDRESS.slice(2);
    const flipped = body.replace(/[a-f]/i, (c) =>
      c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase(),
    );
    for (const bad of [TEST_ADDRESS.toLowerCase(), `0x${body.toUpperCase()}`, `0x${flipped}`]) {
      expectCode(() => parseSiweMessage(withAddress(bad)), ErrorCodes.INVALID_EVM_ADDRESS);
    }
  });
});

describe('validateSiweMessage', () => {
  const parsed = parseSiweMessage(
    generateSiweMessage({
      ...baseParams,
      expirationTime: new Date('2026-07-02T02:00:00.000Z'),
      notBefore: new Date('2026-07-01T00:00:00.000Z'),
    }),
  );
  const now = new Date('2026-07-02T00:30:00.000Z');

  it('domain 一致・期限内なら例外を投げない', () => {
    expect(() => validateSiweMessage(parsed, 'example.com', now)).not.toThrow();
  });

  it('domain 不一致は 8041（フィッシング防止）', () => {
    expectCode(() => validateSiweMessage(parsed, 'evil.com', now), ErrorCodes.SIWE_MESSAGE_INVALID);
  });

  it('expirationTime を過ぎていると 8041', () => {
    const past = new Date('2026-07-02T03:00:00.000Z');
    expectCode(
      () => validateSiweMessage(parsed, 'example.com', past),
      ErrorCodes.SIWE_MESSAGE_INVALID,
    );
  });

  it('notBefore より前だと 8041', () => {
    const early = new Date('2026-06-30T00:00:00.000Z');
    expectCode(
      () => validateSiweMessage(parsed, 'example.com', early),
      ErrorCodes.SIWE_MESSAGE_INVALID,
    );
  });
});

describe('verifyEoaSignature', () => {
  it('正しい鍵の ERC-191 署名を検証できる', async () => {
    const wallet = new Wallet(TEST_PRIVATE_KEY);
    const message = generateSiweMessage(baseParams);
    const signature = await wallet.signMessage(message);
    expect(verifyEoaSignature(message, signature, TEST_ADDRESS)).toBe(true);
  });

  it('別アドレスを期待すると false', async () => {
    const wallet = new Wallet(TEST_PRIVATE_KEY);
    const message = generateSiweMessage(baseParams);
    const signature = await wallet.signMessage(message);
    const other = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
    expect(verifyEoaSignature(message, signature, other)).toBe(false);
  });

  it('壊れた署名は false（例外を投げない）', () => {
    expect(verifyEoaSignature('msg', '0x1234', TEST_ADDRESS)).toBe(false);
  });
});

/** テスト用の fake Erc1271Rpc。送られた calldata を lastData に記録する。 */
function fakeRpc(magicValue: string): Erc1271Rpc & { lastData?: Hex } {
  const state: Erc1271Rpc & { lastData?: Hex } = {
    async call(_to: string, data: Hex): Promise<Hex> {
      state.lastData = data;
      // eth_call の戻り値は bytes4 を 32 byte 左詰めで返す。
      return `${magicValue}${'0'.repeat(56)}` as Hex;
    },
  };
  return state;
}

describe('verifyErc1271Signature', () => {
  const message = 'smart account siwe body';
  const signature = '0xdeadbeef' as Hex;
  const account = TEST_ADDRESS;

  it('magicValue 0x1626ba7e なら有効（true）', async () => {
    const rpc = fakeRpc('0x1626ba7e');
    expect(await verifyErc1271Signature(rpc, message, signature, account)).toBe(true);
  });

  it('magicValue が異なると無効（false）', async () => {
    const rpc = fakeRpc('0xffffffff');
    expect(await verifyErc1271Signature(rpc, message, signature, account)).toBe(false);
  });

  it('ERC-1271 calldata が ethers の ABI エンコードと一致する', async () => {
    const rpc = fakeRpc(ERC1271_MAGIC_VALUE);
    const longSig =
      '0x6c980bd63b94ea604baa4b030985abc1727fa47b9dccc52acb5b48b261c5b98f6678463e7eea78de332d725d93ce360431e75da5a31dc065eb2c9bd0d7d15ab91c' as Hex;
    await verifyErc1271Signature(rpc, message, longSig, account);
    const iface = new Interface([
      'function isValidSignature(bytes32 hash, bytes signature) view returns (bytes4)',
    ]);
    const expected = iface.encodeFunctionData('isValidSignature', [hashMessage(message), longSig]);
    expect(rpc.lastData).toBe(expected as Hex);
  });

  it('アドレス形式不正は 4070', async () => {
    const rpc = fakeRpc(ERC1271_MAGIC_VALUE);
    await expect(verifyErc1271Signature(rpc, message, signature, '0xnope')).rejects.toMatchObject({
      code: ErrorCodes.INVALID_EVM_ADDRESS,
    });
  });

  it('署名が hex でないと 4070', async () => {
    const rpc = fakeRpc(ERC1271_MAGIC_VALUE);
    await expect(
      verifyErc1271Signature(rpc, message, 'not-hex' as Hex, account),
    ).rejects.toMatchObject({ code: ErrorCodes.INVALID_EVM_ADDRESS });
  });

  it('RPC が失敗すると 1021 を伝播する', async () => {
    const rpc: Erc1271Rpc = {
      async call(): Promise<Hex> {
        throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
      },
    };
    await expect(verifyErc1271Signature(rpc, message, signature, account)).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
  });
});
