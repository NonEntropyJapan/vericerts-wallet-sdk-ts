/**
 * parseDidPkh / resolveDidPkh / createDidPkh / MethodPkh の検証。
 *
 * 代表ネットワーク（Mainnet / Arbitrum / Soneium / Filecoin）の
 * did:pkh を解決して 期待する DID Document 構造になること、形式が正しい任意の `eip155` chainId
 * （許可リストなし）を解決できること、アドレスの大小文字を保持すること、
 * createDidPkh → resolveDidPkh の往復一致、各種形式不正・非 eip155 名前空間が
 * VericertsError(2001) になること、create / update / deactivate が METHOD_NOT_SUPPORTED(2002)
 * になることを確認する（CAIP-10 パース / マルチチェーン解決 /
 * DID Document 構築のスナップショット）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createDidPkh, MethodPkh, parseDidPkh, resolveDidPkh } from '../method-pkh.js';

/** EIP-55 チェックサム形式のサンプルアドレス。 */
const CHECKSUM_ADDRESS = '0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb';
/** 素の小文字形式の同一アドレス。 */
const LOWERCASE_ADDRESS = '0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb';

/** 代表ネットワークの chainId と表示名（許可リストではない）。 */
const NETWORKS: ReadonlyArray<{ name: string; chainId: string }> = [
  { name: 'Ethereum Mainnet', chainId: '1' },
  { name: 'Arbitrum One', chainId: '42161' },
  { name: 'Soneium', chainId: '1868' },
  { name: 'Filecoin (FEVM)', chainId: '314' },
];

describe('resolveDidPkh', () => {
  for (const { name, chainId } of NETWORKS) {
    it(`${name}（eip155:${chainId}）を DID Document に解決する`, () => {
      const did = `did:pkh:eip155:${chainId}:${CHECKSUM_ADDRESS}`;
      const doc = resolveDidPkh(did);
      const vmId = `${did}#blockchainAccountId`;
      expect(doc['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
      ]);
      expect(doc.id).toBe(did);
      expect(doc.verificationMethod).toEqual([
        {
          id: vmId,
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: did,
          blockchainAccountId: `eip155:${chainId}:${CHECKSUM_ADDRESS}`,
        },
      ]);
      expect(doc.authentication).toEqual([vmId]);
      expect(doc.assertionMethod).toEqual([vmId]);
    });
  }

  it('EIP-55 チェックサムアドレスの大小文字を保持して解決する', () => {
    const did = `did:pkh:eip155:1:${CHECKSUM_ADDRESS}`;
    const doc = resolveDidPkh(did);
    expect(doc.verificationMethod[0]?.blockchainAccountId).toBe(`eip155:1:${CHECKSUM_ADDRESS}`);
  });

  it('小文字アドレスをそのまま保持して解決する', () => {
    const did = `did:pkh:eip155:1:${LOWERCASE_ADDRESS}`;
    const doc = resolveDidPkh(did);
    expect(doc.verificationMethod[0]?.blockchainAccountId).toBe(`eip155:1:${LOWERCASE_ADDRESS}`);
  });
});

describe('parseDidPkh', () => {
  it('CAIP-10 構成要素をパースする', () => {
    const parsed = parseDidPkh(`did:pkh:eip155:42161:${CHECKSUM_ADDRESS}`);
    expect(parsed).toEqual({
      namespace: 'eip155',
      chainId: '42161',
      address: CHECKSUM_ADDRESS,
      accountId: `eip155:42161:${CHECKSUM_ADDRESS}`,
    });
  });

  const expectInvalidDid = (fn: () => unknown): void => {
    expect(fn).toThrow(VericertsError);
    try {
      fn();
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  };

  it('プレフィックス不正は INVALID_DID', () => {
    expectInvalidDid(() => parseDidPkh(`did:key:eip155:1:${CHECKSUM_ADDRESS}`));
  });

  it('セグメント不足は INVALID_DID', () => {
    expectInvalidDid(() => parseDidPkh('did:pkh:eip155:1'));
  });

  it('セグメント過多は INVALID_DID', () => {
    expectInvalidDid(() => parseDidPkh(`did:pkh:eip155:1:${CHECKSUM_ADDRESS}:extra`));
  });

  it('chainId 非数字は INVALID_DID', () => {
    expectInvalidDid(() => parseDidPkh(`did:pkh:eip155:mainnet:${CHECKSUM_ADDRESS}`));
  });

  // 旧 CHAIN_ID_PATTERN（`/^[0-9]+$/`）は先頭ゼロを許容し、did:ethr 系（先頭ゼロ拒否）と
  // 挙動が食い違っていた。`did:pkh:eip155:007:...` のような非正準表現を拒否することを固定する。
  it('chainId 先頭ゼロは INVALID_DID', () => {
    expectInvalidDid(() => parseDidPkh(`did:pkh:eip155:007:${CHECKSUM_ADDRESS}`));
  });

  it('address 長さ不正は INVALID_DID', () => {
    expectInvalidDid(() => parseDidPkh('did:pkh:eip155:1:0xabc'));
  });

  it('address 非 hex は INVALID_DID', () => {
    expectInvalidDid(() =>
      parseDidPkh('did:pkh:eip155:1:0xZZ16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb'),
    );
  });

  it('非 eip155 名前空間（スコープ外）は INVALID_DID', () => {
    expectInvalidDid(() =>
      parseDidPkh('did:pkh:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:address1234567890'),
    );
  });
});

describe('createDidPkh', () => {
  it('CAIP-10 アカウントから DID と DID Document を生成する', () => {
    const { did, document } = createDidPkh({ chainId: '1', address: CHECKSUM_ADDRESS });
    expect(did).toBe(`did:pkh:eip155:1:${CHECKSUM_ADDRESS}`);
    expect(document.id).toBe(did);
    expect(document.verificationMethod[0]?.blockchainAccountId).toBe(
      `eip155:1:${CHECKSUM_ADDRESS}`,
    );
  });

  it('createDidPkh → resolveDidPkh が一致する（往復）', () => {
    const { did, document } = createDidPkh({ chainId: '1868', address: CHECKSUM_ADDRESS });
    expect(resolveDidPkh(did)).toEqual(document);
  });

  it('address 形式不正は INVALID_DID', () => {
    expect(() => createDidPkh({ chainId: '1', address: '0xabc' })).toThrow(VericertsError);
    try {
      createDidPkh({ chainId: '1', address: '0xabc' });
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });

  it('chainId 非数字は INVALID_DID', () => {
    expect(() => createDidPkh({ chainId: 'main', address: CHECKSUM_ADDRESS })).toThrow(
      VericertsError,
    );
    try {
      createDidPkh({ chainId: 'main', address: CHECKSUM_ADDRESS });
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });
});

describe('MethodPkh', () => {
  const method = new MethodPkh();

  it('メソッド名は pkh', () => {
    expect(method.method()).toBe('pkh');
  });

  it('resolve は did:pkh を解決する', async () => {
    const did = `did:pkh:eip155:1:${CHECKSUM_ADDRESS}`;
    const doc = await method.resolve(did);
    expect(doc.id).toBe(did);
  });

  const expectMethodNotSupported = async (fn: () => Promise<unknown>): Promise<void> => {
    try {
      await fn();
      throw new Error('expected to throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.METHOD_NOT_SUPPORTED);
    }
  };

  it('create は METHOD_NOT_SUPPORTED', async () => {
    await expectMethodNotSupported(() =>
      method.create({ keyType: 'secp256k1', publicKey: new Uint8Array(33) }),
    );
  });

  it('update は METHOD_NOT_SUPPORTED', async () => {
    await expectMethodNotSupported(() => method.update(`did:pkh:eip155:1:${CHECKSUM_ADDRESS}`, {}));
  });

  it('deactivate は METHOD_NOT_SUPPORTED', async () => {
    await expectMethodNotSupported(() => method.deactivate(`did:pkh:eip155:1:${CHECKSUM_ADDRESS}`));
  });
});

// did:pkh は許可リストを持たず、形式が正しい任意の eip155 chainId を受け付ける。
describe('任意の eip155 chainId（許可リストなし）', () => {
  const expectInvalidDid = (fn: () => unknown): void => {
    expect(fn).toThrow(VericertsError);
    try {
      fn();
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  };

  // 代表 4 チェーン（NETWORKS）に含まれない chainId。桁数の上限も設けない（Number の安全整数を超える値を含む）。
  for (const chainId of ['9999', '10', '8453', '0', '18446744073709551616']) {
    it(`eip155:${chainId} の did:pkh を解決できる`, () => {
      const did = `did:pkh:eip155:${chainId}:${CHECKSUM_ADDRESS}`;
      const doc = resolveDidPkh(did);
      expect(doc.id).toBe(did);
      expect(doc.verificationMethod[0]?.blockchainAccountId).toBe(
        `eip155:${chainId}:${CHECKSUM_ADDRESS}`,
      );
    });

    it(`eip155:${chainId} は createDidPkh → resolveDidPkh で往復する`, () => {
      const { did, document } = createDidPkh({ chainId, address: CHECKSUM_ADDRESS });
      expect(did).toBe(`did:pkh:eip155:${chainId}:${CHECKSUM_ADDRESS}`);
      expect(resolveDidPkh(did)).toEqual(document);
    });
  }

  it('chainId が先頭ゼロ（eip155:01）は INVALID_DID', () => {
    expectInvalidDid(() => resolveDidPkh(`did:pkh:eip155:01:${CHECKSUM_ADDRESS}`));
    expectInvalidDid(() => createDidPkh({ chainId: '01', address: CHECKSUM_ADDRESS }));
  });

  it('chainId が非数値（eip155:abc）は INVALID_DID', () => {
    expectInvalidDid(() => resolveDidPkh(`did:pkh:eip155:abc:${CHECKSUM_ADDRESS}`));
    expectInvalidDid(() => createDidPkh({ chainId: 'abc', address: CHECKSUM_ADDRESS }));
  });

  it('非 eip155 名前空間（cosmos:…）は INVALID_DID', () => {
    expectInvalidDid(() =>
      resolveDidPkh('did:pkh:cosmos:cosmoshub-3:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0'),
    );
    expectInvalidDid(() => resolveDidPkh(`did:pkh:cosmos:1:${CHECKSUM_ADDRESS}`));
  });
});
