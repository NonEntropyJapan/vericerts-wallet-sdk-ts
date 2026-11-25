/**
 * MethodEthr / createEthersEventSource のエラー検証。
 *
 * 未設定チェーン → DID_NOT_FOUND(2003)、fetchEvents throw → 2003、
 * DID 形式不正 → INVALID_DID(2001)、create / update / deactivate → METHOD_NOT_SUPPORTED(2002)
 * を確認する。
 */

import { describe, expect, it } from 'bun:test';
import type { ErrorCode } from '../../../errors.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { MethodEthr } from '../method-ethr.js';
import { createEthersEventSource, type Erc1056EventSource } from '../registry.js';

const IDENTITY = '0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb';

const expectCode = async (fn: () => Promise<unknown>, code: ErrorCode): Promise<void> => {
  try {
    await fn();
    throw new Error('expected to throw');
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(code);
  }
};

describe('MethodEthr エラー', () => {
  it('未設定チェーン（rpcUrls に無い）は DID_NOT_FOUND', async () => {
    // 既定 ethers eventSource を使う（rpcUrls 空 → chainId 1 が無い）。
    const method = new MethodEthr({ rpcUrls: {} });
    await expectCode(() => method.resolve(`did:ethr:${IDENTITY}`), ErrorCodes.DID_NOT_FOUND);
  });

  it('fetchEvents が throw した場合は DID_NOT_FOUND を伝播する', async () => {
    const failingSource: Erc1056EventSource = {
      async fetchEvents() {
        throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
      },
    };
    const method = new MethodEthr({ rpcUrls: {}, eventSource: failingSource });
    await expectCode(() => method.resolve(`did:ethr:${IDENTITY}`), ErrorCodes.DID_NOT_FOUND);
  });

  it('DID 形式不正は INVALID_DID', async () => {
    const method = new MethodEthr({ rpcUrls: {} });
    await expectCode(() => method.resolve('did:ethr:0xabc'), ErrorCodes.INVALID_DID);
  });

  it('create は METHOD_NOT_SUPPORTED', async () => {
    const method = new MethodEthr({ rpcUrls: {} });
    await expectCode(
      () => method.create({ keyType: 'secp256k1', publicKey: new Uint8Array(33) }),
      ErrorCodes.METHOD_NOT_SUPPORTED,
    );
  });

  it('update は METHOD_NOT_SUPPORTED', async () => {
    const method = new MethodEthr({ rpcUrls: {} });
    await expectCode(
      () => method.update(`did:ethr:${IDENTITY}`, {}),
      ErrorCodes.METHOD_NOT_SUPPORTED,
    );
  });

  it('deactivate は METHOD_NOT_SUPPORTED', async () => {
    const method = new MethodEthr({ rpcUrls: {} });
    await expectCode(
      () => method.deactivate(`did:ethr:${IDENTITY}`),
      ErrorCodes.METHOD_NOT_SUPPORTED,
    );
  });
});

describe('createEthersEventSource', () => {
  it('未設定チェーンは DID_NOT_FOUND（network に触れない）', async () => {
    const source = createEthersEventSource({});
    await expectCode(() => source.fetchEvents(1, IDENTITY), ErrorCodes.DID_NOT_FOUND);
  });
});
