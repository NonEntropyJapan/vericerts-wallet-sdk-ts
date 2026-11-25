/**
 * `Wallet.receiveCredential` は `ReceiveCredentialDeps` の全 15 キーについて、
 * `Object.prototype` 由来の値（データ汚染・アクセサ汚染）を `8010` / `invalid_receive_deps` で拒否する。
 *
 * 内部ファサード（`facade/deps.ts`）も同じ汚染を拒否する（`facade/__tests__/deps/receive-proto-pollution.test.ts`）。
 * 汚染を黙って捨てると利用者が気づけないため、両者とも拒否する。`Wallet` の拒否は
 * `resolveActiveHolder` の前（副作用・通信の前）で行う。
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import type { ReceiveCredentialDeps } from '../../../../internal/auth/index.js';
import {
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  preAuthorizedOfferURI,
  type StubFetch,
  TOKEN_URL,
  tokenResponse,
} from '../../../../internal/auth/oid4vci/facade/__tests__/facade-fixtures.js';
import { RECEIVE_DEPS_KEYS } from '../../../../internal/auth/oid4vci/facade/deps.js';
import { ErrorCodes } from '../../../../internal/errors.js';
import { MemoryStorage } from '../../../../storage/storage.js';

import { createWallet } from '../../../factory.js';
import { setupWallet, TEST_MNEMONIC } from '../receive-credential-fixtures.js';

/** 汚染値を呼び出し記録つきで作る。`Record<keyof ReceiveCredentialDeps, …>` なのでキーの過不足は型エラーになる。 */
function pollutedValues(invoked: string[]): Record<keyof ReceiveCredentialDeps, unknown> {
  const fn = (name: string) => () => {
    invoked.push(name);
  };
  return {
    signer: { sign: fn('signer') },
    holderDid: 'did:example:polluted',
    keyId: 'did:example:polluted#key',
    authorize: fn('authorize'),
    txCode: '0000',
    clientAssertion: 'polluted-assertion',
    clientAssertionType: 'polluted-type',
    clientId: 'polluted-client',
    redirectUri: 'polluted://cb',
    format: 'polluted-format',
    credentialRequestVersion: '1.0',
    createDpopProof: fn('createDpopProof'),
    verifyReceived: fn('verifyReceived'),
    correlationContext: { traceparent: 'polluted' },
    fetchImpl: fn('fetchImpl'),
  };
}

const proto = Object.prototype as unknown as Record<string, unknown>;

describe('Wallet.receiveCredential（Object.prototype 汚染の拒否）', () => {
  const realFetch = globalThis.fetch;
  let stub: StubFetch;

  beforeEach(() => {
    stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    // `opts` に fetchImpl を渡さない呼び出しはグローバル fetch へ向かう。ここで通信を観測する。
    globalThis.fetch = stub.fetchImpl as unknown as typeof fetch;
  });
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it('拒否対象のキー一覧は ReceiveCredentialDeps の全 15 キーと一致する', () => {
    const expected: string[] = Object.keys(pollutedValues([])).sort();
    expect(expected).toHaveLength(15);
    const actual: string[] = [...RECEIVE_DEPS_KEYS].sort();
    expect(actual).toEqual(expected);
  });

  const keys = Object.keys(pollutedValues([])) as (keyof ReceiveCredentialDeps)[];
  const modes = ['data', 'accessor'] as const;
  const optsVariants: readonly [string, () => object | undefined][] = [
    ['opts なし', () => undefined],
    ['プレーンな opts', () => ({})],
  ];

  for (const key of keys) {
    for (const mode of modes) {
      for (const [label, makeOpts] of optsVariants) {
        it(`${key} の${mode === 'data' ? 'データ' : 'アクセサ'}汚染は ${label} でも 8010 invalid_receive_deps で拒否し、通信しない`, async () => {
          const invoked: string[] = [];
          const value = pollutedValues(invoked)[key];
          const wallet = await setupWallet();
          Object.defineProperty(
            Object.prototype,
            key,
            mode === 'data'
              ? { value, configurable: true, writable: true }
              : { get: () => value, configurable: true },
          );
          try {
            await expect(
              wallet.receiveCredential(preAuthorizedOfferURI(), makeOpts() as never),
            ).rejects.toMatchObject({
              code: ErrorCodes.TOKEN_REQUEST_FAILED,
              context: { reason: 'invalid_receive_deps' },
            });
          } finally {
            delete proto[key];
          }
          expect(stub.calls).toHaveLength(0);
          expect(invoked).toEqual([]);
        });
      }
    }
  }

  it('拒否は resolveActiveHolder より前（アクティブペルソナが無くても 8010 になる）', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    proto.clientId = 'polluted-client';
    try {
      await expect(wallet.receiveCredential(preAuthorizedOfferURI())).rejects.toMatchObject({
        code: ErrorCodes.TOKEN_REQUEST_FAILED,
        context: { reason: 'invalid_receive_deps' },
      });
    } finally {
      delete proto.clientId;
    }
    expect(stub.calls).toHaveLength(0);
  });

  it('opts 自身が同じキーを own で持つなら汚染があっても own 値が使われ、拒否しない', async () => {
    const wallet = await setupWallet();
    proto.txCode = 'polluted-pin';
    try {
      await wallet.receiveCredential(preAuthorizedOfferURI(), {
        txCode: '1234',
        verifyReceived: () => {},
      });
    } finally {
      delete proto.txCode;
    }
    expect(stub.formTo(TOKEN_URL)?.get('tx_code')).toBe('1234');
  });

  it('クラスのプロトタイプが同じキーを持つなら汚染があっても拒否しない（Object.prototype より手前が優先）', async () => {
    const wallet = await setupWallet();
    class Opts {
      verifyReceived(): void {}
    }
    proto.verifyReceived = () => {
      throw new Error('polluted verifyReceived must not run');
    };
    try {
      await wallet.receiveCredential(preAuthorizedOfferURI(), new Opts());
    } finally {
      delete proto.verifyReceived;
    }
    expect(stub.callTo(CREDENTIAL_URL)).toBeDefined();
  });
});
