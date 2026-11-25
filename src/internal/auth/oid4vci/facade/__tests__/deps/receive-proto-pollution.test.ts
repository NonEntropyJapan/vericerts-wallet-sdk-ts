/**
 * ファサード `receiveCredential` も、`ReceiveCredentialDeps` の全 15 キーについて
 * `Object.prototype` 由来の値（データ汚染・アクセサ汚染）を `8010` / `invalid_receive_deps` で拒否する。
 *
 * 以前は未指定扱いで黙って無視していた（`Wallet.receiveCredential` だけが拒否）。`Wallet` と同じ規則に
 * 揃えるため、汚染を黙って捨てず、通信より前に拒否する。呼び出し側が own で同じキーを渡している場合と、
 * クラスのプロトタイプが同じキーを持つ場合は、`Object.prototype` より手前なので拒否しない。
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../../../errors.js';
import { receiveCredential } from '../../receive.js';
import type { ReceiveCredentialDeps } from '../../types.js';
import {
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  facadeDeps,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  preAuthorizedOfferURI,
  type StubFetch,
  TOKEN_URL,
  tokenResponse,
} from '../facade-fixtures.js';

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

describe('receiveCredential（ファサード）: Object.prototype 汚染の拒否', () => {
  const realFetch = globalThis.fetch;
  let stub: StubFetch;

  beforeEach(() => {
    stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    // `fetchImpl` を渡さない呼び出しはグローバル fetch へ向かう。ここで通信を観測する。
    globalThis.fetch = stub.fetchImpl as unknown as typeof fetch;
  });
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  /** 試験対象のキーだけを own に持たない依存（他のキーは正当な own 値）。 */
  function depsWithout(key: keyof ReceiveCredentialDeps): ReceiveCredentialDeps {
    const deps: Record<string, unknown> = { ...facadeDeps(stub) };
    delete deps[key];
    return deps as unknown as ReceiveCredentialDeps;
  }

  const keys = Object.keys(pollutedValues([])) as (keyof ReceiveCredentialDeps)[];

  test('拒否対象のキーは ReceiveCredentialDeps の全 15 キー', () => {
    expect(keys).toHaveLength(15);
  });

  for (const key of keys) {
    for (const mode of ['data', 'accessor'] as const) {
      test(`${key} の${mode === 'data' ? 'データ' : 'アクセサ'}汚染は 8010 invalid_receive_deps で拒否し、通信しない`, async () => {
        const invoked: string[] = [];
        const value = pollutedValues(invoked)[key];
        Object.defineProperty(
          Object.prototype,
          key,
          mode === 'data'
            ? { value, configurable: true, writable: true }
            : { get: () => value, configurable: true },
        );
        try {
          await expect(
            receiveCredential(preAuthorizedOfferURI(), depsWithout(key)),
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

  test('呼び出し側が同じキーを own で渡すなら、汚染があっても own 値が使われ拒否しない', async () => {
    proto.txCode = 'polluted-pin';
    try {
      await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub, { txCode: '1234' }));
    } finally {
      delete proto.txCode;
    }
    expect(stub.formTo(TOKEN_URL)?.get('tx_code')).toBe('1234');
  });

  test('クラスのプロトタイプが同じキーを持つなら、汚染があっても拒否しない（Object.prototype より手前が優先）', async () => {
    const verified: string[] = [];
    class Deps {
      verifyReceived(raw: string): void {
        verified.push(raw);
      }
    }
    const deps = Object.assign(new Deps(), facadeDeps(stub));
    proto.verifyReceived = () => {
      throw new Error('polluted verifyReceived must not run');
    };
    try {
      await receiveCredential(preAuthorizedOfferURI(), deps);
    } finally {
      delete proto.verifyReceived;
    }
    expect(verified).toHaveLength(1);
  });
});
