/**
 * `Wallet.receiveCredential` が `opts` から採用する値の境界。
 *
 * - 純データ DI（`txCode` / `clientAssertion` / `clientAssertionType` / `clientId` / `redirectUri` / `format` /
 *   `credentialRequestVersion` / `correlationContext`）は own 限定。クラスのプロトタイプ値は採用しない。
 * - `signer` / `holderDid` / `keyId` は `opts` で上書きできない（アクティブペルソナの値が常に使われる）。
 */

import { describe, expect, it } from 'bun:test';
import {
  authorizationCodeOfferURI,
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
import { setupWallet } from '../receive-credential-fixtures.js';

function preAuthorizedStub(): StubFetch {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
    [TOKEN_URL]: tokenResponse(),
    [CREDENTIAL_URL]: credentialResponse,
  });
}

/** 純データ 8 キーを全てプロトタイプ側（getter）だけで持つクラス。`fetchImpl` / `verifyReceived` は own。 */
class PrototypeDataOpts {
  readonly verifyReceived = (): void => {};
  constructor(readonly fetchImpl: StubFetch['fetchImpl']) {}
  get txCode(): string {
    return '1234';
  }
  get clientAssertion(): string {
    return 'proto-assertion';
  }
  get clientAssertionType(): string {
    return 'proto-assertion-type';
  }
  get clientId(): string {
    return 'proto-client';
  }
  get redirectUri(): string {
    return 'proto://cb';
  }
  get format(): string {
    return 'proto-format';
  }
  get credentialRequestVersion(): string {
    return '1.0';
  }
  get correlationContext(): object {
    return { traceparent: 'proto-traceparent' };
  }
}

/** Credential Request の JWT Proof から `iss` / `kid` を取り出す（draft 形 / 1.0 形の両対応）。 */
function proofIdentity(stub: StubFetch): { iss: unknown; kid: unknown } {
  const body = JSON.parse(stub.callTo(CREDENTIAL_URL)?.body ?? '{}') as {
    proof?: { jwt?: string };
    proofs?: { jwt?: string[] };
  };
  const jwt = body.proof?.jwt ?? body.proofs?.jwt?.[0] ?? '';
  const [header, payload] = jwt
    .split('.')
    .slice(0, 2)
    .map((part) => JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/'))));
  return { iss: payload?.iss, kid: header?.kid };
}

describe('Wallet.receiveCredential（純データ DI はプロトタイプ値を採用しない）', () => {
  it('クラスのプロトタイプ（getter）だけにある純データ 8 キーは facade へ渡らない', async () => {
    const stub = preAuthorizedStub();
    const wallet = await setupWallet();

    await wallet.receiveCredential(
      preAuthorizedOfferURI(),
      new PrototypeDataOpts(stub.fetchImpl) as never,
    );

    const token = stub.formTo(TOKEN_URL);
    expect(token?.has('tx_code')).toBe(false);
    expect(token?.has('client_assertion')).toBe(false);
    expect(token?.has('client_assertion_type')).toBe(false);
    const credentialCall = stub.callTo(CREDENTIAL_URL);
    // `format: 'proto-format'` / `credentialRequestVersion: '1.0'` が採用されると Credential Request の形が変わる。
    expect(credentialCall?.body).not.toContain('proto-format');
    expect(credentialCall?.body).not.toContain('credential_configuration_id');
    // `correlationContext` が採用されると相関ヘッダが出る。
    expect(credentialCall?.headers.traceparent).toBeUndefined();
  });

  // `clientId` / `redirectUri` は authorization_code 経路でしか読まれない。pre-authorized の Offer では
  // 採用されても観測できないので、この経路で「プロトタイプ値は採用されず未指定として 8010」を固定する。
  it('authorization_code でも、プロトタイプ（getter）だけにある clientId / redirectUri は採用されず 8010', async () => {
    const stub = preAuthorizedStub();
    const wallet = await setupWallet();
    let authorized = false;
    class PrototypeRegistrationOpts {
      readonly verifyReceived = (): void => {};
      readonly authorize = (): Promise<{ code: string; state: string }> => {
        authorized = true;
        return Promise.resolve({ code: 'c', state: 's' });
      };
      constructor(readonly fetchImpl: StubFetch['fetchImpl']) {}
      get clientId(): string {
        return 'proto-client';
      }
      get redirectUri(): string {
        return 'proto://cb';
      }
    }

    await expect(
      wallet.receiveCredential(
        authorizationCodeOfferURI(),
        new PrototypeRegistrationOpts(stub.fetchImpl) as never,
      ),
    ).rejects.toMatchObject({ context: { reason: 'missing_client_registration' } });
    expect(authorized).toBe(false);
  });

  it('own で指定した純データは採用される（対照）', async () => {
    const stub = preAuthorizedStub();
    const wallet = await setupWallet();

    await wallet.receiveCredential(preAuthorizedOfferURI(), {
      fetchImpl: stub.fetchImpl,
      verifyReceived: () => {},
      txCode: '1234',
    });

    expect(stub.formTo(TOKEN_URL)?.get('tx_code')).toBe('1234');
  });
});

describe('Wallet.receiveCredential（signer / holderDid / keyId は opts で上書きできない）', () => {
  const evil = (): Record<string, unknown> => ({
    signer: {
      sign: () => {
        throw new Error('opts.signer must not be used');
      },
    },
    holderDid: 'did:example:evil-holder',
    keyId: 'did:example:evil-holder#evil-key',
  });

  async function baselineIdentity(): Promise<{ iss: unknown; kid: unknown }> {
    const stub = preAuthorizedStub();
    const wallet = await setupWallet();
    await wallet.receiveCredential(preAuthorizedOfferURI(), {
      fetchImpl: stub.fetchImpl,
      verifyReceived: () => {},
    });
    return proofIdentity(stub);
  }

  it('opts の own に signer / holderDid / keyId があっても、アクティブペルソナの iss / kid で署名する', async () => {
    const stub = preAuthorizedStub();
    const wallet = await setupWallet();
    // 同じニーモニック・同じペルソナ導出なので、ベースラインと同じ `iss` / `kid` になる。
    const baseline = await baselineIdentity();

    await wallet.receiveCredential(preAuthorizedOfferURI(), {
      ...evil(),
      fetchImpl: stub.fetchImpl,
      verifyReceived: () => {},
    } as never);

    const identity = proofIdentity(stub);
    expect(identity).toEqual(baseline);
    expect(String(identity.iss)).not.toContain('evil');
    expect(String(identity.kid)).not.toContain('evil');
  });

  it('opts のプロトタイプ（Object.create）側に持たせても同じ', async () => {
    const stub = preAuthorizedStub();
    const wallet = await setupWallet();
    const baseline = await baselineIdentity();
    const opts = Object.assign(Object.create(evil()) as object, {
      fetchImpl: stub.fetchImpl,
      verifyReceived: () => {},
    });

    await wallet.receiveCredential(preAuthorizedOfferURI(), opts as never);

    expect(proofIdentity(stub)).toEqual(baseline);
  });
});
