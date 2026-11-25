/**
 * eudi/issuance の `Object.prototype` 汚染耐性テスト。
 *
 * 検証するのは「その任意プロパティを**省略した**正当な呼び出し」が継承値を拾わないこと。
 * - `Object.prototype.fetchImpl`: 汚染下でも攻撃者の fetch へ委譲しない（Bearer access_token と
 *   受領 VC が攻撃者へ渡らない）。Metadata / Token / Credential の 3 経路すべてで確認する。
 * - `Object.prototype.buildClientAttestation`: 汚染下でも `client_assertion` を送らない。
 * - `Object.prototype.grants`: 汚染下でも pre-authorized_code grant を「有る」ことにしない。
 * - `Object.prototype.nonceEndpoint`: `nonce_endpoint` を**告知しない** Issuer Metadata に対して、
 *   汚染値を「告知された Nonce Endpoint」として採用しない（採用すると AS が発行していない nonce を
 *   載せた WUA-PoP が本物の Token Endpoint へ送出され、リプレイ防止が崩れる）。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../../__tests__/prototype-pollution.fixtures.js';
import { VericertsError } from '../../../../../errors.js';
import { PID_VCT } from '../../../../../eudi/pid/index.js';
import { WUA_CLIENT_ASSERTION_TYPE } from '../../../../../eudi/wua/types.js';
import { receivePIDCredential } from '../../receive.js';
import {
  AS_METADATA_URL,
  buildOfferURI,
  buildSdJwtVc,
  createIssuerStub,
  defaultOfferURI,
  HOLDER_DID,
  HOLDER_KEY_ID,
  holderSigner,
  ISSUER,
  METADATA_URL,
  TOKEN_URL,
  VALID_PID_CLAIMS,
} from '../issuance-fixtures.js';

/** 呼ばれたら記録するだけの「攻撃者の fetch」。 */
function attackerFetch(): { called: boolean; impl: () => Promise<Response> } {
  const state = { called: false, impl: () => Promise.resolve(new Response('', { status: 200 })) };
  state.impl = () => {
    state.called = true;
    return Promise.resolve(new Response('{}', { status: 200 }));
  };
  return state;
}

describe('receivePIDCredential / Object.prototype 汚染', () => {
  test('汚染された fetchImpl は採用しない（注入した実装がそのまま使われる）', async () => {
    const attacker = attackerFetch();
    const stub = createIssuerStub(buildSdJwtVc({ claims: VALID_PID_CLAIMS }));
    const pid = await withPollutedPrototypeAsync({ fetchImpl: attacker.impl }, async () =>
      receivePIDCredential(defaultOfferURI(), {
        signer: holderSigner(),
        holderDid: HOLDER_DID,
        keyId: HOLDER_KEY_ID,
        fetchImpl: stub.fetchImpl,
      }),
    );
    expect(attacker.called).toBe(false);
    expect(pid.vct).toBe(PID_VCT);
    // Issuer Metadata・AS Metadata・Token・Credential の 4 本（すべて注入した実装へ流れる）。
    expect(stub.calls).toHaveLength(4);
  });

  test('fetchImpl 未指定でも汚染された実装へは委譲しない', async () => {
    const attacker = attackerFetch();
    const originalFetch = globalThis.fetch;
    let globalCalled = false;
    globalThis.fetch = (() => {
      globalCalled = true;
      // Metadata 取得で 404 にし、3004 で早期に落とす（外部通信は発生しない）。
      return Promise.resolve(new Response('', { status: 404 }));
    }) as unknown as typeof fetch;
    try {
      await withPollutedPrototypeAsync({ fetchImpl: attacker.impl }, async () => {
        try {
          await receivePIDCredential(defaultOfferURI(), {
            signer: holderSigner(),
            holderDid: HOLDER_DID,
            keyId: HOLDER_KEY_ID,
          });
          throw new Error('should throw');
        } catch (e) {
          expect(e).toBeInstanceOf(VericertsError);
          expect((e as VericertsError).code).toBe('3004');
        }
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
    expect(attacker.called).toBe(false);
    expect(globalCalled).toBe(true);
  });

  test('汚染された buildClientAttestation は Token Request に載らない', async () => {
    const stub = createIssuerStub(buildSdJwtVc({ claims: VALID_PID_CLAIMS }));
    const attackerAttestation = () => ({
      clientAssertion: 'attacker~assertion',
      clientAssertionType: 'urn:attacker',
    });
    await withPollutedPrototypeAsync({ buildClientAttestation: attackerAttestation }, async () =>
      receivePIDCredential(defaultOfferURI(), {
        signer: holderSigner(),
        holderDid: HOLDER_DID,
        keyId: HOLDER_KEY_ID,
        fetchImpl: stub.fetchImpl,
      }),
    );
    const tokenCall = stub.calls.find((call) => call.url === TOKEN_URL);
    const params = new URLSearchParams(tokenCall?.body ?? '');
    expect(params.has('client_assertion')).toBe(false);
    expect(params.has('client_assertion_type')).toBe(false);
  });

  test('汚染された grants は pre-authorized_code grant の代わりにならない（3003）', async () => {
    const stub = createIssuerStub(buildSdJwtVc({ claims: VALID_PID_CLAIMS }));
    const attackerGrants = {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': 'attacker-code',
      },
    };
    const offerURI = buildOfferURI({
      credential_issuer: ISSUER,
      credential_configuration_ids: [PID_VCT],
    });
    await withPollutedPrototypeAsync({ grants: attackerGrants }, async () => {
      try {
        await receivePIDCredential(offerURI, {
          signer: holderSigner(),
          holderDid: HOLDER_DID,
          keyId: HOLDER_KEY_ID,
          fetchImpl: stub.fetchImpl,
        });
        throw new Error('should throw');
      } catch (e) {
        expect(e).toBeInstanceOf(VericertsError);
        expect((e as VericertsError).code).toBe('3003');
      }
    });
    expect(stub.calls).toHaveLength(0);
  });
});

describe('receivePIDCredential / nonce_endpoint 未告知時の汚染耐性', () => {
  test('汚染された nonceEndpoint は採用せず 8010 nonce_endpoint_unavailable で止まる', async () => {
    // 既定の Issuer Metadata は `nonce_endpoint` を告知しない。
    const stub = createIssuerStub(buildSdJwtVc({ claims: VALID_PID_CLAIMS }));
    const attackerNonceUrl = 'https://attacker.example/nonce';
    let receivedNonce: string | undefined;
    await withPollutedPrototypeAsync({ nonceEndpoint: attackerNonceUrl }, async () => {
      try {
        await receivePIDCredential(defaultOfferURI(), {
          signer: holderSigner(),
          holderDid: HOLDER_DID,
          keyId: HOLDER_KEY_ID,
          fetchImpl: stub.fetchImpl,
          buildClientAttestation: (_aud: string, nonce: string) => {
            receivedNonce = nonce;
            return { clientAssertion: 'wua~pop', clientAssertionType: WUA_CLIENT_ASSERTION_TYPE };
          },
        });
        throw new Error('should throw');
      } catch (e) {
        expect(e).toBeInstanceOf(VericertsError);
        expect((e as VericertsError).code).toBe('8010');
        expect((e as VericertsError).context).toEqual({ reason: 'nonce_endpoint_unavailable' });
      }
    });
    // 攻撃者の URL へ nonce を取りに行っていない（Issuer Metadata と AS Metadata で止まる）。
    expect(stub.calls.map((call) => call.url)).toEqual([METADATA_URL, AS_METADATA_URL]);
    expect(stub.calls.some((call) => call.url === attackerNonceUrl)).toBe(false);
    // PoP の組み立て自体に到達しない（攻撃者 nonce が署名対象にならない）。
    expect(receivedNonce).toBeUndefined();
  });
});
