/**
 * `receiveEAACredential` と Wallet Attestation 添付のテスト。
 *
 * (Q)EAA は Catalogue 解決を**受領後**に行う（要求時の configuration id ではなく、受領した VC の
 * `vct` で判定する）。その順序と、未登録 vct の fail-closed を検証する。
 */

import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../../../errors.js';
import type { AttestationCatalogueEntry } from '../../../../eudi/pid/index.js';
import { createRecordCatalogueSource } from '../../../../eudi/pid/index.js';
import { WUA_CLIENT_ASSERTION_TYPE } from '../../../../eudi/wua/types.js';
import { receiveEAACredential } from '../receive.js';
import {
  AS_C_NONCE,
  buildSdJwtVc,
  CREDENTIAL_URL,
  createIssuerStub,
  createIssuerStubWithNonce,
  defaultOfferURI,
  EAA_VCT,
  ISSUER,
  NONCE_URL,
  receiveDeps,
  TOKEN_URL,
} from './issuance-fixtures.js';

/** `EAA_VCT` を登録済みの Catalogue。 */
const CATALOGUE_ENTRY: AttestationCatalogueEntry = {
  vct: EAA_VCT,
  rulebookUrl: 'https://catalogue.example.eu/diploma/rulebook',
  schemaUrl: 'https://catalogue.example.eu/diploma/schema.json',
  version: '1.0',
};

/** 登録済み Catalogue の参照源。 */
function registeredSource() {
  return createRecordCatalogueSource({ [EAA_VCT]: CATALOGUE_ENTRY });
}

/** (Q)EAA の SD-JWT VC。 */
function eaaSdJwt(vct: string = EAA_VCT): string {
  return buildSdJwtVc({ vct, claims: { degree: 'Laurea Magistrale', institution: 'UniRoma' } });
}

describe('receiveEAACredential', () => {
  test('正常系: vct / claims / raw を持つ (Q)EAA を返す', async () => {
    const sdJwt = eaaSdJwt();
    const stub = createIssuerStub(sdJwt);
    const eaa = await receiveEAACredential(
      defaultOfferURI(EAA_VCT),
      registeredSource(),
      receiveDeps(stub.fetchImpl),
    );
    expect(eaa.vct).toBe(EAA_VCT);
    expect(eaa.raw).toBe(sdJwt);
    expect(eaa.claims.degree).toBe('Laurea Magistrale');
    expect(eaa.claims.institution).toBe('UniRoma');
  });

  test('要求する vct は Offer の credential_configuration_ids[0]', async () => {
    const stub = createIssuerStub(eaaSdJwt());
    await receiveEAACredential(
      defaultOfferURI(EAA_VCT),
      registeredSource(),
      receiveDeps(stub.fetchImpl),
    );
    const credentialCall = stub.calls.find((call) => call.url === CREDENTIAL_URL);
    const body = JSON.parse(credentialCall?.body ?? '{}') as Record<string, unknown>;
    // SD-JWT VC は型を `vct` で伝える。
    expect(body.vct).toBe(EAA_VCT);
    expect(body).not.toHaveProperty('credential_definition');
  });

  describe('Catalogue の issuerAllowList', () => {
    const ALLOWED_ISSUER = 'did:web:only-this-issuer.example';

    /** `issuerAllowList` を持つ Catalogue。 */
    function allowListSource(issuerAllowList: readonly string[]) {
      return createRecordCatalogueSource({
        [EAA_VCT]: { ...CATALOGUE_ENTRY, issuerAllowList },
      });
    }

    async function receiveWith(iss: string | undefined, allowList: readonly string[]) {
      const stub = createIssuerStub(
        buildSdJwtVc({ vct: EAA_VCT, ...(iss === undefined ? {} : { iss }), claims: { a: 1 } }),
      );
      return receiveEAACredential(
        defaultOfferURI(EAA_VCT),
        allowListSource(allowList),
        receiveDeps(stub.fetchImpl),
      );
    }

    test('許可リスト外の Issuer の EAA は 8020 issuer_not_allowed で拒否する', async () => {
      try {
        await receiveWith(ISSUER, [ALLOWED_ISSUER]);
        throw new Error('should throw');
      } catch (error) {
        expect(error).toBeInstanceOf(VericertsError);
        expect((error as VericertsError).code).toBe('8020');
        expect((error as VericertsError).context).toEqual({ reason: 'issuer_not_allowed' });
      }
    });

    test('許可リスト内の Issuer の EAA は受理する', async () => {
      const eaa = await receiveWith(ISSUER, [ALLOWED_ISSUER, ISSUER]);
      expect(eaa.vct).toBe(EAA_VCT);
    });

    test('空配列は全拒否、前方一致・部分一致も許可しない（完全一致）', async () => {
      await expect(receiveWith(ISSUER, [])).rejects.toThrow();
      await expect(receiveWith(ISSUER, [`${ISSUER}/x`])).rejects.toThrow();
      await expect(receiveWith(`${ISSUER}/x`, [ISSUER])).rejects.toThrow();
    });

    test('許可リストが定義されていて配列でなければ拒否する（fail-closed）', async () => {
      const stub = createIssuerStub(buildSdJwtVc({ vct: EAA_VCT, claims: { a: 1 } }));
      const source = createRecordCatalogueSource({
        [EAA_VCT]: { ...CATALOGUE_ENTRY, issuerAllowList: ISSUER as unknown as readonly string[] },
      });
      await expect(
        receiveEAACredential(defaultOfferURI(EAA_VCT), source, receiveDeps(stub.fetchImpl)),
      ).rejects.toThrow();
    });

    test('許可リストが無いエントリは Issuer を制限しない', async () => {
      const eaa = await receiveEAACredential(
        defaultOfferURI(EAA_VCT),
        registeredSource(),
        receiveDeps(createIssuerStub(eaaSdJwt()).fetchImpl),
      );
      expect(eaa.vct).toBe(EAA_VCT);
    });
  });

  test('Catalogue 未登録は 10003', async () => {
    const stub = createIssuerStub(eaaSdJwt('urn:eudi:eaa:unknown:1'));
    try {
      await receiveEAACredential(
        defaultOfferURI('urn:eudi:eaa:unknown:1'),
        registeredSource(),
        receiveDeps(stub.fetchImpl),
      );
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10003');
    }
    // Catalogue 解決は受領後なので、通信（Metadata・AS Metadata・Token・Credential）は 4 回とも行われている。
    expect(stub.calls).toHaveLength(4);
  });

  test('vct を持たない VC は 8020', async () => {
    const stub = createIssuerStub(
      buildSdJwtVc({ vct: '', claims: { degree: 'Laurea Magistrale' } }),
    );
    try {
      await receiveEAACredential(
        defaultOfferURI(EAA_VCT),
        registeredSource(),
        receiveDeps(stub.fetchImpl),
      );
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('8020');
    }
  });
});

describe('receiveEAACredential / Wallet Attestation 添付', () => {
  test('buildClientAttestation 指定時のみ client_assertion を Token Request に載せる', async () => {
    const stub = createIssuerStubWithNonce(eaaSdJwt());
    await receiveEAACredential(defaultOfferURI(EAA_VCT), registeredSource(), {
      ...receiveDeps(stub.fetchImpl),
      buildClientAttestation: () => ({
        clientAssertion: 'wua~wua-pop',
        clientAssertionType: WUA_CLIENT_ASSERTION_TYPE,
      }),
    });
    const tokenCall = stub.calls.find((call) => call.url === TOKEN_URL);
    const params = new URLSearchParams(tokenCall?.body ?? '');
    expect(params.get('client_assertion')).toBe('wua~wua-pop');
    expect(params.get('client_assertion_type')).toBe(WUA_CLIENT_ASSERTION_TYPE);
  });

  test('buildClientAttestation は解決済み Token Endpoint と AS 発行 c_nonce を受け取る', async () => {
    const stub = createIssuerStubWithNonce(eaaSdJwt());
    const auds: string[] = [];
    const nonces: string[] = [];
    await receiveEAACredential(defaultOfferURI(EAA_VCT), registeredSource(), {
      ...receiveDeps(stub.fetchImpl),
      buildClientAttestation: (aud: string, nonce: string) => {
        auds.push(aud);
        nonces.push(nonce);
        return { clientAssertion: `wua~${aud}`, clientAssertionType: WUA_CLIENT_ASSERTION_TYPE };
      },
    });
    // Offer の credential_issuer ではなく Issuer Metadata が宣言した Token Endpoint に束縛する。
    expect(auds).toEqual([TOKEN_URL]);
    // WUA-PoP の nonce は AS が発行した c_nonce でなければならない。
    expect(nonces).toEqual([AS_C_NONCE]);
    // Nonce Endpoint は Token Request より前に呼ばれる。
    const order = stub.calls.map((call) => call.url);
    expect(order.indexOf(NONCE_URL)).toBeLessThan(order.indexOf(TOKEN_URL));
  });

  test('nonce_endpoint 未告知の Issuer への WUA 添付は 8010（非準拠 PoP を送らない）', async () => {
    // 既定の Metadata は nonce_endpoint を告知しない。
    const stub = createIssuerStub(eaaSdJwt());
    try {
      await receiveEAACredential(defaultOfferURI(EAA_VCT), registeredSource(), {
        ...receiveDeps(stub.fetchImpl),
        buildClientAttestation: () => ({
          clientAssertion: 'wua~wua-pop',
          clientAssertionType: WUA_CLIENT_ASSERTION_TYPE,
        }),
      });
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('8010');
      expect((e as VericertsError).context).toEqual({ reason: 'nonce_endpoint_unavailable' });
    }
    // Token Request は 1 度も送られない。
    expect(stub.calls.some((call) => call.url === TOKEN_URL)).toBe(false);
  });

  test('clientAssertion を own プロパティとして読めない組み立て結果は 8010（fail-closed）', async () => {
    // プロトタイプ上の getter で値を出す実装。own 限定読みでは undefined になる。
    class ProtoAttestation {
      get clientAssertion(): string {
        return 'wua~wua-pop';
      }
      get clientAssertionType(): typeof WUA_CLIENT_ASSERTION_TYPE {
        return WUA_CLIENT_ASSERTION_TYPE;
      }
    }
    const stub = createIssuerStubWithNonce(eaaSdJwt());
    try {
      await receiveEAACredential(defaultOfferURI(EAA_VCT), registeredSource(), {
        ...receiveDeps(stub.fetchImpl),
        buildClientAttestation: () => new ProtoAttestation(),
      });
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('8010');
    }
    // 添付できないまま「未認証で送る」ダウングレードを起こさない。
    expect(stub.calls.some((call) => call.url === TOKEN_URL)).toBe(false);
  });

  test('buildClientAttestation 未指定なら client_assertion を送らない', async () => {
    const stub = createIssuerStub(eaaSdJwt());
    await receiveEAACredential(
      defaultOfferURI(EAA_VCT),
      registeredSource(),
      receiveDeps(stub.fetchImpl),
    );
    const tokenCall = stub.calls.find((call) => call.url === TOKEN_URL);
    const params = new URLSearchParams(tokenCall?.body ?? '');
    expect(params.has('client_assertion')).toBe(false);
    expect(params.has('client_assertion_type')).toBe(false);
  });

  test('client_assertion_type を欠く組み立て結果は 8010', async () => {
    const stub = createIssuerStubWithNonce(eaaSdJwt());
    try {
      await receiveEAACredential(defaultOfferURI(EAA_VCT), registeredSource(), {
        ...receiveDeps(stub.fetchImpl),
        buildClientAttestation: () => ({ clientAssertion: 'wua~wua-pop' }) as never,
      });
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('8010');
    }
  });

  test('オブジェクト以外を返す組み立て結果は 8010（fail-closed）', async () => {
    const stub = createIssuerStubWithNonce(eaaSdJwt());
    try {
      await receiveEAACredential(defaultOfferURI(EAA_VCT), registeredSource(), {
        ...receiveDeps(stub.fetchImpl),
        buildClientAttestation: (() => 'wua~wua-pop') as never,
      });
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('8010');
    }
  });
});
