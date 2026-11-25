/**
 * `verifyJarSignature` の回帰テスト ―― 発行者同一性
 * （`iss == client_id` / SubjectAltName == `client_id` == `response_uri` origin）。
 *
 * 署名が正しく Trust Anchor へ到達していても、**証明書が名乗るドメインと要求の相手が食い違う**
 * 提示要求は受理してはならない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { makeRpCertificate } from '../../../trust/rp-access/__tests__/fixtures.js';
import { verifyJarSignature } from '../jar-signature.js';
import { jarClaims, makeJarSigner, signJar, toX5cEntry } from './jar-fixtures.js';

const VERIFIER = makeJarSigner();
const TRUST = { trustAnchors: VERIFIER.anchors } as const;

async function expectReason(promise: Promise<unknown>, reason: string): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    const error = err as VericertsError;
    expect(error.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(error.context).toMatchObject({ reason });
  }
}

describe('verifyJarSignature: 発行者同一性', () => {
  it('iss != client_id を拒否する', async () => {
    const jar = signJar(VERIFIER, { claims: jarClaims({ iss: 'https://other.example' }) });
    await expectReason(verifyJarSignature(jar, TRUST), 'jar_iss_client_id_mismatch');
  });

  it('iss を持たない JAR を拒否する', async () => {
    const claims = jarClaims();
    delete claims.iss;
    await expectReason(
      verifyJarSignature(signJar(VERIFIER, { claims }), TRUST),
      'jar_iss_client_id_mismatch',
    );
  });

  it('deep link の client_id と Request Object の client_id が食い違えば拒否する', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        ...TRUST,
        expectedClientId: 'https://another-verifier.example',
      }),
      'jar_client_id_mismatch',
    );
  });

  it('URL でない client_id を拒否する（SubjectAltName と突き合わせる相手が無い）', async () => {
    const claims = jarClaims({
      iss: 'x509_san_dns:verifier.example.com',
      client_id: 'x509_san_dns:verifier.example.com',
    });
    await expectReason(
      verifyJarSignature(signJar(VERIFIER, { claims }), TRUST),
      'jar_client_id_not_url',
    );
  });

  it('不透明 origin の client_id は jar_client_id_not_url で拒否する（URL.origin === "null"）', async () => {
    // `did:web:…` は URL としてパースできるが opaque origin なので `URL.origin` は文字列 `'null'`
    // を返す。これを比較値に使うと想定した reason が出ず、3 者が別の不透明識別子でも
    // すべて `'null'` で一致扱いになり得る。
    const clientId = 'did:web:verifier.example.com';
    const claims = jarClaims({ iss: clientId, client_id: clientId });
    await expectReason(
      verifyJarSignature(signJar(VERIFIER, { claims }), TRUST),
      'jar_client_id_not_url',
    );
  });

  it('response_uri のオリジンが client_id と異なれば拒否する', async () => {
    const claims = jarClaims({ response_uri: 'https://attacker.example/callback' });
    await expectReason(
      verifyJarSignature(signJar(VERIFIER, { claims }), TRUST),
      'jar_response_uri_domain_mismatch',
    );
  });

  it('同一ホストでもポートが違う response_uri は拒否する（origin 比較）', async () => {
    const claims = jarClaims({ response_uri: 'https://verifier.example.com:8443/callback' });
    await expectReason(
      verifyJarSignature(signJar(VERIFIER, { claims }), TRUST),
      'jar_response_uri_domain_mismatch',
    );
  });

  it('証明書の SubjectAltName が client_id と一致しなければ拒否する', async () => {
    // Trust Anchor へは到達し署名も正しいが、証明書が名乗るドメインが要求と違う。
    const impostor = makeJarSigner({ origin: 'https://someone-else.example' });
    const jar = signJar(impostor);
    await expectReason(
      verifyJarSignature(jar, { trustAnchors: impostor.anchors }),
      'jar_san_client_id_mismatch',
    );
  });

  it('SubjectAltName を持たない証明書を拒否する', async () => {
    const noSan = makeRpCertificate({
      subject: { organizationName: 'No SAN Verifier', country: 'DE' },
      kind: 'ec',
      serial: 55,
      issuer: { name: VERIFIER.ca.subjectName, privateKey: VERIFIER.ca.privateKey, kind: 'ec' },
    });
    const jar = signJar({ ...VERIFIER, rp: noSan }, { header: { x5c: [toX5cEntry(noSan.der)] } });
    await expectReason(verifyJarSignature(jar, TRUST), 'jar_san_client_id_mismatch');
  });
});
