/**
 * SD-JWT VC の Credential Request は `vct` で型を伝える（旧 Draft 形。draft-13 Annex A.3）。
 * OID4VCI 1.0 Final の Credential Request は `credential_configuration_id` で伝え、`vct` を持たない。
 *
 * 回帰観点:
 * - `format` が SD-JWT VC（`dc+sd-jwt` / 移行期間の `vc+sd-jwt`）の旧 Draft 形は、`vct` を送り
 *   `credential_definition` を**送らない**。SD-JWT VC は型を `vct` の 1 値で持ち、
 *   `credential_definition` は JWT-VC 系の形だからである。
 * - JWT-VC（`jwt_vc_json`）は従来どおり `credential_definition` を送り、`vct` を混ぜない。
 * - `vct` 未指定の SD-JWT VC は従来どおり `credential_definition` を送る（呼び出し側が移行するまで壊さない）。
 * - 1.0 Final 形（`credentialConfigurationId` 指定）は `vct` を指定しても従来どおり
 *   `{ credential_configuration_id, proofs }` だけを送る（形を混在させない）。
 *
 * 実害: walt.id issuer-api は `findMatchingIssuanceRequest` で Credential Request の `vct` を
 * credential configuration の `vct` と突き合わせるため、`vct` を送らないと発行セッションに紐づかず
 * HTTP 400 `No matching issuance request found for this session` を返し、受領が 8020 で落ちていた。
 */

import { afterEach, describe, expect, test } from 'bun:test';
import type { FetchLike } from '../../../../fetch-di.js';
import { type RequestCredentialOptions, requestCredential } from '../../oid4vci.js';

const CREDENTIAL_URL = 'https://issuer.example.com/credential';
const PROOF_JWT = 'header.payload.sig';
const VCT = 'https://issuer.example.com/identity_credential';

function stub(): { fetchImpl: FetchLike; bodies: Record<string, unknown>[] } {
  const bodies: Record<string, unknown>[] = [];
  const fetchImpl: FetchLike = async (_url, init) => {
    bodies.push(JSON.parse(String(init.body)) as Record<string, unknown>);
    return new Response(JSON.stringify({ credential: 'issued.sd.jwt' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  return { fetchImpl, bodies };
}

function options(overrides: Partial<RequestCredentialOptions>): RequestCredentialOptions {
  return {
    credentialEndpoint: CREDENTIAL_URL,
    accessToken: 'access-token-value',
    format: 'dc+sd-jwt',
    credentialDefinition: { type: [VCT] },
    proofJwt: PROOF_JWT,
    ...overrides,
  };
}

afterEach(() => {
  delete (Object.prototype as unknown as Record<string, unknown>).vct;
});

describe('requestCredential: SD-JWT VC は vct で型を伝える', () => {
  test.each([
    'dc+sd-jwt',
    'vc+sd-jwt',
  ])('%s は vct を送り credential_definition を送らない', async (format) => {
    const { fetchImpl, bodies } = stub();
    await requestCredential(options({ format, vct: VCT, fetchImpl }));
    expect(bodies[0]?.vct).toBe(VCT);
    expect(bodies[0]).not.toHaveProperty('credential_definition');
    expect(bodies[0]?.format).toBe(format);
    expect(bodies[0]?.proof).toEqual({ proof_type: 'jwt', jwt: PROOF_JWT });
  });

  test('jwt_vc_json は従来どおり credential_definition を送り、vct を混ぜない', async () => {
    const { fetchImpl, bodies } = stub();
    await requestCredential(
      options({
        format: 'jwt_vc_json',
        credentialDefinition: { type: ['UniversityDegree'] },
        vct: VCT,
        fetchImpl,
      }),
    );
    expect(bodies[0]?.credential_definition).toEqual({ type: ['UniversityDegree'] });
    expect(bodies[0]).not.toHaveProperty('vct');
  });

  test('vct 未指定の SD-JWT VC は従来どおり credential_definition を送る', async () => {
    const { fetchImpl, bodies } = stub();
    await requestCredential(options({ fetchImpl }));
    expect(bodies[0]?.credential_definition).toEqual({ type: [VCT] });
    expect(bodies[0]).not.toHaveProperty('vct');
  });

  test('Object.prototype の汚染値を vct として拾わない（own 限定読み）', async () => {
    (Object.prototype as unknown as Record<string, unknown>).vct = 'https://attacker.example/vct';
    const { fetchImpl, bodies } = stub();
    // `vct` を渡していない SD-JWT VC の呼び出し。鎖読みだと汚染値で要求してしまう。
    await requestCredential(options({ fetchImpl }));
    // `toHaveProperty` はプロトタイプ鎖を辿るため、ここでは own 判定で見る（汚染中のため）。
    expect(Object.hasOwn(bodies[0] ?? {}, 'vct')).toBe(false);
    expect(bodies[0]?.credential_definition).toEqual({ type: [VCT] });
  });

  test('1.0 Final 形は vct を指定しても credential_configuration_id / proofs だけを送る', async () => {
    const { fetchImpl, bodies } = stub();
    await requestCredential(
      options({ vct: VCT, credentialConfigurationId: 'identity_credential', fetchImpl }),
    );
    expect(bodies[0]).toEqual({
      credential_configuration_id: 'identity_credential',
      proofs: { jwt: [PROOF_JWT] },
    });
  });
});
