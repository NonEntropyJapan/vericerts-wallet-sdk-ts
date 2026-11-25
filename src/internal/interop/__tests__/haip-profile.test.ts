/**
 * HAIP プロファイル準拠テスト（VC 署名・検証）。
 *
 * HAIP（OpenID4VC High Assurance Interoperability Profile）の SD-JWT VC 必須要件を、実鍵・実署名で
 * 検証する（モック・ネット非依存）:
 * - Issuer-signed JWT の署名アルゴリズムが ES256（P-256）である。
 * - `vct`（Verifiable Credential Type）が必須で付与・検証される。
 * - Holder Binding（`cnf.jwk`）が必須で付与され、検証結果に保持される。
 * - `typ` ヘッダが `dc+sd-jwt`（HAIP 1.0。旧 `vc+sd-jwt` の受理は SD-JWT コア側でカバー）。
 * - 選択的開示クレーム（`_sd`）を含み、発行時点で全 Disclosure を復元できる。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { createSdJwt, parseSdJwt } from '../../credential/sdjwt/sdjwt.js';
import { verifySdJwt } from '../../credential/sdjwt/verify.js';
import { credentialInput, ISSUER_JWK, issuerSigner, VCT } from '../fixtures.js';

/** Issuer-signed JWT のヘッダを JSON として取り出す。 */
function decodeHeader(sdJwt: string): Record<string, unknown> {
  const issuerJwt = sdJwt.split('~')[0] as string;
  const headerSeg = issuerJwt.split('.')[0] as string;
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(headerSeg)));
}

/** Issuer-signed JWT の payload を JSON として取り出す。 */
function decodePayload(sdJwt: string): Record<string, unknown> {
  const issuerJwt = sdJwt.split('~')[0] as string;
  const payloadSeg = issuerJwt.split('.')[1] as string;
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(payloadSeg)));
}

describe('HAIP プロファイル準拠 — SD-JWT VC 発行', () => {
  it('Issuer-signed JWT の alg は ES256（HAIP 必須）', () => {
    const sdJwt = createSdJwt(issuerSigner(), credentialInput());
    expect(decodeHeader(sdJwt).alg).toBe('ES256');
  });

  it('typ ヘッダは dc+sd-jwt', () => {
    const sdJwt = createSdJwt(issuerSigner(), credentialInput());
    expect(decodeHeader(sdJwt).typ).toBe('dc+sd-jwt');
  });

  it('vct が payload に必須で含まれる', () => {
    const sdJwt = createSdJwt(issuerSigner(), credentialInput());
    expect(decodePayload(sdJwt).vct).toBe(VCT);
  });

  it('Holder Binding（cnf.jwk）が payload に含まれる', () => {
    const sdJwt = createSdJwt(issuerSigner(), credentialInput());
    const cnf = decodePayload(sdJwt).cnf as { jwk?: { crv?: string } } | undefined;
    expect(cnf?.jwk?.crv).toBe('P-256');
  });

  it('選択的開示クレームが _sd に digest として格納される', () => {
    const sdJwt = createSdJwt(issuerSigner(), credentialInput());
    const sd = decodePayload(sdJwt)._sd as unknown[];
    // 4 つの開示クレーム（nickname / age_over_18 / resident_address / resident_country）。
    expect(Array.isArray(sd)).toBe(true);
    expect(sd.length).toBe(4);
    expect(parseSdJwt(sdJwt).disclosures.length).toBe(4);
  });

  it('_sd_alg は sha-256', () => {
    const sdJwt = createSdJwt(issuerSigner(), credentialInput());
    expect(decodePayload(sdJwt)._sd_alg).toBe('sha-256');
  });
});

describe('HAIP プロファイル準拠 — SD-JWT VC 検証', () => {
  it('Issuer 鍵で検証成功し vct / cnf を保持する', () => {
    const sdJwt = createSdJwt(issuerSigner(), credentialInput());
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, expectedVct: VCT });
    expect(result.vct).toBe(VCT);
    expect(result.cnf?.jwk.crv).toBe('P-256');
  });

  it('全 Disclosure 同梱時に全開示クレームを復元する', () => {
    const sdJwt = createSdJwt(issuerSigner(), credentialInput());
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK });
    expect(result.claims.nickname).toBe('ali');
    expect(result.claims.age_over_18).toBe(true);
    expect(result.claims.resident_address).toBe('Rue de la Loi 200, 1049 Brussels');
    expect(result.claims.resident_country).toBe('BE');
    // 平文クレーム（非開示）も残る。
    expect(result.claims.sub).toBe('did:example:haip-holder');
  });
});
