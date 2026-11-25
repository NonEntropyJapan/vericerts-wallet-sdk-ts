import { describe, expect, it } from 'bun:test';
import {
  buildReceivedIssuerTrust,
  createPrivateKeySigner,
  createSdJwt,
  parseReceivedCredential,
  verifyReceivedSdJwtCredential,
} from '../../../exports/credential.js';
import { createDidJwk, createDidResolver } from '../../../exports/identity.js';

const VCT = 'https://issuer.example.org/identity';
const HTTPS_ISSUER = 'https://issuer.example.org';
const signer = createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256');
const did = createDidJwk(signer.publicKeyJwk).id;
const resolver = createDidResolver({});
const trust = buildReceivedIssuerTrust({}, resolver, undefined);

function credential(issuer = did, claims: Record<string, unknown> = {}): string {
  return createSdJwt(signer, {
    issuer,
    vct: VCT,
    disclosureClaims: ['name'],
    claims: { name: 'Alice', exp: Math.floor(Date.now() / 1000) + 600, ...claims },
  });
}

describe('公開 Credential 受領データ API', () => {
  it('構造解析と検証済み結果を別の判別子で返す', async () => {
    const raw = credential();
    const parsed = parseReceivedCredential(raw);
    expect(parsed).toMatchObject({
      verification: 'unverified',
      format: 'sd-jwt',
      issuer: did,
      type: [VCT],
    });
    expect(parsed.claims).toEqual({ name: 'Alice' });
    const verified = await verifyReceivedSdJwtCredential(raw, {
      issuerTrust: trust,
      expectedVct: VCT,
    });
    expect(verified).toMatchObject({ verification: 'verified', raw, issuer: did, type: [VCT] });
  });

  it('期限切れの原本は未検証解析で保持できるが新規受領の検証は拒否する', async () => {
    const raw = credential(did, { exp: Math.floor(Date.now() / 1000) - 3600 });
    expect(parseReceivedCredential(raw).verification).toBe('unverified');
    await expect(verifyReceivedSdJwtCredential(raw, { issuerTrust: trust })).rejects.toMatchObject({
      code: '3024',
    });
  });

  it('要求したvctと異なる署名付きVCを拒否する', async () => {
    await expect(
      verifyReceivedSdJwtCredential(credential(), {
        issuerTrust: trust,
        expectedVct: `${VCT}/other`,
      }),
    ).rejects.toMatchObject({ code: '3010' });
  });

  it('別鍵の署名・改変Disclosure・解決不能issuerを拒否する', async () => {
    const other = createDidJwk(
      createPrivateKeySigner(new Uint8Array(32).fill(8), 'ES256').publicKeyJwk,
    ).id;
    await expect(
      verifyReceivedSdJwtCredential(credential(other), { issuerTrust: trust }),
    ).rejects.toMatchObject({ code: '3010' });
    const parts = credential().split('~');
    parts[1] = `${parts[1]?.slice(0, -1)}A`;
    await expect(
      verifyReceivedSdJwtCredential(parts.join('~'), { issuerTrust: trust }),
    ).rejects.toBeDefined();
    await expect(
      verifyReceivedSdJwtCredential(credential('did:unknown:issuer'), { issuerTrust: trust }),
    ).rejects.toMatchObject({ code: '3010' });
  });

  it('HTTPS metadata鍵は明示opt-inした場合だけ取得し検証する', async () => {
    const urls: string[] = [];
    const fetchImpl = async (url: string) => {
      urls.push(url);
      return new Response(
        JSON.stringify({ issuer: HTTPS_ISSUER, jwks: { keys: [signer.publicKeyJwk] } }),
        {
          headers: { 'content-type': 'application/json' },
        },
      );
    };
    const raw = credential(HTTPS_ISSUER);
    await expect(
      verifyReceivedSdJwtCredential(raw, {
        issuerTrust: buildReceivedIssuerTrust({}, resolver, fetchImpl),
      }),
    ).rejects.toMatchObject({ code: '3010' });
    expect(urls).toHaveLength(0);
    const result = await verifyReceivedSdJwtCredential(raw, {
      issuerTrust: buildReceivedIssuerTrust(
        { jwtVcIssuerMetadataResolution: true },
        resolver,
        fetchImpl,
      ),
      expectedVct: VCT,
    });
    expect(result.verification).toBe('verified');
    expect(urls).toEqual([`${HTTPS_ISSUER}/.well-known/jwt-vc-issuer`]);
  });

  it('継承されたmetadata opt-inを信頼しない', async () => {
    let calls = 0;
    const options = Object.create({ jwtVcIssuerMetadataResolution: true });
    const issuerTrust = buildReceivedIssuerTrust(options, resolver, async () => {
      calls += 1;
      throw new Error('must not fetch');
    });
    await expect(
      verifyReceivedSdJwtCredential(credential(HTTPS_ISSUER), { issuerTrust }),
    ).rejects.toMatchObject({ code: '3010' });
    expect(calls).toBe(0);
  });
});
