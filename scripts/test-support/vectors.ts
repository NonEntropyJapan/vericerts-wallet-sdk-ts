import { issuePresentation } from '../../src/internal/credential/presentation/issue.js';
import { issueCredential } from '../../src/internal/credential/vc/issue.js';
import { createPrivateKeySigner } from '../../src/internal/credential/vc/signer.js';
import { createDidJwk } from '../../src/internal/identity/jwk/method-jwk.js';
import { signBitstringStatusListCredential } from '../../src/internal/issuer/bitstring-status-list/credential.js';
import { createBitstringStatusListEntry } from '../../src/internal/issuer/bitstring-status-list/entry.js';
import { BitstringStatusList } from '../../src/internal/issuer/bitstring-status-list/list.js';
import { hostedWebVh, localDids } from './did-fixtures.js';

export const NOW = 1_767_225_600;
/** 合成固定鍵。実運用の鍵・ユーザーデータは含めない。 */
const issuer = createPrivateKeySigner(new Uint8Array(32).fill(41), 'EdDSA');
const holder = createPrivateKeySigner(new Uint8Array(32).fill(43), 'EdDSA');
const issuerDid = createDidJwk(issuer.publicKeyJwk).id;
const holderDid = createDidJwk(holder.publicKeyJwk).id;
const audience = 'https://verifier.example';
const nonce = 'synthetic-test-nonce';

export function credentialVectors() {
  const vc = issueCredential(
    {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: issuerDid,
      issuanceDate: '2026-01-01T00:00:00Z',
      credentialSubject: { id: holderDid, nickname: 'synthetic' },
    },
    issuer,
    { nowSeconds: NOW },
  );
  const foreignIssuerVc = issueCredential(
    {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: holderDid,
      issuanceDate: '2026-01-01T00:00:00Z',
      credentialSubject: { id: holderDid, nickname: 'synthetic' },
    },
    issuer,
    { nowSeconds: NOW },
  );
  const vp = issuePresentation(
    {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: holderDid,
      verifiableCredential: [vc],
    },
    holder,
    { audience, nonce, nowSeconds: NOW },
  );
  return {
    cases: [
      {
        id: 'signed-vc-vp',
        vc,
        vp,
        foreignIssuerVc,
        nowSeconds: NOW,
        issuerDid,
        holderDid,
        issuerPublicKeyJwk: issuer.publicKeyJwk,
        holderPublicKeyJwk: holder.publicKeyJwk,
        audience,
        nonce,
      },
    ],
  };
}

export async function didVectors() {
  return {
    cases: [
      { id: 'local-dids', ...localDids() },
      { id: 'webvh', ...(await hostedWebVh({ host: 'plain.example' })) },
      {
        id: 'webvh-witness',
        ...(await hostedWebVh({ host: 'witness.example', versions: 8, witness: true })),
      },
    ],
  };
}

/** TS所有の生成器。Go由来のライセンス未確定ベクタは再配布しない。 */
export async function statusVectors() {
  const cases = [];
  for (const purpose of ['revocation', 'suspension', 'message'] as const) {
    const size = purpose === 'message' ? 2 : 1;
    const value = purpose === 'message' ? 2 : 1;
    const list = BitstringStatusList.create(purpose, size, 131_072);
    list.set(7, value);
    const url = `https://issuer.example/status/${purpose}`;
    const token = await signBitstringStatusListCredential(list, issuer, {
      id: url,
      issuer: issuerDid,
      issuanceSeconds: NOW,
    });
    for (const index of [0, 7]) {
      const statusMessage =
        purpose === 'message'
          ? [
              { status: '0x0', message: 'ok' },
              { status: '0x2', message: 'hold' },
            ]
          : undefined;
      cases.push({
        id: `bitstring-${purpose}-${index}`,
        input: {
          format: 'bitstring-status-list',
          issuerPublicKeyJwk: issuer.publicKeyJwk,
          nowSeconds: NOW,
          statusListCredential: token,
          entry: createBitstringStatusListEntry(
            list,
            index,
            url,
            statusMessage ? { statusMessage } : {},
          ),
        },
        expected: {
          valid: index === 0,
          purpose,
          value: index === 0 ? 0 : value,
          ...(purpose === 'message' ? { message: index === 0 ? 'ok' : 'hold' } : {}),
        },
      });
    }
  }
  return { cases };
}
