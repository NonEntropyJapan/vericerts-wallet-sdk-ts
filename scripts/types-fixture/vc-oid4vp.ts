// VC/VP の companion 型が公開 entry の組み合わせだけで構築できることを確認する。
import {
  type AssertedVerifiableCredentialV2,
  assertTimeClaims,
  assertVerifiableCredentialV2Members,
  createPrivateKeySigner,
  type DecodedJws,
  decodeCompactJws,
  type JwtVcBody,
  type JwtVcForm,
  jwtVcBodyOf,
  resolveClockSkewSeconds,
  type VerifiableCredential,
  verifyWithJwk,
} from '@vericerts/vericerts-wallet-sdk/credential';
import type { PresentationRequestOptions } from '@vericerts/vericerts-wallet-sdk/experimental';
import type { PublicKeyJwk } from '@vericerts/vericerts-wallet-sdk/identity';
import {
  type CreatedPresentation,
  type CreatePresentationOptions,
  type CredentialMatch,
  createPresentation,
  type DcqlClaim,
  type DcqlCredential,
  type DcqlMeta,
  type DcqlQuery,
  type LoaCheck,
  type PresentationMetadata,
  type PresentationRequest,
  type QueryableCredential,
} from '@vericerts/vericerts-wallet-sdk/oid4vp';

const claim: DcqlClaim = { path: ['credentialSubject', 'name'], values: ['Bob'] };
const meta: DcqlMeta = { type_values: [['VerifiableCredential']] };
const requirement: DcqlCredential = {
  id: 'degree',
  format: 'jwt_vc_json',
  meta,
  claims: [claim],
};
const query: DcqlQuery = { credentials: [requirement] };
const queryable: QueryableCredential = {
  id: 'vc',
  format: 'jwt_vc_json',
  claims: { credentialSubject: { name: 'Bob' } },
};
const match: CredentialMatch = {
  credentialId: queryable.id,
  queryId: requirement.id,
  matchedClaims: ['credentialSubject.name'],
};
const request: PresentationRequest = {
  responseType: 'vp_token',
  clientId: 'https://verifier.example.com',
  responseMode: 'direct_post',
  responseUri: 'https://verifier.example.com/callback',
  nonce: 'n-0S6_WzA2Mj-0123456789',
  state: 'state',
  dcqlQuery: query,
};
const requestOptions: PresentationRequestOptions = {};
const vc: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { name: 'Bob' },
  issuanceDate: '2025-01-01T00:00:00Z',
  id: 'vc',
};
const checkLoa: LoaCheck = (selected) => {
  selected.forEach((item) => void item.id);
};
const options: CreatePresentationOptions = {
  checkLoa,
  rawCredentials: new Map([['vc', 'signed.jwt.vc']]),
};
const signer = createPrivateKeySigner(new Uint8Array(32).fill(1), 'ES256');
const presentation: Promise<CreatedPresentation> = createPresentation(
  request,
  [vc],
  [vc],
  signer,
  'did:example:holder',
  options,
);
const metadata: PresentationMetadata = { disputed: false };
const form: JwtVcForm = 'flat';
const body: JwtVcBody = jwtVcBodyOf({ '@context': [] });
const asserted: AssertedVerifiableCredentialV2 = assertVerifiableCredentialV2Members({
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: {},
  validFrom: '2025-01-01T00:00:00Z',
});
const decoded: DecodedJws = decodeCompactJws('a.b.c');
declare const jwk: PublicKeyJwk;
verifyWithJwk('ES256', decoded, jwk);
assertTimeClaims(decoded.payload, 0, resolveClockSkewSeconds('vc', undefined));

void [match, requestOptions, presentation, metadata, form, body, asserted];
