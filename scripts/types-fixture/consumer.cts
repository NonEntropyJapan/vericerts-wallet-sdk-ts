// CommonJS 利用者の tsc が exports マップの `types` 条件で型を解決できることを確かめるフィクスチャ。
// scripts/smoke-types.mjs が Node16 / NodeNext / bundler の適用可能な組合せで型検査する。パッケージ名で import するため
// 自己参照解決（package.json の exports）を通る。entry を増やしたらここにも足すこと。
import * as main from '@vericerts/vericerts-wallet-sdk';
import * as aa from '@vericerts/vericerts-wallet-sdk/aa';
import {
  ENTRY_POINT_V07_ADDRESS,
  type Hex,
  signUserOpWithPasskey,
  type UserOperationV07,
  type WebAuthnAssertion,
} from '@vericerts/vericerts-wallet-sdk/aa';
import * as asset from '@vericerts/vericerts-wallet-sdk/asset';
import {
  assertPersonalSignAllowed,
  isHexString,
  isValidEvmAddress,
  parseSiweStrict,
  personalSignMessageBytes,
  type StrictSiweFields,
  signSIWE,
} from '@vericerts/vericerts-wallet-sdk/asset';
import type { NonceStore, WellKnownJsonFailure } from '@vericerts/vericerts-wallet-sdk/common';
import * as common from '@vericerts/vericerts-wallet-sdk/common';
import * as credential from '@vericerts/vericerts-wallet-sdk/credential';
import type { ReceivedIssuerTrust } from '@vericerts/vericerts-wallet-sdk/eudi';
import * as eudi from '@vericerts/vericerts-wallet-sdk/eudi';
import * as experimental from '@vericerts/vericerts-wallet-sdk/experimental';
import type { PresentDeps, ReceiveDeps } from '@vericerts/vericerts-wallet-sdk/experimental/eudi';
import * as experimentalEudi from '@vericerts/vericerts-wallet-sdk/experimental/eudi';
import type { IssuerEndpoints } from '@vericerts/vericerts-wallet-sdk/experimental/oid4vci';
import * as experimentalOid4vci from '@vericerts/vericerts-wallet-sdk/experimental/oid4vci';
import * as gdpr from '@vericerts/vericerts-wallet-sdk/gdpr';
import {
  DASHBOARD_LOG_EXPORT_MIME,
  DASHBOARD_LOG_KEY_PREFIX,
  DASHBOARD_LOG_TAIL_ANCHOR_KEY,
  PRESENTATION_LOG_TYPE,
} from '@vericerts/vericerts-wallet-sdk/gdpr';
import type {
  DelegatedSigner,
  DidResolverLike,
  PrivateKeyJwk,
} from '@vericerts/vericerts-wallet-sdk/identity';
import * as identity from '@vericerts/vericerts-wallet-sdk/identity';
import type { Storage } from '@vericerts/vericerts-wallet-sdk/keymanager';
import * as keymanager from '@vericerts/vericerts-wallet-sdk/keymanager';
import type {
  AuthorizationCodeGrant,
  CredentialAlg,
  CredentialDefinition,
  CredentialGrants,
  CredentialOffer,
  CredentialProof,
  CredentialResponse,
  CredentialSigner,
  CredentialSignerAlg,
  DeferredCredential,
  DpopProof,
  DpopProofRebuilder,
  FetchLike,
  GenerateProofJwtOptions,
  Metrics,
  PreAuthorizedCodeGrant,
  PreAuthorizedIssuerEndpoints,
  PreAuthorizedTokenRequest,
  PublicKeyJwk,
  ReceivedCredential,
  RequestCredentialOptions,
  RequestCredentialResult,
  ResolvedTokenEndpoint,
  TokenResponse,
  TxCode,
} from '@vericerts/vericerts-wallet-sdk/oid4vci';
import * as oid4vci from '@vericerts/vericerts-wallet-sdk/oid4vci';
import type { DcqlQuery } from '@vericerts/vericerts-wallet-sdk/oid4vp';
import * as oid4vp from '@vericerts/vericerts-wallet-sdk/oid4vp';
import * as otel from '@vericerts/vericerts-wallet-sdk/otel';
import type { PersonaStorage } from '@vericerts/vericerts-wallet-sdk/persona';
import * as persona from '@vericerts/vericerts-wallet-sdk/persona';
import * as trust from '@vericerts/vericerts-wallet-sdk/trust';

// 型のみのシンボルが d.ts に載り、サブパスから解決できること（実行時に消えるため import type で検査する）。
export type ProtocolEntryTypes = [
  NonceStore,
  CredentialGrants,
  AuthorizationCodeGrant,
  CredentialAlg,
  CredentialDefinition,
  CredentialOffer,
  CredentialProof,
  CredentialResponse,
  CredentialSigner,
  CredentialSignerAlg,
  DeferredCredential,
  DpopProof,
  DpopProofRebuilder,
  FetchLike,
  GenerateProofJwtOptions,
  Metrics,
  PreAuthorizedCodeGrant,
  DcqlQuery,
  PreAuthorizedIssuerEndpoints,
  PreAuthorizedTokenRequest,
  PublicKeyJwk,
  ReceivedCredential,
  RequestCredentialOptions,
  RequestCredentialResult,
  ResolvedTokenEndpoint,
  TokenResponse,
  TxCode,
  IssuerEndpoints,
  ReceivedIssuerTrust,
  PresentDeps,
  ReceiveDeps,
  WellKnownJsonFailure,
  Storage,
  PersonaStorage,
  DidResolverLike,
];

declare const issuerEndpoints: IssuerEndpoints;
const preAuthorizedEndpoints: PreAuthorizedIssuerEndpoints = issuerEndpoints;
export const tokenEndpointInput: Parameters<typeof oid4vci.resolvePreAuthorizedTokenEndpoint>[1] =
  preAuthorizedEndpoints;

const errorClass: typeof main.VericertsError = common.VericertsError;
const keyClass: typeof main.KeyManager = keymanager.KeyManager;
const personaClass: typeof main.PersonaManager = persona.PersonaManager;
const failure: WellKnownJsonFailure = (reason) =>
  new common.VericertsError(common.ErrorCodes.ISSUER_COMMUNICATION_FAILED, { context: { reason } });
const parameterFailure: Parameters<typeof common.fetchWellKnownJson>[3] = failure;
const reverseFailure: WellKnownJsonFailure = parameterFailure;
void [errorClass, keyClass, personaClass, reverseFailure];

// DID 署名の用途別 entry とメインバレルの宣言の互換性を検査する。
declare const identitySigningTypes: [DelegatedSigner, PrivateKeyJwk];
const mainSigningTypes: [main.DelegatedSigner, main.PrivateKeyJwk] = identitySigningTypes;
const signingTypes: [DelegatedSigner, PrivateKeyJwk] = mainSigningTypes;
const inlineMethods: typeof main.inlineExternalMethods = identity.inlineExternalMethods;
const requireSigner: typeof main.requireStandardSigner = credential.requireStandardSigner;
void [signingTypes, inlineMethods, requireSigner];

// /asset が公開する署名正規化・SIWE・EVM 形式検証の 6 名を名前付き import で代入位置に使う
// （`import * as asset` だけでは個々の名前の欠落を tsc が検出できない）。
const messageBytes: Uint8Array = personalSignMessageBytes('0x');
// @ts-expect-error personalSignMessageBytes の公開型は ./asset に限る。
void main.personalSignMessageBytes;
const guard: (data: string) => void = assertPersonalSignAllowed;
const siweFields: StrictSiweFields | null = parseSiweStrict('');
const hexCheck: (value: unknown, options?: { allowEmpty?: boolean }) => value is string =
  isHexString;
const addressCheck: (address: unknown) => address is string = isValidEvmAddress;
const siweSigner: typeof main.signSIWE = signSIWE;
void [messageBytes, guard, siweFields, hexCheck, addressCheck, siweSigner];

// /gdpr が公開する保存 layout とエクスポート MIME の 4 定数。リテラル型への代入で、`.d.ts` 上で
// `string` に広がっていないこと（値の契約が型にも残っていること）を検査する。
const exportMime: 'application/x-ndjson' = DASHBOARD_LOG_EXPORT_MIME;
const presentationType: 'presentation' = PRESENTATION_LOG_TYPE;
const logKeyPrefix: 'dashboard-log/' = DASHBOARD_LOG_KEY_PREFIX;
const tailAnchorKey: 'anchor/dashboard-log' = DASHBOARD_LOG_TAIL_ANCHOR_KEY;
void [exportMime, presentationType, logKeyPrefix, tailAnchorKey];

// /aa の 5 名。公開型だけで UserOperation と WebAuthn assertion を組み立てて署名関数へ渡し、
// 戻り値を同じ公開型で受ける（別形式の UserOperation へ cast せずに呼べること）。
const entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032' = ENTRY_POINT_V07_ADDRESS;
const unsignedUserOp: UserOperationV07 = {
  sender: '0x2222222222222222222222222222222222222222',
  nonce: 0n,
  callData: '0x',
  callGasLimit: 0n,
  verificationGasLimit: 0n,
  preVerificationGas: 0n,
  maxFeePerGas: 0n,
  maxPriorityFeePerGas: 0n,
  signature: '0x',
};
const passkeyAssertion: WebAuthnAssertion = {
  authenticatorData: new Uint8Array(0),
  clientDataJSON: new Uint8Array(0),
  signature: new Uint8Array(0),
};
// 型検査だけが目的なので、関数に包んで実行時には呼ばない。
export const signWithPasskey = (): UserOperationV07 =>
  signUserOpWithPasskey(
    unsignedUserOp,
    passkeyAssertion,
    '0x1111111111111111111111111111111111111111',
  );
// @ts-expect-error `Hex` は `0x` で始まらない文字列を拒否する。
const badHex: Hex = 'abc';
void [entryPoint, badHex];

export const entries = {
  main,
  aa,
  asset,
  common,
  credential,
  eudi,
  experimental,
  experimentalEudi,
  experimentalOid4vci,
  gdpr,
  identity,
  keymanager,
  oid4vci,
  oid4vp,
  otel,
  persona,
  trust,
};
