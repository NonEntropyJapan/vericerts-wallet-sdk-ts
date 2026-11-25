import type { CredentialSigner } from '../../../credential/vc/signer.js';
import { ErrorCodes } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import * as eudi from '../../eudi/issuance/__tests__/issuance-fixtures.js';
import { resolveReceiveDeps } from '../../eudi/issuance/deps.js';
import { receivePIDCredential } from '../../eudi/issuance/receive.js';
import * as flow from '../../oid4vci/authz-flow/__tests__/flow-fixtures.js';
import { resolveFlowDeps } from '../../oid4vci/authz-flow/deps.js';
import { receiveCredentialViaAuthorizationCode } from '../../oid4vci/authz-flow/receive.js';
import * as facade from '../../oid4vci/facade/__tests__/facade-fixtures.js';
import { resolveReceiveCredentialDeps } from '../../oid4vci/facade/deps.js';
import { receiveCredential } from '../../oid4vci/facade/receive.js';

export interface ReceiveFixture {
  readonly signer: CredentialSigner;
  readonly calls: readonly { readonly url: string }[];
  readonly tokenUrl: string;
  readonly credentialUrl: string;
  readonly errorCode: string;
  readonly reason: string;
  invoke(): Promise<unknown>;
  resolvedSigner(): CredentialSigner;
  setSigner(value: unknown): void;
  removeSigner(): void;
  setSignerDescriptor(descriptor: PropertyDescriptor): void;
  duringToken(callback: () => void): void;
}

function tokenHook(fetchImpl: FetchLike, tokenUrl: string) {
  let callback = () => {};
  return {
    fetchImpl: ((url, init) => {
      if (url === tokenUrl) callback();
      return fetchImpl(url, init);
    }) satisfies FetchLike,
    duringToken(value: () => void) {
      callback = value;
    },
  };
}

function fixture(
  deps: { readonly signer: CredentialSigner },
  calls: readonly { readonly url: string }[],
  tokenUrl: string,
  credentialUrl: string,
  errorCode: string,
  reason: string,
  invoke: () => Promise<unknown>,
  resolvedSigner: () => CredentialSigner,
  duringToken: (callback: () => void) => void,
): ReceiveFixture {
  return {
    signer: deps.signer,
    calls,
    tokenUrl,
    credentialUrl,
    errorCode,
    reason,
    invoke,
    resolvedSigner,
    duringToken,
    setSigner(value) {
      Object.defineProperty(deps, 'signer', { value, configurable: true, writable: true });
    },
    removeSigner() {
      Reflect.deleteProperty(deps, 'signer');
    },
    setSignerDescriptor(descriptor) {
      Object.defineProperty(deps, 'signer', { ...descriptor, configurable: true });
    },
  };
}

function pid(): ReceiveFixture {
  const stub = eudi.createIssuerStub(eudi.buildSdJwtVc({ claims: eudi.VALID_PID_CLAIMS }));
  const hook = tokenHook(stub.fetchImpl, eudi.TOKEN_URL);
  const deps = eudi.receiveDeps(hook.fetchImpl);
  return fixture(
    deps,
    stub.calls,
    eudi.TOKEN_URL,
    eudi.CREDENTIAL_URL,
    ErrorCodes.CREDENTIAL_REQUEST_FAILED,
    'invalid_receive_deps',
    () => receivePIDCredential(eudi.defaultOfferURI(), deps),
    () => resolveReceiveDeps(deps).signer,
    hook.duringToken,
  );
}

function facadeReceive(authorizationCode: boolean): ReceiveFixture {
  const stub = facade.createStubFetch({
    [facade.ISSUER_METADATA_URL]: () =>
      facade.issuerMetadataResponse(
        authorizationCode ? { authorization_servers: [facade.AS] } : {},
      ),
    [facade.ISSUER_AS_METADATA_URL]: () => facade.asMetadataResponse({ issuer: facade.ISSUER }),
    [facade.AS_METADATA_URL]: () => facade.asMetadataResponse(),
    [facade.PAR_URL]: facade.parResponse,
    [facade.TOKEN_URL]: facade.tokenResponse(),
    [facade.CREDENTIAL_URL]: facade.credentialResponse,
  });
  const hook = tokenHook(stub.fetchImpl, facade.TOKEN_URL);
  const deps = authorizationCode
    ? facade.authorizationCodeDeps(stub, { fetchImpl: hook.fetchImpl })
    : facade.facadeDeps(stub, { fetchImpl: hook.fetchImpl });
  return fixture(
    deps,
    stub.calls,
    facade.TOKEN_URL,
    facade.CREDENTIAL_URL,
    ErrorCodes.TOKEN_REQUEST_FAILED,
    'invalid_receive_deps',
    () =>
      receiveCredential(
        authorizationCode ? facade.authorizationCodeOfferURI() : facade.preAuthorizedOfferURI(),
        deps,
      ),
    () => resolveReceiveCredentialDeps(deps).signer,
    hook.duringToken,
  );
}

function authorizationCode(): ReceiveFixture {
  const stub = flow.createHappyStub();
  const hook = tokenHook(stub.fetchImpl, flow.TOKEN_URL);
  const deps = flow.flowDeps(stub, { fetchImpl: hook.fetchImpl });
  return fixture(
    deps,
    stub.calls,
    flow.TOKEN_URL,
    flow.CREDENTIAL_URL,
    ErrorCodes.TOKEN_REQUEST_FAILED,
    'invalid_flow_deps',
    () => receiveCredentialViaAuthorizationCode(flow.flowOptions(), deps),
    () => resolveFlowDeps(deps).signer,
    hook.duringToken,
  );
}

export const receiveFixtures = [
  ['EUDI PID', pid],
  ['facade pre-authorized', () => facadeReceive(false)],
  ['facade authorization-code', () => facadeReceive(true)],
  ['direct authorization-code', authorizationCode],
] as const;

export function callsTo(fixture: ReceiveFixture, url: string): number {
  return fixture.calls.filter((call) => call.url === url).length;
}

export function signerWithDescriptor(
  fixture: ReceiveFixture,
  descriptor: PropertyDescriptor,
): object {
  return Object.defineProperty(
    { alg: fixture.signer.alg, publicKeyJwk: fixture.signer.publicKeyJwk },
    'sign',
    { ...descriptor, configurable: true },
  );
}
