// `./experimental` サブパスが値として公開する名前の一覧（packaging.test.ts と purpose-subpath-surface.test.ts が共有する）。

/** サブパスで公開される呼び出し可能 API（`markExperimental` でラップ済み）。 */
export const EXPERIMENTAL_CALLABLES = [
  // credential
  'buildDerivedCredential',
  'ChainVerificationCache',
  'checkTermsOfUse',
  'interpretEvidence',
  'validateTermsOfUseOnPresentation',
  'verifyCredentialChain',
  'verifyCredentialChainOnPresentation',
  'verifyEvidence',
  // auth
  'assertBinding',
  'assertBindingMatches',
  'bindingValueOf',
  'buildAuthorizationUrl',
  'contextKeyFrom',
  'contextKeyOf',
  'entryKeyFrom',
  'entryKeyOf',
  'fetchAuthorizationServerMetadata',
  'pushAuthorizationRequest',
  'pushAuthorizationRequestForPresentation',
  'receiveCredential',
  'receiveCredentialViaAuthorizationCode',
  'resolveBinding',
  'verifyJarSignature',
  // EUDI / Issuer Metadata
  'fetchIssuerMetadata',
  'presentEAACredential',
  'presentPIDCredential',
  'receiveVerifiedEAA',
  'receiveVerifiedPID',
  // eudi (WUA)
  'buildClientAttestation',
  'buildWuaProofOfPossession',
  'isWalletAttestationExpired',
  'obtainWalletUnitAttestation',
  'parseWalletUnitAttestation',
  'refreshWalletAttestation',
  'verifyWalletUnitAttestation',
  'verifyWscdBinding',
] as const;

/** 呼び出し点を持たないため素の再エクスポートとなる定数。 */
export const EXPERIMENTAL_CONSTANTS = {
  DEFAULT_TTL_MS_BY_FLOW: 'object',
  WUA_VCT: 'string',
  WUA_CLIENT_ASSERTION_TYPE: 'string',
} as const;
