/**
 * 「自分の DID として署名する」ための公開 API。
 *
 * ペルソナの鍵（P-256 / secp256k1 / Ed25519）で VP・VC・SIOPv2 id_token・signMessage を署名するための
 * `kid` 付き署名鍵の解決、既存 DID の取り込み（DID Document と保持鍵の照合、fail-closed）、
 * `did_signMessage` のコンパクト JWS、DID Document / did:web `did.json` の書き出しを提供する。
 *
 * 委任 DID: DID Core の `controller` / `capabilityDelegation` / `authentication` だけによる controller 検証と、
 * 委任先 DID として署名する署名鍵の解決（`verifyDelegationControl` / `resolveDelegatedSigner`）、他 DID の検証メソッドへの
 * 参照の解決（`inlineExternalMethods`）。検証側は既存の `verifyPresentation` / `verifyMessageJws` / `verifyIDToken`。
 */

export type {
  DelegatedKeyInput,
  DelegatedKeyMatch,
  DelegatedSigner,
  DelegatedSignerOptions,
  DelegationControl,
  DelegationControlBasis,
  DidCoreDocumentInput,
  DidWebExport,
  DidWebLocation,
  HeldKeyMatch,
  HeldKeyOptions,
  ImportedKeySource,
  ImportPersonaDeps,
  ImportPersonaFromDidInput,
  InlineExternalMethodsOptions,
  PersonaSigner,
  PersonaSignerOptions,
  PrivateKeyJwk,
  SigningRelationship,
  VerifiedSignedMessage,
  VerifyMessageOptions,
} from '../internal/credential/did-signing/index.js';
export {
  algForPublicKeyJwk,
  buildDidCoreDocument,
  buildDidWebDocument,
  createExternalEip191Signer,
  createExternalKeySigner,
  didKeyKid,
  didWebDocumentLocation,
  findHeldKeyInDocument,
  importPersonaFromDid,
  inlineExternalMethods,
  MAX_EXTERNAL_DEREFERENCES,
  methodsInRelationship,
  personaKid,
  requireStandardSigner,
  resolveDelegatedSigner,
  resolvePersonaSigner,
  samePublicKeyJwk,
  serializeDidDocument,
  signMessageJws,
  verifyDelegatedKey,
  verifyDelegationControl,
  verifyHeldKeyAgainstDid,
  verifyMessageJws,
} from '../internal/credential/did-signing/index.js';
export { p256DidPath } from '../internal/keymanager/derivation/slip10.js';
