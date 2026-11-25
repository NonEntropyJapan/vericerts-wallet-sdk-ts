/**
 * 「自分の DID として署名する」ための部品。
 *
 * - `key-binding.ts`: 保持鍵と DID Document の検証メソッドの照合（fail-closed、`2017`）。
 * - `public-key-jwk.ts`: 公開鍵 JWK の比較・鍵種 → JWS `alg`。
 * - `external-key.ts`: 取り込んだ秘密鍵 JWK から署名鍵を作る。
 * - `persona-signer.ts`: ペルソナから `kid` 付きの署名鍵を解決する。
 * - `sign-message.ts`: `did_signMessage` のコンパクト JWS 署名・検証。
 * - `delegation.ts`: 標準（DID Core）だけによる委任 DID の controller 検証・署名鍵の解決。
 * - `external-methods.ts`: 検証関係が参照する他 DID の検証メソッドの解決。
 * - `did-document-export.ts`: DID Core 文書・did:web `did.json` の書き出し（書き込みなし）。
 * - `import-persona.ts`: 既存 DID をペルソナとして取り込む。
 */

export { requireStandardSigner } from '../vc/signer.js';
export type {
  DelegatedKeyInput,
  DelegatedKeyMatch,
  DelegatedSigner,
  DelegatedSignerOptions,
  DelegationControl,
  DelegationControlBasis,
} from './delegation.js';
export {
  resolveDelegatedSigner,
  verifyDelegatedKey,
  verifyDelegationControl,
} from './delegation.js';
export type { DidCoreDocumentInput, DidWebExport, DidWebLocation } from './did-document-export.js';
export {
  buildDidCoreDocument,
  buildDidWebDocument,
  didWebDocumentLocation,
  serializeDidDocument,
} from './did-document-export.js';
export type { PrivateKeyJwk } from './external-key.js';
export { createExternalEip191Signer, createExternalKeySigner } from './external-key.js';
export type { InlineExternalMethodsOptions } from './external-methods.js';
export { inlineExternalMethods, MAX_EXTERNAL_DEREFERENCES } from './external-methods.js';
export type {
  ImportedKeySource,
  ImportPersonaDeps,
  ImportPersonaFromDidInput,
} from './import-persona.js';
export { importPersonaFromDid } from './import-persona.js';
export type { HeldKeyMatch, HeldKeyOptions, SigningRelationship } from './key-binding.js';
export {
  findHeldKeyInDocument,
  methodsInRelationship,
  verifyHeldKeyAgainstDid,
} from './key-binding.js';
export type { PersonaSigner, PersonaSignerOptions } from './persona-signer.js';
export { didKeyKid, personaKid, resolvePersonaSigner } from './persona-signer.js';
export { algForPublicKeyJwk, samePublicKeyJwk } from './public-key-jwk.js';
export type { VerifiedSignedMessage, VerifyMessageOptions } from './sign-message.js';
export { signMessageJws, verifyMessageJws } from './sign-message.js';
