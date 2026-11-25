export type { PublicKeyJwk } from '../internal/identity/did.js';
export type { AesGcmCiphertext } from '../internal/keymanager/encryption.js';
export { decryptAesGcm, encryptAesGcm } from '../internal/keymanager/encryption.js';
export type {
  RemoteMessageFormat,
  RemoteSignatureFormat,
} from '../internal/keymanager/jws/remote-signer.js';
export type {
  AsyncCredentialSigner,
  CredentialAlg,
} from '../internal/keymanager/jws/signer-types.js';
export type { KdfParams } from '../internal/keymanager/kdf.js';
export type {
  CredentialSigningKey,
  KeyPair,
  P256KeyPair,
  ShamirRecoveryResult,
  ShamirSharesResult,
  Signer,
} from '../internal/keymanager/keymanager.js';
export { KeyManager } from '../internal/keymanager/keymanager.js';
export type { KmsKeyDescriptor, KmsProvider } from '../internal/keymanager/kms/provider.js';
export { createKmsSigner } from '../internal/keymanager/kms/provider.js';
export type { MnemonicLanguage, WordCount } from '../internal/keymanager/mnemonic.js';
export type {
  EcdsaCurve,
  EcdsaSignatureEncoding,
  RecoverableSignature,
  VerifyP256Options,
  VerifySecp256k1Options,
} from '../internal/keymanager/signer.js';
export {
  derToP1363,
  getP256PublicKey,
  getSecp256k1PublicKey,
  normalizeLowS,
  p1363ToDer,
  recoverSecp256k1PublicKey,
  signP256,
  signSecp256k1Recoverable,
  verifyP256,
  verifySecp256k1,
} from '../internal/keymanager/signer.js';
export type { Storage } from '../storage/storage.js';
