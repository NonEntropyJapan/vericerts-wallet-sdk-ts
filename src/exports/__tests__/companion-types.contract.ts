/** Typecheck-only consumer of the public barrels. The packed consumer is checked separately. */

import type { fetchWellKnownJson, WellKnownJsonFailure } from '../common.js';
import type { createDidResolver, DidResolverLike, ResolutionWorkBudget } from '../identity.js';
import type {
  AsyncCredentialSigner,
  CredentialSigningKey,
  createKmsSigner,
  KdfParams,
  KeyManager,
  Storage,
} from '../keymanager.js';
import type { PersonaManager, PersonaStorage, RestoreLegacyPersonaOptions } from '../persona.js';

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Assert<T extends true> = T;

export type PublicCompanionContracts = [
  Assert<Equal<WellKnownJsonFailure, Parameters<typeof fetchWellKnownJson>[3]>>,
  Assert<
    Equal<Storage | undefined, NonNullable<ConstructorParameters<typeof KeyManager>[0]>['storage']>
  >,
  Assert<
    Equal<KdfParams | undefined, NonNullable<ConstructorParameters<typeof KeyManager>[0]>['kdf']>
  >,
  Assert<Equal<CredentialSigningKey, ReturnType<KeyManager['getCredentialSigner']>>>,
  Assert<Equal<AsyncCredentialSigner, Awaited<ReturnType<typeof createKmsSigner>>>>,
  Assert<Equal<PersonaStorage, ConstructorParameters<typeof PersonaManager>[1]>>,
  Assert<Equal<RestoreLegacyPersonaOptions, Parameters<PersonaManager['restoreLegacyPersona']>[0]>>,
  Assert<ReturnType<typeof createDidResolver> extends DidResolverLike ? true : false>,
  Assert<Equal<ResolutionWorkBudget | undefined, Parameters<DidResolverLike['resolve']>[1]>>,
];
