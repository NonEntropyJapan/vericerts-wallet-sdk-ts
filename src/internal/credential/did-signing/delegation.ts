/**
 * 標準（W3C DID Core）だけによる DID の委任。
 *
 * 委任先 DID `D`（did:web など任意の解決可能なメソッド）を、ペルソナ `P`（DID = `P`、署名鍵 = `K`）が
 * 「`D` として」署名できる条件を、**`D` の DID Document だけ**から判定する。独自のクレーム（`act` / `on_behalf_of` など）・
 * 独自の VC 型・委任 VC は使わない。検証側が読むのも `D` の DID Document の `verificationMethod` / `authentication` だけ
 * （`verifyPresentation` / `verifyMessageJws` / SIOPv2 id_token の検証と同じ読み方）。
 *
 * 1. **Controller 関係**（{@link verifyDelegationControl}。DID Core §5.1.2 `controller`、§5.3.5 `capabilityDelegation`）。
 *    次のいずれかを満たす（`D` の文書を**毎回**解決し直す。キャッシュしない）。
 *    - `controller` に `P` が含まれる（`basis: 'controller'`）。
 *    - `capabilityDelegation` に、`controller` が `P` の検証メソッド（埋め込み、または `P` の文書を指す DID URL 参照）が
 *      含まれる（`basis: 'capabilityDelegation'`）。
 * 2. **署名権限**（{@link verifyDelegatedKey}。DID Core §5.3.1 `authentication` / §5.3.3 `assertionMethod`）。
 *    `D` の文書の検証関係（既定 `authentication`）に、`K` と同じ公開鍵の検証メソッド `V` が列挙されている。
 *    `V` は `D` の文書に埋め込まれた検証メソッド（`kid` は `D` 配下の DID URL）でも、`P` の文書など**他 DID の
 *    検証メソッドへの DID URL 参照**（`kid` はその DID URL。参照は {@link inlineExternalMethods} で辿る）でもよい。
 *
 * どちらかを満たさなければ署名鍵を返さない（fail-closed）。コード: controller 関係なし・失効は `2006`
 * （`CONTROLLER_NOT_AUTHORIZED`）、`V` が無い・検証関係に無い・鍵不一致は `2017`（`DID_KEY_MISMATCH`）、
 * 文書不正・参照先を辿れないは `2010`、解決失敗は `2001` / `2002` / `2003`。
 * `context.reason` は固定識別子のみ（DID・鍵の値は入れない）。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DidResolverLike } from '../../identity/bounded-resolver.js';
import type { DIDDocument, PublicKeyJwk } from '../../identity/did.js';
import { controllersOf, relationshipEntriesOf } from '../../identity/did-document-read.js';
import type { KeyManager } from '../../keymanager/keymanager.js';
import type { PersonaMetadata } from '../../persona/types.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { CredentialSignerAlg } from '../vc/jws.js';
import type { CredentialSigner } from '../vc/signer.js';
import type { PrivateKeyJwk } from './external-key.js';
import {
  createDereferenceBudget,
  type DereferenceBudget,
  didOfUrl,
  documentIdMatches,
  inlineExternalMethods,
} from './external-methods.js';
import { findHeldKeyInDocument, type SigningRelationship } from './key-binding.js';
import { didKeyKid, resolvePersonaKey } from './persona-signer.js';

/** Controller 関係の根拠。 */
export type DelegationControlBasis = 'controller' | 'capabilityDelegation';

/** controller 関係の検証結果。 */
export interface DelegationControl {
  /** どちらの根拠で controller 関係が成立したか。 */
  readonly basis: DelegationControlBasis;
  /** 今回解決した委任先 DID の DID Document。 */
  readonly document: DIDDocument;
}

/** 委任先 DID の鍵まで確認できた結果。 */
export interface DelegatedKeyMatch extends DelegationControl {
  /** 署名に使う検証メソッド `V` の DID URL（JWS `kid`）。 */
  readonly kid: string;
  /** その鍵で署名する JWS `alg`。 */
  readonly alg: CredentialSignerAlg;
}

/** `verifyDelegatedKey` / `resolveDelegatedSigner` の入力（署名鍵以外）。 */
export interface DelegatedKeyInput {
  /** 委任先 DID `D`。 */
  readonly delegatedDid: string;
  /** controller 側（ペルソナ）の DID `P`。 */
  readonly controllerDid: string;
  /** 署名に使う検証関係。VP / SIOPv2 / signMessage は `authentication`（既定）、VC 発行は `assertionMethod`。 */
  readonly relationship?: SigningRelationship;
  /**
   * 署名者が使う検証メソッドの DID URL（既知なら）。指定すると、検証関係の他 DID への参照のうち**この DID を指すものだけ**
   * を辿る（無関係な外部参照を解決しない）。省略時は外部参照をすべて辿る（予算の範囲で）。
   */
  readonly kid?: string;
}

/** `resolveDelegatedSigner` のオプション。 */
export interface DelegatedSignerOptions {
  /** 委任先 DID `D`。 */
  readonly delegatedDid: string;
  /** `D` を毎回解決し直す DID Resolver（キャッシュしないこと）。 */
  readonly resolver: DidResolverLike;
  /** 署名に使う検証関係（既定 `authentication`）。 */
  readonly relationship?: SigningRelationship;
  /** `keySource: 'external'` のペルソナの秘密鍵 JWK。 */
  readonly externalKey?: PrivateKeyJwk;
}

/** 解決した委任署名鍵。 */
export interface DelegatedSigner {
  /** `kid` = 委任先 DID の検証メソッド `V`、`publicKeyJwk` / `sign` はペルソナの鍵。 */
  readonly signer: CredentialSigner;
  /** 署名主体 = 委任先 DID `D`（VP の `holder` / `iss`、id_token の `iss` / `sub`）。 */
  readonly did: string;
  /** `V` の DID URL（`signer.kid` と同じ）。 */
  readonly kid: string;
  /** JWS `alg`。 */
  readonly alg: CredentialSignerAlg;
  /** controller 関係の根拠。 */
  readonly basis: DelegationControlBasis;
}

/** 失敗（`2006`）。 */
function notController(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.CONTROLLER_NOT_AUTHORIZED, { context: { reason } });
}

/** 解決済み文書の controller 関係を判定する。成立しなければ `2006`。 */
async function controlOfDocument(
  resolver: DidResolverLike,
  document: DIDDocument,
  controllerDid: string,
  budget: DereferenceBudget,
): Promise<DelegationControlBasis> {
  if (ownProperty<unknown>(document, 'deactivated') === true) {
    throw notController('deactivated');
  }
  if (controllersOf(document).includes(controllerDid)) {
    return 'controller';
  }
  // capabilityDelegation: ペルソナが controller の検証メソッドが載っているか。他 DID への参照は、参照先の検証メソッドの
  // `controller` が参照先 DID と一致しなければならない（`inlineExternalMethods`）ので、成立し得るのは controller 自身の DID
  // （`controllerDid`）を指す参照だけ。それ以外は解決しない。
  const inlined = await inlineExternalMethods(resolver, document, 'capabilityDelegation', {
    all: true,
    onlyDid: controllerDid,
    budget,
  });
  const delegated = relationshipEntriesOf(inlined, 'capabilityDelegation') ?? [];
  if (
    delegated.some(
      (entry) =>
        typeof entry !== 'string' && ownProperty<unknown>(entry, 'controller') === controllerDid,
    )
  ) {
    return 'capabilityDelegation';
  }
  throw notController('not_a_controller');
}

/**
 * 委任先 DID を**毎回**解決し直し、`controllerDid` がその controller であることを確かめる。
 *
 * 登録時（`DELEGATED_DID_ADD`）と、切り替え・署名・提示のたびに呼ぶこと（キャッシュしない）。
 *
 * @param resolver DID Resolver。
 * @param delegatedDid 委任先 DID。
 * @param controllerDid controller 側（ペルソナ）の DID。
 * @param budget 他 DID への参照を辿れる残り件数。1 回の検証操作の中で共有する（省略時はこの呼び出し専用）。
 * @returns 成立した根拠と、今回解決した DID Document。
 * @throws controller 関係が無い・失効している（VericertsError、code `2006`。`context.reason`:
 *         `not_a_controller` / `deactivated`）、文書の `id` 不一致・参照先を辿れない（`2010`）、解決失敗（`2001` / `2002` / `2003`）。
 */
export async function verifyDelegationControl(
  resolver: DidResolverLike,
  delegatedDid: string,
  controllerDid: string,
  budget: DereferenceBudget = createDereferenceBudget(),
): Promise<DelegationControl> {
  const document = await resolver.resolve(delegatedDid);
  if (!documentIdMatches(ownProperty<unknown>(document, 'id'), delegatedDid)) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
      context: { reason: 'document_id_mismatch' },
    });
  }
  const basis = await controlOfDocument(resolver, document, controllerDid, budget);
  return { basis, document };
}

/**
 * controller 関係に加えて、委任先 DID の検証関係に保持鍵 `K` と同じ検証メソッドが載っていることを確かめる。
 *
 * @param resolver DID Resolver。
 * @param input 委任先 DID・controller DID・検証関係。
 * @param publicKeyJwk 保持している公開鍵 JWK `K`。
 * @returns 署名に使う検証メソッド `V` の DID URL（`kid`）・`alg`・controller 関係の根拠。
 * @throws {@link verifyDelegationControl} の失敗に加え、`V` が無い・検証関係に載っていない（VericertsError、
 *         code `2017`。`context.reason`: `no_matching_verification_method` / `relationship_not_granted`）、
 *         未対応の鍵種（`1030`）。
 */
export async function verifyDelegatedKey(
  resolver: DidResolverLike,
  input: DelegatedKeyInput,
  publicKeyJwk: PublicKeyJwk,
): Promise<DelegatedKeyMatch> {
  const relationship = ownProperty<SigningRelationship>(input, 'relationship') ?? 'authentication';
  // 1 回の検証操作で他 DID への参照を辿る件数は、controller 関係の判定と署名鍵の選択で 1 つの予算を共有する。
  const budget = createDereferenceBudget();
  const control = await verifyDelegationControl(
    resolver,
    input.delegatedDid,
    input.controllerDid,
    budget,
  );
  const kid = ownProperty<string>(input, 'kid');
  const kidDid = kid === undefined ? undefined : didOfUrl(kid);
  const document = await inlineExternalMethods(resolver, control.document, relationship, {
    all: true,
    ...(kidDid !== undefined ? { onlyDid: kidDid } : {}),
    budget,
  });
  const match = findHeldKeyInDocument(document, publicKeyJwk, { relationship });
  return { ...control, kid: match.kid, alg: match.alg };
}

/**
 * ペルソナの鍵で委任先 DID として署名する署名鍵を解決する。
 *
 * ペルソナの鍵（シード導出 / 取り込んだ外部鍵）に、{@link verifyDelegatedKey} が確認した `V` を `kid` として載せる。
 * 署名のたびに呼ぶこと（`D` を毎回解決し直す。キャッシュなし）。ペルソナ自身の DID の文書は引かない（使うのは鍵だけ）。
 *
 * @param keymanager シードを保持する `KeyManager`。
 * @param persona 署名するペルソナ。controller 関係の `P` はこのペルソナの DID。
 * @param opts 委任先 DID・Resolver・検証関係・外部秘密鍵。
 * @returns `did` = 委任先 DID、`kid` = `V` の署名鍵。
 * @throws 鍵の解決に失敗した場合（`2007` / `1040` / `1041`）、{@link verifyDelegatedKey} の失敗。
 */
export async function resolveDelegatedSigner(
  keymanager: KeyManager,
  persona: PersonaMetadata,
  opts: DelegatedSignerOptions,
): Promise<DelegatedSigner> {
  const delegatedDid = ownProperty<string>(opts, 'delegatedDid');
  const resolver = ownProperty<DidResolverLike>(opts, 'resolver');
  if (delegatedDid === undefined || resolver === undefined) {
    throw new VericertsError(ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE);
  }
  const { base, fields } = await resolvePersonaKey(
    keymanager,
    persona,
    ownProperty<PrivateKeyJwk>(opts, 'externalKey'),
  );
  const relationship = ownProperty<SigningRelationship>(opts, 'relationship');
  const match = await verifyDelegatedKey(
    resolver,
    {
      delegatedDid,
      controllerDid: fields.did,
      // ペルソナの検証メソッドの DID URL は既知（`D` の文書がペルソナの鍵を参照するなら、その DID を指す参照だけが要る）。
      kid: fields.kid ?? didKeyKid(fields.did),
      ...(relationship !== undefined ? { relationship } : {}),
    },
    base.publicKeyJwk,
  );
  const signer: CredentialSigner = {
    alg: base.alg,
    publicKeyJwk: base.publicKeyJwk,
    kid: match.kid,
    sign: (signingInput) => base.sign(signingInput),
  };
  return { signer, did: delegatedDid, kid: match.kid, alg: base.alg, basis: match.basis };
}
