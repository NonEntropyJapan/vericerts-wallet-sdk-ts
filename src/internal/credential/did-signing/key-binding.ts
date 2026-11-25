/**
 * 保持している公開鍵と DID Document の検証メソッドの照合。
 *
 * did:web / did:ethr / did:webvh など DID Document を外部に置く DID を「自分の DID」として使うとき、DID
 * Document の鍵と手元の鍵が一致しなければ署名してはならない。本モジュールは解決済み DID Document から、保持鍵
 * （公開鍵 JWK）と一致する検証メソッドを探し、DID Core の検証関係（`authentication` / `assertionMethod`）に
 * 列挙されていることを確かめる。**一致しなければ必ず `2017`（DID_KEY_MISMATCH）で失敗する（fail-closed）**。
 *
 * 公開鍵の表現（`publicKeyJwk` / `publicKeyMultibase` / `publicKeyHex` / `publicKeyBase58`）は既存の
 * `verificationMethodToJwk`（verifier-key-jwk.ts）で JWK に揃えてから JWK 同士で比較する。JWK にできない表現
 * （did:pkh / did:ethr controller の `blockchainAccountId`）は、`allowAddressKey` のときだけ保持鍵（secp256k1）の
 * Ethereum アドレスと照合する（`alg: "ES256K-R"`。IANA の JWS alg 登録外で、標準だけで署名する規則の例外）。
 *
 * 対応する署名アルゴリズムは `ES256`（EC P-256）/ `ES256K`（EC secp256k1、RFC 8812）/ `EdDSA`（OKP Ed25519、
 * RFC 8037）と、例外の `ES256K-R`。
 *
 * 失敗理由（`context.reason`）: `deactivated` / `document_id_mismatch` / `no_matching_verification_method` /
 * `relationship_not_granted`。理由に DID・鍵の値は含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DidResolverLike } from '../../identity/bounded-resolver.js';
import type { DIDDocument, PublicKeyJwk, VerificationMethod } from '../../identity/did.js';
import {
  relationshipEntriesOf,
  relationshipId,
  verificationMethodsOf,
} from '../../identity/did-document-read.js';
import { ES256K_R_ALG, ethereumAddressOfJwk } from '../../keymanager/eip191.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { CredentialSignerAlg } from '../vc/jws.js';
import { ethereumAddressOfMethod } from '../vc/verifier-key-ethereum.js';
import { verificationMethodToJwk } from '../vc/verifier-key-jwk.js';
import { documentIdMatches } from './external-methods.js';
import { algForPublicKeyJwk, samePublicKeyJwk } from './public-key-jwk.js';

/** 署名で使う DID Core の検証関係。 */
export type SigningRelationship = 'authentication' | 'assertionMethod';

/** 署名で使う検証関係の一覧（照合の走査順。`authentication` を先に見る）。 */
export const SIGNING_RELATIONSHIPS: readonly SigningRelationship[] = [
  'authentication',
  'assertionMethod',
];

/** 保持鍵と一致した検証メソッド。 */
export interface HeldKeyMatch {
  /** 一致した検証メソッドの DID URL（JWS `kid`。`did#fragment`）。 */
  readonly kid: string;
  /** その鍵で署名する JWS `alg`。 */
  readonly alg: CredentialSignerAlg;
  /** 一致した検証メソッド（`kid`）が列挙されている検証関係（1 つ以上）。 */
  readonly relationships: readonly SigningRelationship[];
  /**
   * 保持鍵と一致した**全ての**検証メソッドを合わせた検証関係。同じ鍵が用途別の検証メソッドに分かれる DID
   * （did:ethr の `sigAuth` と `veriKey` など）では `relationships` より広い。
   */
  readonly allRelationships: readonly SigningRelationship[];
  /** 一致した検証メソッド。 */
  readonly verificationMethod: VerificationMethod;
}

/** `findHeldKeyInDocument` / `verifyHeldKeyAgainstDid` のオプション。 */
export interface HeldKeyOptions {
  /** この検証メソッド id に限定する（相対 `#frag` は文書の `id` 基準）。 */
  readonly kid?: string;
  /** 一致した検証メソッドが必ず含むべき検証関係。省略時は `authentication` / `assertionMethod` のいずれか 1 つ以上。 */
  readonly relationship?: SigningRelationship;
  /**
   * 一致する検証メソッドが複数あるとき、この id を優先する（相対 `#frag` は文書の `id` 基準）。`kid` と異なり、
   * 優先 id が条件を満たさなくても他の一致する検証メソッドを使う。
   */
  readonly preferKid?: string;
  /**
   * 公開鍵を持たず `blockchainAccountId` だけの検証メソッド（did:pkh / did:ethr の controller 鍵）を、保持する secp256k1 鍵の
   * アドレスで照合することを許す（一致したら `alg: "ES256K-R"`）。既定 `false`。IANA の JWS alg 登録外で、標準だけで署名する
   * 規則の例外。自分の DID として署名する経路（取り込み・`resolvePersonaSigner`）だけが `true` を渡す。
   */
  readonly allowAddressKey?: boolean;
}

/** 相対 id（`#frag`）を文書の `id` 基準の絶対 id にする。 */
function absoluteId(documentId: string | undefined, id: string): string {
  return id.startsWith('#') && documentId !== undefined ? `${documentId}${id}` : id;
}

/**
 * DID Document の指定検証関係に列挙された検証メソッドを、参照を解決して返す。
 *
 * 文字列参照は `verificationMethod` の id と突き合わせる（相対 id は文書 `id` 基準）。解決できない参照は
 * 無視する（その参照では鍵を選ばない）。埋め込みの検証メソッドはそのまま使う。
 *
 * @returns 検証メソッドと、その絶対 id の組。
 */
export function methodsInRelationship(
  document: DIDDocument,
  relationship: SigningRelationship,
): readonly { readonly id: string; readonly method: VerificationMethod }[] {
  const documentId = ownProperty<string>(document, 'id');
  const byId = new Map<string, VerificationMethod>();
  for (const method of verificationMethodsOf(document)) {
    const id = ownProperty<string>(method, 'id');
    if (id !== undefined && !byId.has(absoluteId(documentId, id))) {
      byId.set(absoluteId(documentId, id), method);
    }
  }
  const resolved: { id: string; method: VerificationMethod }[] = [];
  for (const entry of relationshipEntriesOf(document, relationship) ?? []) {
    const rawId = relationshipId(entry);
    if (rawId === undefined) {
      continue;
    }
    const id = absoluteId(documentId, rawId);
    const method = typeof entry === 'string' ? byId.get(id) : entry;
    if (method !== undefined) {
      resolved.push({ id, method });
    }
  }
  return resolved;
}

/** 検証メソッドの公開鍵を JWK にする。JWK にできない表現・未対応の鍵は `undefined`（照合対象外）。 */
function methodJwk(method: VerificationMethod): PublicKeyJwk | undefined {
  try {
    return verificationMethodToJwk(method);
  } catch (error) {
    if (error instanceof VericertsError) {
      return undefined;
    }
    throw error;
  }
}

/** 失敗（`2017`）。`reason` は固定識別子のみ。 */
function mismatch(reason: string, relationship?: SigningRelationship): VericertsError {
  return new VericertsError(ErrorCodes.DID_KEY_MISMATCH, {
    context: relationship === undefined ? { reason } : { reason, relationship },
  });
}

/**
 * 解決済み DID Document から、保持鍵と一致する検証メソッドを探す（純粋関数）。
 *
 * 一致した検証メソッドのうち、`opts.relationship` を満たすものから、`opts.preferKid` → 標準の `alg` で署名できるもの →
 * 両方の検証関係に載るもの → 最初の 1 件、の順で 1 つ選ぶ。
 *
 * 一致の種類は 2 つ。(1) 検証メソッドの公開鍵（JWK / multibase / hex / base58）が保持鍵と同じ（`alg` は鍵種に従う標準の
 * `ES256` / `ES256K` / `EdDSA`）。(2) `opts.allowAddressKey` のとき、保持鍵が secp256k1 で、検証メソッドが公開鍵を持たず
 * `blockchainAccountId`（`eip155` の CAIP-10）だけを持ち、そのアドレスが保持鍵のアドレスと同じ（did:pkh / did:ethr の
 * controller 鍵。`alg` は `ES256K-R`。IANA の JWS alg 登録外で、標準だけで署名する規則の例外）。
 *
 * @param document 解決済みの DID Document。
 * @param publicKeyJwk 保持している公開鍵 JWK。
 * @param opts `kid` 限定・必須の検証関係・アドレス鍵の許可。
 * @returns 一致した検証メソッド。
 * @throws 失効済み（`deactivated`）・検証メソッドが一致しない・検証関係に列挙されていない場合（VericertsError、
 *         code `2017`）。保持鍵が未対応の鍵種の場合（code `1030`）。
 */
export function findHeldKeyInDocument(
  document: DIDDocument,
  publicKeyJwk: PublicKeyJwk,
  opts: HeldKeyOptions = {},
): HeldKeyMatch {
  const keyAlg = algForPublicKeyJwk(publicKeyJwk);
  // オプションは own 限定で読む（`Object.prototype` 汚染で省略した条件が緩まない）。
  const kid = ownProperty<string>(opts, 'kid');
  const relationship = ownProperty<SigningRelationship>(opts, 'relationship');
  const preferKid = ownProperty<string>(opts, 'preferKid');
  // アドレス鍵（標準外の例外）は呼び出し側が明示したときだけ、secp256k1 の保持鍵だけで照合する。
  const heldAddress =
    ownProperty<boolean>(opts, 'allowAddressKey') === true && keyAlg === 'ES256K'
      ? ethereumAddressOfJwk(
          ownProperty<unknown>(publicKeyJwk, 'x'),
          ownProperty<unknown>(publicKeyJwk, 'y'),
        )
      : undefined;
  /** 検証メソッドが保持鍵と一致するときの `alg`（一致しなければ `undefined`）。 */
  const algIfHeld = (method: VerificationMethod): CredentialSignerAlg | undefined => {
    const jwk = methodJwk(method);
    if (jwk !== undefined) {
      return samePublicKeyJwk(jwk, publicKeyJwk) ? keyAlg : undefined;
    }
    return heldAddress !== undefined && ethereumAddressOfMethod(method) === heldAddress
      ? ES256K_R_ALG
      : undefined;
  };
  if (ownProperty<unknown>(document, 'deactivated') === true) {
    throw mismatch('deactivated', relationship);
  }
  const documentId = ownProperty<string>(document, 'id');
  const wanted = kid === undefined ? undefined : absoluteId(documentId, kid);
  const granted = new Map<
    string,
    { method: VerificationMethod; relationships: SigningRelationship[] }
  >();
  for (const candidate of SIGNING_RELATIONSHIPS) {
    for (const { id, method } of methodsInRelationship(document, candidate)) {
      if (wanted !== undefined && id !== wanted) {
        continue;
      }
      const entry = granted.get(id) ?? { method, relationships: [] };
      entry.relationships.push(candidate);
      granted.set(id, entry);
    }
  }
  const matches: HeldKeyMatch[] = [];
  for (const [id, { method, relationships }] of granted) {
    const alg = algIfHeld(method);
    if (alg !== undefined) {
      matches.push({
        kid: id,
        alg,
        relationships,
        allRelationships: [],
        verificationMethod: method,
      });
    }
  }
  const eligible =
    relationship === undefined
      ? matches
      : matches.filter((match) => match.relationships.includes(relationship));
  const preferred = preferKid === undefined ? undefined : absoluteId(documentId, preferKid);
  // 標準の alg で署名できる検証メソッドがあればそれを使う（`ES256K-R` は標準外の例外なので、ほかに無いときだけ）。
  const standard = eligible.filter((match) => match.alg !== ES256K_R_ALG);
  const pool = standard.length > 0 ? standard : eligible;
  const best =
    eligible.find((match) => match.kid === preferred) ??
    pool.find((match) => match.relationships.length === SIGNING_RELATIONSHIPS.length) ??
    pool[0];
  if (best !== undefined) {
    const all = SIGNING_RELATIONSHIPS.filter((candidate) =>
      matches.some((match) => match.relationships.includes(candidate)),
    );
    return { ...best, allRelationships: all };
  }
  // 理由の切り分け: 検証関係に載っていないだけで、検証メソッド自体は鍵と一致しているか。
  const listedElsewhere = verificationMethodsOf(document).some((method) => {
    const id = ownProperty<string>(method, 'id');
    if (wanted !== undefined && (id === undefined || absoluteId(documentId, id) !== wanted)) {
      return false;
    }
    return algIfHeld(method) !== undefined;
  });
  throw mismatch(
    matches.length > 0 || listedElsewhere
      ? 'relationship_not_granted'
      : 'no_matching_verification_method',
    relationship,
  );
}

/**
 * DID を SDK の Resolver で解決し、保持鍵が DID Document の検証メソッドと一致することを確かめる。
 *
 * 取り込み時だけでなく**署名のたびに**呼ぶこと（ここでは記憶しない。鍵のローテーション・失効後に古い鍵で署名しないため、
 * `resolver` は DID Document を記憶しないものを渡す: `createWallet` は `Resolver.resolveUncached` を使う）。解決の失敗
 * （`2001` / `2002` / `2003` / `2010` など）はそのまま伝播する。
 *
 * @param resolver DID Resolver（`createDidResolver` の戻り値など）。
 * @param did 照合する DID。
 * @param publicKeyJwk 保持している公開鍵 JWK。
 * @param opts `kid` 限定・必須の検証関係。
 * @returns 一致した検証メソッド（`kid` / `alg` / 検証関係）。
 * @throws 一致しない場合（VericertsError、code `2017`）、解決失敗（`2001` / `2002` / `2003` / `2010`）、未対応の鍵種（`1030`）。
 */
export async function verifyHeldKeyAgainstDid(
  resolver: DidResolverLike,
  did: string,
  publicKeyJwk: PublicKeyJwk,
  opts: HeldKeyOptions = {},
): Promise<HeldKeyMatch> {
  const document = await resolver.resolve(did);
  if (!documentIdMatches(ownProperty<unknown>(document, 'id'), did)) {
    throw mismatch('document_id_mismatch', ownProperty<SigningRelationship>(opts, 'relationship'));
  }
  return findHeldKeyInDocument(document, publicKeyJwk, opts);
}
