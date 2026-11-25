/**
 * 他の DID Document に定義された検証メソッドへの参照の解決（DID Core §5.3）。
 *
 * 検証関係（`authentication` など）の値は、同じ文書の検証メソッドを指す DID URL 参照のほか、**別の DID
 * の検証メソッド**を指す DID URL でもよい（DID Core §5.3「Verification Relationships」）。委任 DID（例: did:web）は
 * 「委任先ペルソナの検証メソッド（`did:key:z…#z…` など）」をそのまま `authentication` に参照で載せられる。
 * 検証側が `authentication` から鍵を選ぶとき、その参照を辿れなければ鍵が選べない。
 *
 * 本モジュールは、解決済み文書の指定検証関係に含まれる**他 DID への参照**を、その DID を（キャッシュなしで）
 * 解決し直して得た検証メソッドの実体に置き換えた文書を返す。後段の同期処理（`didDocumentToVerifierKey` /
 * `findHeldKeyInDocument` / `methodsInRelationship`）はそのまま使える。
 *
 * 制約（fail-closed。いずれも `2010`、`context.reason` は固定識別子）:
 * - 参照先 DID の文書の `verificationMethod` に、参照した id の検証メソッドが**定義されている**こと
 *   （`external_method_unresolvable`）。参照先文書の検証関係を辿る再帰はしない（1 段のみ）。
 * - 参照先文書の `id` が参照した DID と一致し（`external_document_id_mismatch`）、失効していない
 *   （`external_document_deactivated`）。
 * - 検証メソッドの `controller` を持つなら参照先 DID と一致すること（`external_controller_mismatch`。DID Core §5.2.1）。
 * - 辿る参照は 1 回の**検証操作**で最大 {@link MAX_EXTERNAL_DEREFERENCES} 件（`external_references_too_many`）。
 *   1 つの操作の中で複数回呼ぶとき（controller 関係と署名鍵の両方など）は同じ {@link DereferenceBudget} を渡して共有する。
 *
 * 辿る参照は `kid`（JWS ヘッダ）が指す 1 件、`kid` がなければ先頭の要素が参照のときのその 1 件だけ（`all` 指定時は
 * すべて、`onlyDid` 指定時はその DID を指すものだけ）。使わない参照は文書から外す（解決しない = ネットワークを引かない）。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DidResolverLike } from '../../identity/bounded-resolver.js';
import type { DIDDocument, VerificationMethod } from '../../identity/did.js';
import {
  type RelationshipKey,
  relationshipEntriesOf,
  verificationMethodsOf,
} from '../../identity/did-document-read.js';
import { ownProperty } from '../../prototype-safety/own-property.js';

/** 1 回の呼び出しで辿る他 DID への参照の上限。 */
export const MAX_EXTERNAL_DEREFERENCES = 8;

/** 1 回の検証操作が辿れる他 DID への参照の残り件数。操作の中の全呼び出しで同じ値を共有する。 */
export interface DereferenceBudget {
  remaining: number;
}

/** 1 回の検証操作用の新しい予算（{@link MAX_EXTERNAL_DEREFERENCES} 件）。 */
export function createDereferenceBudget(): DereferenceBudget {
  return { remaining: MAX_EXTERNAL_DEREFERENCES };
}

/**
 * 解決した文書の `id` が要求した DID と一致するか。did:ion の long-form は短縮形 `id` の接頭辞になるので、
 * 接頭辞の一致を認めるのは did:ion だけ（他のメソッドでは `id` の完全一致が必要）。
 */
export function documentIdMatches(id: unknown, did: string): boolean {
  return (
    typeof id === 'string' &&
    (id === did || (did.startsWith('did:ion:') && did.startsWith(`${id}:`)))
  );
}

/** 相対 id（`#frag`）を文書の `id` 基準の絶対 id にする。 */
function absolute(documentId: string | undefined, id: string): string {
  return id.startsWith('#') && documentId !== undefined ? `${documentId}${id}` : id;
}

/** 失敗（`2010`）。`reason` は固定識別子のみ（DID・鍵の値は入れない）。 */
function invalid(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.DID_DOC_INVALID, { context: { reason } });
}

/** DID URL（`did:…#fragment` / `did:…?query`）の DID 部分。DID URL でなければ `undefined`。 */
export function didOfUrl(url: string): string | undefined {
  if (!url.startsWith('did:')) {
    return undefined;
  }
  const end = url.search(/[#?/]/);
  return end === -1 ? url : url.slice(0, end);
}

/** 参照先 DID の文書から、参照した検証メソッドの実体を取り出す。 */
async function dereference(
  resolver: DidResolverLike,
  did: string,
  reference: string,
): Promise<VerificationMethod> {
  const document = await resolver.resolve(did);
  const id = ownProperty<unknown>(document, 'id');
  if (typeof id !== 'string' || !documentIdMatches(id, did)) {
    throw invalid('external_document_id_mismatch');
  }
  if (ownProperty<unknown>(document, 'deactivated') === true) {
    throw invalid('external_document_deactivated');
  }
  const method = verificationMethodsOf(document).find(
    (candidate) => absolute(id, ownProperty<string>(candidate, 'id') ?? '') === reference,
  );
  if (method === undefined) {
    throw invalid('external_method_unresolvable');
  }
  const controller = ownProperty<unknown>(method, 'controller');
  if (controller !== undefined && controller !== id && controller !== did) {
    throw invalid('external_controller_mismatch');
  }
  return method;
}

/** `inlineExternalMethods` のオプション。 */
export interface InlineExternalMethodsOptions {
  /** 辿る参照をこの検証メソッド id（DID URL）に限る（JWS ヘッダ `kid`）。省略時は先頭の要素。 */
  readonly kid?: string;
  /** 参照を**すべて**辿る（署名鍵の選択側。上限 {@link MAX_EXTERNAL_DEREFERENCES}）。 */
  readonly all?: boolean;
  /** `all` のとき、この DID を指す参照だけを辿る（既知の署名鍵の DID。他の外部参照は解決しない）。 */
  readonly onlyDid?: string;
  /** 検証操作で共有する予算。省略時はこの呼び出し専用の新しい予算。 */
  readonly budget?: DereferenceBudget;
}

/**
 * 指定検証関係の他 DID への参照を検証メソッドの実体に置き換えた文書を返す（元の文書は変更しない）。
 *
 * 他 DID への参照が無ければ `document` をそのまま返す（既存の挙動を変えない・ネットワークを引かない）。
 *
 * @param resolver DID Resolver（参照先の解決に使う。キャッシュしない）。
 * @param document 解決済みの DID Document。
 * @param relationship 参照を辿る検証関係。
 * @param opts 辿る参照の絞り込み。
 * @throws 参照先を解決・取り出せない場合（VericertsError、code `2010`）、参照先の解決失敗（`2001` / `2002` / `2003`）。
 */
export async function inlineExternalMethods(
  resolver: DidResolverLike,
  document: DIDDocument,
  relationship: RelationshipKey,
  opts: InlineExternalMethodsOptions = {},
): Promise<DIDDocument> {
  const entries = relationshipEntriesOf(document, relationship);
  if (entries === undefined) {
    return document;
  }
  const documentId = ownProperty<string>(document, 'id');
  const local = new Set(
    verificationMethodsOf(document).map((method) =>
      absolute(documentId, ownProperty<string>(method, 'id') ?? ''),
    ),
  );
  const isExternal = (entry: string | VerificationMethod): entry is string =>
    typeof entry === 'string' &&
    !local.has(absolute(documentId, entry)) &&
    (didOfUrl(entry) ?? documentId) !== documentId;
  if (!entries.some(isExternal)) {
    return document;
  }
  const wanted = ownProperty<string>(opts, 'kid');
  const all = ownProperty<boolean>(opts, 'all') === true;
  const onlyDid = ownProperty<string>(opts, 'onlyDid');
  const budget = ownProperty<DereferenceBudget>(opts, 'budget') ?? createDereferenceBudget();
  const result: (string | VerificationMethod)[] = [];
  for (const [index, entry] of entries.entries()) {
    if (!isExternal(entry)) {
      result.push(entry);
      continue;
    }
    // 鍵の選択は `kid` 一致、`kid` が無ければ先頭の要素（`didDocumentToVerifierKey` の既定と同じ）。
    const did = didOfUrl(entry);
    const selected = all
      ? onlyDid === undefined || did === onlyDid
      : wanted === undefined
        ? index === 0
        : entry === wanted;
    if (!selected || did === undefined) {
      continue;
    }
    if (budget.remaining <= 0) {
      throw invalid('external_references_too_many');
    }
    budget.remaining -= 1;
    result.push(await dereference(resolver, did, entry));
  }
  return { ...document, [relationship]: result } as DIDDocument;
}
