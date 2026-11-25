/**
 * did:cheqd メソッド実装（cheqd ネットワーク、解決のみ）。
 *
 * 解決: cheqd の did-resolver（既定 `https://resolver.cheqd.net`）へ HTTPS GET する。
 * `GET <resolverUrl>/1.0/identifiers/<did>[?versionId=&versionTime=]`
 * → `{ didResolutionMetadata, didDocument, didDocumentMetadata }`。
 * - 404 / `didResolutionMetadata.error === "notFound"` → `2003`。
 * - `didDocument.id` が要求した DID と一致しなければ `2010`。
 * - `didDocumentMetadata.deactivated === true` → `2001`（フィールドが無ければ `false` 扱い）。
 * - 鍵は Ed25519 のみ。それ以外は `2010`（`cheqd_key_unsupported`）。
 *
 * 信頼の根はリゾルバー運営者（HTTPS）。クライアントは台帳の状態証明を検証しない。重要な用途では自己ホストの
 * `cheqd/did-resolver` を `resolverUrl` に指定する。作成・更新・失効（Cosmos トランザクション）は範囲外で、
 * `create` / `update` / `deactivate` は `2002`（書き込みは `@cheqd/sdk`）。
 *
 * セキュリティ上の注意: 例外の `context` に DID・URL・本文を含めない。
 */

import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { CreateOptions, DIDDocument, DIDMethod, UpdateOptions } from '../did.js';
import {
  assertNetworkDidDocumentShape,
  RELATIONSHIP_KEYS,
  relationshipEntriesOf,
  verificationMethodsOf,
} from '../did-document-read.js';
import { asJsonObject, buildEndpointUrl, fetchResolverJson } from '../network/http-resolver.js';
import { ResolutionCache, type ResolutionCacheLike } from '../network/resolution-cache.js';
import type { ResolutionWorkBudget } from '../resolution-budget.js';
import { assertEd25519VerificationMethod, parseDidCheqd, UUID_PATTERN } from './did-cheqd.js';

/** 既定のリゾルバー（cheqd 運営）。 */
export const DEFAULT_CHEQD_RESOLVER_URL = 'https://resolver.cheqd.net';

/** DID Resolution の結果表現（`didResolutionMetadata` を含む）を要求する `Accept`。 */
const ACCEPT_RESOLUTION_RESULT = 'application/ld+json;profile="https://w3id.org/did-resolution"';

/** 受理する Content-Type（パラメータ部は除いて判定。`profile` 付きの `application/ld+json` を含む）。 */
const ALLOWED_CONTENT_TYPES: readonly string[] = ['application/ld+json', 'application/json'];

/** DID Resolution が失効した DID に返す HTTP ステータス。本文の `deactivated` で `2001` にする。 */
const HTTP_GONE = 410;

/** 解決結果のメタデータ。 */
export interface CheqdDidMetadata {
  /** 失効済みか。失効は `2001` で拒否するため、成功した解決では常に `false`。 */
  readonly deactivated: boolean;
  /** 解決した版の識別子（UUID）。 */
  readonly versionId?: string;
}

/** {@link resolveDidCheqd} の結果。 */
export interface CheqdResolution {
  readonly document: DIDDocument;
  readonly metadata: CheqdDidMetadata;
}

/** {@link resolveDidCheqd} の解決オプション。 */
export interface ResolveDidCheqdOptions {
  /** リゾルバーのベース URL（`https:` のみ。既定 {@link DEFAULT_CHEQD_RESOLVER_URL}）。 */
  readonly resolverUrl?: string;
  /** 版の指定（UUID）。 */
  readonly versionId?: string;
  /** 時点の指定（ISO 8601、オフセット必須）。 */
  readonly versionTime?: string;
  /** 取得に使う fetch 実装（未指定ならグローバル `fetch`）。 */
  readonly fetchFn?: typeof fetch;
}

interface Fetched {
  readonly resolution: CheqdResolution;
  readonly bodyLength: number;
}

function invalidOption(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID, { context: { reason } });
}

function invalidDocument(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.DID_DOC_INVALID, { context: { reason } });
}

/** `versionId` / `versionTime` を検査してクエリにする。 */
function versionQuery(versionId: string | undefined, versionTime: string | undefined) {
  const query: Record<string, string> = {};
  if (versionId !== undefined) {
    if (!UUID_PATTERN.test(versionId)) {
      throw invalidOption('cheqd_invalid_version_id');
    }
    query.versionId = versionId;
  }
  if (versionTime !== undefined) {
    // `parseIsoDateTimeMs` がオフセット必須の厳格パーサなので、オフセット無しもここで弾かれる。
    if (Number.isNaN(parseIsoDateTimeMs(versionTime))) {
      throw invalidOption('cheqd_invalid_version_time');
    }
    query.versionTime = versionTime;
  }
  return query;
}

async function fetchCheqdResolution(
  did: string,
  options: ResolveDidCheqdOptions,
  scope: ResolutionWorkBudget | undefined,
): Promise<Fetched> {
  parseDidCheqd(did);
  // 設定は own 限定で読む（`Object.prototype` 汚染で宛先・版指定が差し替わらない）。
  const resolverUrl = ownProperty<string>(options, 'resolverUrl') ?? DEFAULT_CHEQD_RESOLVER_URL;
  const versionId = ownProperty<string>(options, 'versionId');
  const versionTime = ownProperty<string>(options, 'versionTime');
  // 取得シームはプロトタイプメソッド実装が正当な DI なので own 限定にはしない（汚染だけ弾く）。
  const fetchFn = nonObjectPrototypeProperty<typeof fetch>(options, 'fetchFn');
  const query = versionQuery(versionId, versionTime);
  const url = buildEndpointUrl(resolverUrl, `/1.0/identifiers/${did}`, query);
  const { value, status, bodyLength } = await fetchResolverJson({
    url,
    accept: ACCEPT_RESOLUTION_RESULT,
    contentTypes: ALLOWED_CONTENT_TYPES,
    fetchFn,
    scope,
    extraStatuses: [HTTP_GONE],
  });
  const body = asJsonObject(value);
  const rawMetadata = ownProperty<unknown>(body, 'didDocumentMetadata');
  if (
    rawMetadata !== undefined &&
    (typeof rawMetadata !== 'object' || rawMetadata === null || Array.isArray(rawMetadata))
  ) {
    throw invalidDocument('cheqd_metadata_invalid');
  }
  const metadata = (rawMetadata ?? {}) as Readonly<Record<string, unknown>>;
  const deactivated = ownProperty<unknown>(metadata, 'deactivated');
  if (deactivated !== undefined && typeof deactivated !== 'boolean') {
    throw invalidDocument('cheqd_metadata_invalid');
  }
  if (deactivated === true) {
    throw new VericertsError(ErrorCodes.INVALID_DID, { context: { reason: 'cheqd_deactivated' } });
  }
  const resolutionMetadata = ownProperty<unknown>(body, 'didResolutionMetadata');
  const resolutionError =
    typeof resolutionMetadata === 'object' && resolutionMetadata !== null
      ? ownProperty<unknown>(resolutionMetadata, 'error')
      : undefined;
  if (resolutionError === 'notFound') {
    throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
  }
  if (resolutionError !== undefined) {
    throw invalidDocument('cheqd_resolution_error');
  }
  if (status === HTTP_GONE) {
    // 410 は失効の表現。失効と読めない 410 は取得失敗として扱う。
    throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
  }
  const resolvedVersionId = ownProperty<unknown>(metadata, 'versionId');
  if (resolvedVersionId !== undefined && typeof resolvedVersionId !== 'string') {
    throw invalidDocument('cheqd_metadata_invalid');
  }
  // 版を指定したのに別の版が返ったら、指定の版の文書として採用しない。
  if (versionId !== undefined && resolvedVersionId !== versionId) {
    throw invalidDocument('cheqd_version_mismatch');
  }
  const document = asJsonObject(
    ownProperty<unknown>(body, 'didDocument'),
  ) as unknown as DIDDocument;
  // 取り違え・なりすましの拒否。
  if (ownProperty<unknown>(document, 'id') !== did) {
    throw invalidDocument('cheqd_id_mismatch');
  }
  assertNetworkDidDocumentShape(document);
  for (const vm of verificationMethodsOf(document)) {
    assertEd25519VerificationMethod(vm);
  }
  for (const relationship of RELATIONSHIP_KEYS) {
    for (const entry of relationshipEntriesOf(document, relationship) ?? []) {
      if (typeof entry !== 'string') assertEd25519VerificationMethod(entry);
    }
  }
  return {
    resolution: {
      document: withDefaultRelationships(document),
      metadata: {
        deactivated: false,
        ...(resolvedVersionId === undefined ? {} : { versionId: resolvedVersionId }),
      },
    },
    bodyLength,
  };
}

/** cheqd は検証関係を持たない文書を許す（ADR）。必須の 3 配列は空配列で埋める。 */
function withDefaultRelationships(document: DIDDocument): DIDDocument {
  const filled: Record<string, unknown> = { __proto__: null, ...document };
  for (const key of ['verificationMethod', 'authentication', 'assertionMethod'] as const) {
    filled[key] ??= [];
  }
  return filled as unknown as DIDDocument;
}

/**
 * did:cheqd を cheqd の did-resolver 経由で DID Document とメタデータに解決する。
 *
 * 状態を持たない（キャッシュしない）。キャッシュは {@link MethodCheqd} が持つ。
 *
 * @param scope 解決スコープ全体の予算。取得した本文量を計上する（仕事量は計上しない）。
 * @throws 形式不正・版指定の不正・失効（code `2001`）・取得失敗 / 未発見（code `2003`）・
 *   Content-Type / JSON / スキーマ不正・`id` 不一致・未対応鍵・版の不一致（code `2010`）。
 */
export async function resolveDidCheqd(
  did: string,
  options?: ResolveDidCheqdOptions,
  scope?: ResolutionWorkBudget,
): Promise<CheqdResolution> {
  return (await fetchCheqdResolution(did, options ?? {}, scope)).resolution;
}

/**
 * did:cheqd メソッドプラグイン（解決のみ）。`resolverUrl` は呼び出し側の設定値（既定は cheqd 運営）。
 */
export class MethodCheqd implements DIDMethod {
  private readonly resolverUrl: string;
  private readonly fetchFn: typeof fetch | undefined;
  private readonly cache: ResolutionCacheLike<CheqdResolution>;

  /**
   * @param config.resolverUrl リゾルバーのベース URL（`https:` のみ。違反は解決時に `2003`）。
   * @param config.fetchFn 取得に使う fetch 実装。
   * @param config.nowSeconds キャッシュの時計（秒。テスト用）。
   * @param config.cache 解決結果のキャッシュ（既定は 600 秒の TTL キャッシュ。`NO_RESOLUTION_CACHE` を渡すとキャッシュしない）。
   */
  constructor(config?: {
    resolverUrl?: string;
    fetchFn?: typeof fetch;
    nowSeconds?: () => number;
    cache?: ResolutionCacheLike<CheqdResolution>;
  }) {
    this.resolverUrl =
      (config === undefined ? undefined : ownProperty<string>(config, 'resolverUrl')) ??
      DEFAULT_CHEQD_RESOLVER_URL;
    this.fetchFn =
      config === undefined
        ? undefined
        : nonObjectPrototypeProperty<typeof fetch>(config, 'fetchFn');
    this.cache =
      (config === undefined
        ? undefined
        : nonObjectPrototypeProperty<ResolutionCacheLike<CheqdResolution>>(config, 'cache')) ??
      new ResolutionCache(
        config === undefined ? undefined : ownProperty<() => number>(config, 'nowSeconds'),
      );
  }

  /** メソッド名（`'cheqd'`）。 */
  method(): string {
    return 'cheqd';
  }

  /** 書き込みは Cosmos トランザクションで、`@cheqd/sdk` の領域。 */
  async create(_opts: CreateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** 更新は controller 全員の署名つきトランザクションで、範囲外。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** 失効は `DeactivateDidDocRequest` で、範囲外。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** 最新版の DID Document を返す。 */
  async resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    return (await this.resolveWithMetadata(did, scope)).document;
  }

  /** 最新版の DID Document と、`deactivated` / `versionId` を含むメタデータを返す。キャッシュのキーは DID。 */
  async resolveWithMetadata(did: string, scope?: ResolutionWorkBudget): Promise<CheqdResolution> {
    // 形式不正（2001）はネットワークにもキャッシュにも触れず投げる。
    parseDidCheqd(did);
    return this.cache.getOrLoad(
      did,
      async () => {
        const fetched = await fetchCheqdResolution(
          did,
          { resolverUrl: this.resolverUrl, fetchFn: this.fetchFn },
          scope,
        );
        return { value: fetched.resolution, weight: fetched.bodyLength };
      },
      scope,
    );
  }
}
