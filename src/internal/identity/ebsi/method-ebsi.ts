/**
 * did:ebsi メソッド実装（EBSI DID Registry、法人向け）。
 *
 * 解決: 呼び出し側が設定したノードの Core API へ HTTPS GET する。
 * `GET <apiUrl>/v1/did-registry/identifiers/<did>[?valid-at=<ISO 8601>]`（認証不要）。
 * - 404 等の取得失敗 → `2003`、`id` 不一致 → `2010`、controller 先の DID は辿らない。
 * - 鍵は P-256 / secp256k1 のみ。それ以外が文書に現れたら `2010`（`ebsi_key_unsupported`）。
 * - 信頼の根はノード運営者（HTTPS）。クライアントはブロックチェーンの状態証明を検証しない。
 *
 * 登録・更新・鍵ローテ・失効（オンボーディング VC・トークン・トランザクション署名）は呼び出し側の責務。
 * `create` / `update` / `deactivate` は `2002`。DID と鍵名のローカル生成は `did-ebsi.ts`。
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
import { isEbsiSupportedKey, parseDidEbsi } from './did-ebsi.js';

/** 受理する Content-Type（`@context` 付きが既定で返る。`application/did+json` は Accept が厳密一致のときだけ）。 */
const ALLOWED_CONTENT_TYPES: readonly string[] = [
  'application/did+ld+json',
  'application/did+json',
  'application/json',
];

/** {@link resolveDidEbsi} の解決オプション。 */
export interface ResolveDidEbsiOptions {
  /** ノードのベース URL（`https://api-<env>.ebsi.<運営者のドメイン>`。`https:` のみ）。 */
  readonly apiUrl: string;
  /** 時点指定（ISO 8601、オフセット必須）。VC の検証では発行時点（`validFrom` / `iat`）を渡す。 */
  readonly validAt?: string;
  /** 取得に使う fetch 実装（未指定ならグローバル `fetch`）。 */
  readonly fetchFn?: typeof fetch;
}

/** 取得結果（キャッシュ用に本文の長さも持つ）。 */
interface FetchedDocument {
  readonly document: DIDDocument;
  readonly bodyLength: number;
}

/**
 * `validAt`（ISO 8601、`Z` またはオフセット必須）を検査する。
 *
 * @throws 形式不正（code `2001`、`ebsi_invalid_valid_at`）。
 */
function assertValidAt(validAt: string): void {
  // `parseIsoDateTimeMs` がオフセット必須の厳格パーサなので、オフセット無しもここで弾かれる。
  if (Number.isNaN(parseIsoDateTimeMs(validAt))) {
    throw new VericertsError(ErrorCodes.INVALID_DID, {
      context: { reason: 'ebsi_invalid_valid_at' },
    });
  }
}

async function fetchEbsiDocument(
  did: string,
  options: ResolveDidEbsiOptions,
  scope: ResolutionWorkBudget | undefined,
): Promise<FetchedDocument> {
  parseDidEbsi(did);
  // 設定は own 限定で読む（`Object.prototype` 汚染で宛先・時点が差し替わらない）。
  const apiUrl = ownProperty<string>(options, 'apiUrl');
  const validAt = ownProperty<string>(options, 'validAt');
  if (validAt !== undefined) {
    assertValidAt(validAt);
  }
  // 取得シームはプロトタイプメソッド実装が正当な DI なので own 限定にはしない（汚染だけ弾く）。
  const fetchFn = nonObjectPrototypeProperty<typeof fetch>(options, 'fetchFn');
  const url = buildEndpointUrl(
    apiUrl ?? '',
    `/v1/did-registry/identifiers/${did}`,
    validAt === undefined ? {} : { 'valid-at': validAt },
  );
  const { value, bodyLength } = await fetchResolverJson({
    url,
    accept: 'application/did+ld+json',
    contentTypes: ALLOWED_CONTENT_TYPES,
    fetchFn,
    scope,
  });
  const document = asJsonObject(value) as unknown as DIDDocument;
  // 取り違え・なりすましの拒否。controller 先の DID は辿らない。
  if (ownProperty<unknown>(document, 'id') !== did) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
      context: { reason: 'ebsi_id_mismatch' },
    });
  }
  assertNetworkDidDocumentShape(document);
  const methods = [...verificationMethodsOf(document)];
  for (const relationship of RELATIONSHIP_KEYS) {
    for (const entry of relationshipEntriesOf(document, relationship) ?? []) {
      if (typeof entry !== 'string') methods.push(entry);
    }
  }
  for (const vm of methods) {
    if (!isEbsiSupportedKey(ownProperty<unknown>(vm, 'publicKeyJwk'))) {
      throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
        context: { reason: 'ebsi_key_unsupported' },
      });
    }
  }
  return { document, bodyLength };
}

/**
 * did:ebsi を EBSI DID Registry の Core API 経由で DID Document に解決する。
 *
 * 状態を持たない（キャッシュしない）。キャッシュは {@link MethodEbsi} が持つ。
 *
 * @param scope 解決スコープ全体の予算。取得した本文量を計上する。
 * @throws 形式不正・`validAt` 不正（code `2001`）・取得失敗 / 未発見（code `2003`）・
 *   Content-Type / JSON / スキーマ不正・`id` 不一致・未対応鍵（code `2010`）。
 */
export async function resolveDidEbsi(
  did: string,
  options: ResolveDidEbsiOptions,
  scope?: ResolutionWorkBudget,
): Promise<DIDDocument> {
  return (await fetchEbsiDocument(did, options, scope)).document;
}

/**
 * did:ebsi メソッドプラグイン。`apiUrl` は呼び出し側の設定値で、DID からは導出しない。
 */
export class MethodEbsi implements DIDMethod {
  private readonly apiUrl: string;
  private readonly fetchFn: typeof fetch | undefined;
  private readonly cache: ResolutionCacheLike<DIDDocument>;

  /**
   * @param config.apiUrl ノードのベース URL（`https:` のみ。違反は解決時に `2003`）。
   * @param config.fetchFn 取得に使う fetch 実装。
   * @param config.nowSeconds キャッシュの時計（秒。テスト用）。
   * @param config.cache 解決結果のキャッシュ（既定は 600 秒の TTL キャッシュ。`NO_RESOLUTION_CACHE` を渡すとキャッシュしない）。
   */
  constructor(config: {
    apiUrl: string;
    fetchFn?: typeof fetch;
    nowSeconds?: () => number;
    cache?: ResolutionCacheLike<DIDDocument>;
  }) {
    this.apiUrl = ownProperty<string>(config, 'apiUrl') ?? '';
    this.fetchFn = nonObjectPrototypeProperty<typeof fetch>(config, 'fetchFn');
    this.cache =
      nonObjectPrototypeProperty<ResolutionCacheLike<DIDDocument>>(config, 'cache') ??
      new ResolutionCache(ownProperty<() => number>(config, 'nowSeconds'));
  }

  /** メソッド名（`'ebsi'`）。 */
  method(): string {
    return 'ebsi';
  }

  /** 登録は呼び出し側（EBSI 公式クライアント / Issuer のバックエンド）の責務。 */
  async create(_opts: CreateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** 更新は呼び出し側がトランザクションで送る。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** DID 文書は削除できない。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** 「今」の DID Document を返す（`valid-at` なし）。 */
  async resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    return this.load(did, undefined, scope);
  }

  /**
   * 指定時点（ISO 8601、オフセット必須）の DID Document を返す。VC の検証では発行時点で解決する。
   * キャッシュのキーは `(did, validAt)`。
   */
  async resolveAt(
    did: string,
    validAt: string,
    scope?: ResolutionWorkBudget,
  ): Promise<DIDDocument> {
    return this.load(did, validAt, scope);
  }

  private async load(
    did: string,
    validAt: string | undefined,
    scope: ResolutionWorkBudget | undefined,
  ): Promise<DIDDocument> {
    // 形式不正（2001）はネットワークにもキャッシュにも触れず投げる。
    parseDidEbsi(did);
    if (validAt !== undefined) {
      assertValidAt(validAt);
    }
    const key = JSON.stringify([did, validAt ?? null]);
    return this.cache.getOrLoad(
      key,
      async () => {
        const fetched = await fetchEbsiDocument(
          did,
          { apiUrl: this.apiUrl, validAt, fetchFn: this.fetchFn },
          scope,
        );
        return { value: fetched.document, weight: fetched.bodyLength };
      },
      scope,
    );
  }
}
