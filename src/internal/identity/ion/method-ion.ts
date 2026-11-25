/**
 * did:ion メソッド実装（Sidetree on Bitcoin、解決のみ）。
 *
 * 解決: 呼び出し側が設定した Sidetree ノードへ HTTPS GET する。
 * `GET <nodeUrl>/identifiers/<did>`（short-form / long-form）→ `{ didDocument, didDocumentMetadata }`。
 * 1. long-form はローカルで初期状態を検証する（`did-ion.ts`。仕事量を `scope` に計上）。
 * 2. `deactivated === true` → `2001`。
 * 3. `method.published === false`（アンカー前）は既定で `2003`。`allowUnpublished` のときだけ採用する
 *    （初期状態だけを根拠とした文書で、更新・回復・失効が既に行われていないことは保証できない）。
 * 4. 404 等の取得失敗 → `2003`。
 *
 * 信頼の根はノード運営者（HTTPS）。long-form の初期状態の整合だけが自己検証できる。返された文書の中身を
 * 初期状態から再構成して突き合わせる処理は持たない（`allowUnpublished` で採る未公開文書も同じ）。
 *
 * 作成・更新・回復・失効・`POST /operations` は範囲外（`create` / `update` / `deactivate` は `2002`）。
 * `@decentralized-identity/ion-sdk` は使わない。
 *
 * セキュリティ上の注意: 例外の `context` に DID・URL・本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { CreateOptions, DIDDocument, DIDMethod, UpdateOptions } from '../did.js';
import { assertNetworkDidDocumentShape } from '../did-document-read.js';
import { asJsonObject, buildEndpointUrl, fetchResolverJson } from '../network/http-resolver.js';
import { ResolutionCache, type ResolutionCacheLike } from '../network/resolution-cache.js';
import type { ResolutionWorkBudget } from '../resolution-budget.js';
import { type ParsedDidIon, parseDidIon, verifyIonLongForm } from './did-ion.js';
import { absolutizeDidUrls } from './did-url.js';

/** 受理する Content-Type。 */
const ALLOWED_CONTENT_TYPES: readonly string[] = [
  'application/did+ld+json',
  'application/did+json',
  'application/ld+json',
  'application/json',
];

/** 解決結果のメタデータ（`didDocumentMetadata` のうち SDK が返すもの）。 */
export interface IonDidMetadata {
  /** アンカー済みか（`method.published`）。 */
  readonly published: boolean;
  /** 正規の識別子（short-form）。長期の参照はこちらを使う。 */
  readonly canonicalId?: string;
  /** 等価な表記（short-form / long-form）。 */
  readonly equivalentId?: readonly string[];
}

/** {@link resolveDidIon} の結果。 */
export interface IonResolution {
  readonly document: DIDDocument;
  readonly metadata: IonDidMetadata;
}

/** {@link resolveDidIon} の解決オプション。 */
export interface ResolveDidIonOptions {
  /** Sidetree ノードのベース URL（`https:` のみ）。 */
  readonly nodeUrl: string;
  /** アンカー前（`published: false`）の文書を採用するか（既定 `false`）。 */
  readonly allowUnpublished?: boolean;
  /** 取得に使う fetch 実装（未指定ならグローバル `fetch`）。 */
  readonly fetchFn?: typeof fetch;
}

interface Fetched {
  readonly resolution: IonResolution;
  readonly bodyLength: number;
}

function invalidMetadata(): VericertsError {
  return new VericertsError(ErrorCodes.DID_DOC_INVALID, {
    context: { reason: 'ion_metadata_invalid' },
  });
}

/** `value` が、同じ did-suffix を指す did:ion（short-form / long-form）を指していれば `true`。 */
function referencesSuffix(value: unknown, suffix: string): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  try {
    return parseDidIon(value).suffix === suffix;
  } catch {
    return false;
  }
}

/** `didDocumentMetadata` を検査して {@link IonDidMetadata} を取り出す（失効は呼び出し側が先に判定済み）。 */
function readMetadata(raw: Readonly<Record<string, unknown>>, suffix: string): IonDidMetadata {
  const method = ownProperty<unknown>(raw, 'method');
  const published =
    typeof method === 'object' && method !== null
      ? ownProperty<unknown>(method, 'published')
      : undefined;
  if (typeof published !== 'boolean') {
    throw invalidMetadata();
  }
  const canonicalId = ownProperty<unknown>(raw, 'canonicalId');
  const equivalentId = ownProperty<unknown>(raw, 'equivalentId');
  if (canonicalId !== undefined && !referencesSuffix(canonicalId, suffix)) {
    throw invalidMetadata();
  }
  if (
    equivalentId !== undefined &&
    !(Array.isArray(equivalentId) && equivalentId.every((id) => referencesSuffix(id, suffix)))
  ) {
    throw invalidMetadata();
  }
  return {
    published,
    ...(canonicalId === undefined ? {} : { canonicalId }),
    ...(equivalentId === undefined ? {} : { equivalentId: equivalentId as readonly string[] }),
  };
}

async function fetchIonResolution(
  did: string,
  parsed: ParsedDidIon,
  options: ResolveDidIonOptions,
  scope: ResolutionWorkBudget | undefined,
): Promise<Fetched> {
  // 設定は own 限定で読む（`Object.prototype` 汚染で宛先・未公開の許容が差し替わらない）。
  const nodeUrl = ownProperty<string>(options, 'nodeUrl');
  const allowUnpublished = ownProperty<boolean>(options, 'allowUnpublished') === true;
  // 取得シームはプロトタイプメソッド実装が正当な DI なので own 限定にはしない（汚染だけ弾く）。
  const fetchFn = nonObjectPrototypeProperty<typeof fetch>(options, 'fetchFn');
  const url = buildEndpointUrl(nodeUrl ?? '', `/identifiers/${did}`);
  const { value, bodyLength } = await fetchResolverJson({
    url,
    accept: 'application/did+ld+json, application/json',
    contentTypes: ALLOWED_CONTENT_TYPES,
    fetchFn,
    scope,
  });
  const body = asJsonObject(value);
  const rawMetadata = ownProperty<unknown>(body, 'didDocumentMetadata');
  if (typeof rawMetadata !== 'object' || rawMetadata === null || Array.isArray(rawMetadata)) {
    throw invalidMetadata();
  }
  const metadata = rawMetadata as Readonly<Record<string, unknown>>;
  if (ownProperty<unknown>(metadata, 'deactivated') === true) {
    throw new VericertsError(ErrorCodes.INVALID_DID, { context: { reason: 'ion_deactivated' } });
  }
  const document = asJsonObject(
    ownProperty<unknown>(body, 'didDocument'),
  ) as unknown as DIDDocument;
  // 要求した DID か、同じ did-suffix の short-form でなければ取り違え・なりすまし。
  const id = ownProperty<unknown>(document, 'id');
  if (id !== did && id !== `did:ion:${parsed.suffix}`) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
      context: { reason: 'ion_id_mismatch' },
    });
  }
  const readMeta = readMetadata(metadata, parsed.suffix);
  // 未公開を採れるのは long-form だけ（初期状態が DID に束縛されている）。short-form は束縛するものがない。
  if (!readMeta.published && !(allowUnpublished && parsed.longForm !== undefined)) {
    throw new VericertsError(ErrorCodes.DID_NOT_FOUND, { context: { reason: 'ion_unpublished' } });
  }
  assertNetworkDidDocumentShape(document);
  return {
    resolution: { document: absolutizeDidUrls(document, id), metadata: readMeta },
    bodyLength,
  };
}

/**
 * did:ion を Sidetree ノード経由で DID Document とメタデータに解決する。
 *
 * 状態を持たない（キャッシュしない）。キャッシュは {@link MethodIon} が持つ。
 *
 * @param scope 解決スコープ全体の予算。long-form 検証の仕事量と取得した本文量を計上する。
 * @throws 形式不正・失効（code `2001`）・取得失敗 / 未発見 / 未公開（code `2003`）・
 *   long-form 不一致・Content-Type / JSON / スキーマ / メタデータ不正・`id` 不一致（code `2010`）。
 */
export async function resolveDidIon(
  did: string,
  options: ResolveDidIonOptions,
  scope?: ResolutionWorkBudget,
): Promise<IonResolution> {
  const parsed = parseDidIon(did);
  verifyIonLongForm(parsed, scope);
  return (await fetchIonResolution(did, parsed, options, scope)).resolution;
}

/**
 * did:ion メソッドプラグイン（解決のみ）。`nodeUrl` は呼び出し側の設定値で、DID からは導出しない。
 */
export class MethodIon implements DIDMethod {
  private readonly nodeUrl: string;
  private readonly allowUnpublished: boolean;
  private readonly fetchFn: typeof fetch | undefined;
  private readonly cache: ResolutionCacheLike<IonResolution>;

  /**
   * @param config.nodeUrl Sidetree ノードのベース URL（`https:` のみ。違反は解決時に `2003`）。
   * @param config.allowUnpublished アンカー前の文書を採用するか（既定 `false`）。
   * @param config.fetchFn 取得に使う fetch 実装。
   * @param config.nowSeconds キャッシュの時計（秒。テスト用）。
   * @param config.cache 解決結果のキャッシュ（既定は 600 秒の TTL キャッシュ。`NO_RESOLUTION_CACHE` を渡すとキャッシュしない）。
   */
  constructor(config: {
    nodeUrl: string;
    allowUnpublished?: boolean;
    fetchFn?: typeof fetch;
    nowSeconds?: () => number;
    cache?: ResolutionCacheLike<IonResolution>;
  }) {
    this.nodeUrl = ownProperty<string>(config, 'nodeUrl') ?? '';
    this.allowUnpublished = ownProperty<boolean>(config, 'allowUnpublished') === true;
    this.fetchFn = nonObjectPrototypeProperty<typeof fetch>(config, 'fetchFn');
    this.cache =
      nonObjectPrototypeProperty<ResolutionCacheLike<IonResolution>>(config, 'cache') ??
      new ResolutionCache(ownProperty<() => number>(config, 'nowSeconds'));
  }

  /** メソッド名（`'ion'`）。 */
  method(): string {
    return 'ion';
  }

  /** 作成は {@link resolveDidIon} と別の独立関数の領域。 */
  async create(_opts: CreateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** 更新は更新鍵のリビールを伴うステートフルな操作で、範囲外。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** 失効は回復鍵による操作で、範囲外。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** DID Document を返す。 */
  async resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    return (await this.resolveWithMetadata(did, scope)).document;
  }

  /** DID Document と、`canonicalId` / `equivalentId` を含むメタデータを返す。キャッシュのキーは DID。 */
  async resolveWithMetadata(did: string, scope?: ResolutionWorkBudget): Promise<IonResolution> {
    // 形式不正（2001）はネットワークにもキャッシュにも触れず投げる。
    const parsed = parseDidIon(did);
    return this.cache.getOrLoad(
      did,
      async () => {
        verifyIonLongForm(parsed, scope);
        const fetched = await fetchIonResolution(
          did,
          parsed,
          {
            nodeUrl: this.nodeUrl,
            allowUnpublished: this.allowUnpublished,
            fetchFn: this.fetchFn,
          },
          scope,
        );
        return { value: fetched.resolution, weight: fetched.bodyLength };
      },
      scope,
    );
  }
}
