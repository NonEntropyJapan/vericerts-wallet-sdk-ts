/**
 * did:web メソッド実装（DNS/HTTPS ベース DID）。
 *
 * did:web は DID 文字列を HTTPS URL に変換し、公開された `did.json` を取得して
 * DID Document を得る:
 *   - `did:web:example.com`             → `https://example.com/.well-known/did.json`
 *   - `did:web:example.com:users:alice` → `https://example.com/users/alice/did.json`
 *
 * 変換ルール: `:` を `/` に置換し、末尾に `/did.json` を付加する。
 * ドメインのみ（パスなし）の場合は `/.well-known/did.json` を取得する。
 *
 * 解決要件:
 * - HTTPS GET（`fetch`）。最終 URL が HTTPS であること（リダイレクト先のスキーム検証）。
 * - タイムアウト 10 秒（AbortController）。
 * - Content-Type は `application/did+json` または `application/json`。
 * - JSON.parse して DIDDocument に変換する。
 *
 * キャッシュ要件:
 * - HTTP `Cache-Control: max-age` を尊重し、TTL 上限 600 秒でキャップする。
 * - negative cache（404 / DNS 失敗）は 30 秒固定。
 * - 実体は `did-web-cache.ts`（共通キャッシュ層 `internal/cache/` の did:web 向け配線）。
 *
 * did:web の生成・更新・失効は静的ファイルの配置/差し替えで運用するため、
 * SDK としては `resolve` のみ実装し、`create` / `update` / `deactivate` は非対応
 * （`METHOD_NOT_SUPPORTED`、code `2002`）とする。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・URL・レスポンス本文を含めない。
 * - TLS 1.2+ はランタイム（Bun/Node のグローバル `fetch`）の既定に依拠する。
 */

import { resolveMaxTtlSeconds, type TtlCache } from '../../cache/index.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { CreateOptions, DIDDocument, DIDMethod, UpdateOptions } from '../did.js';
import { assertDidLocationSyntax } from '../did-location-syntax.js';
import { assertResolutionWorkRemaining, type ResolutionWorkBudget } from '../resolution-budget.js';
import {
  createDidWebCache,
  DID_WEB_CACHE_MAX_TTL_SECONDS,
  type ResolveDidWebDeps,
  resolveWithDidWebCache,
} from './did-web-cache.js';
import { fetchDidWebDocument } from './did-web-fetch.js';

export { NO_DID_WEB_CACHE } from './did-web-cache.js';

/** `did:web:` メソッドプレフィックス。 */
const DID_WEB_PREFIX = 'did:web:';

/** パスなし did:web の取得パス（well-known）。 */
const WELL_KNOWN_PATH = '/.well-known/did.json';

/** パスあり did:web の末尾に付加するファイル名。 */
const DID_JSON_PATH = '/did.json';

/**
 * did:web 文字列を取得先 HTTPS URL に変換する。
 *
 * - メソッド固有 ID（`did:web:` 以降）の `:` を `/` に置換する。
 * - ドメインのみ（`/` を含まない）の場合は `/.well-known/did.json`、
 *   パスを含む場合は末尾に `/did.json` を付加する。
 * - URL エンコードされたコロン（`%3A`、ポート番号表現）は URL 化の前にデコードして
 *   `:` に戻す（W3C did:web 仕様準拠）。
 *
 * @param did did:web 文字列（`did:web:...`）。
 * @returns 取得先の HTTPS URL。
 * 各セグメントは文字種を検証する（host は `%3A<port>` のみ `%XX` 可、path は
 * `[A-Za-z0-9._~-]+` で `.` / `..` 不可。`did-location-syntax.ts`、webvh と共通）。
 *
 * @throws プレフィックス不正・識別子空・文字種不正・不正な URL になる場合（VericertsError、code `2001`）。
 */
export function didWebToUrl(did: string): string {
  if (!did.startsWith(DID_WEB_PREFIX)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const methodSpecificId = did.slice(DID_WEB_PREFIX.length);
  if (methodSpecificId.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // 識別子内に `/` が含まれていると path セグメントを偽装できるため拒否する。
  if (methodSpecificId.includes('/')) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // `:` は did:web のセグメント区切り。ポート番号は `%3A` で表現されるため、
  // セグメント分割の「後で」各セグメントの `%3A` を `:` に戻す（区切りと混同しない）。
  const segments = methodSpecificId.split(':');
  if (segments.some((segment) => segment.length === 0)) {
    // 空セグメント（先頭/末尾/連続コロン）は不正。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // `%3A` をデコードする前に host / path の文字種を検証する。`? # @ \` や `.` / `..`（`%2e` 含む）が
  // URL の構造として解釈され、DID が示す場所と別のパスを取得するのを防ぐ。
  assertDidLocationSyntax(segments[0] as string, segments.slice(1));
  const decodedSegments = segments.map((segment) => segment.replace(/%3A/gi, ':'));
  const path = decodedSegments.join('/');
  const suffix = segments.length === 1 ? WELL_KNOWN_PATH : DID_JSON_PATH;
  const urlString = `https://${path}${suffix}`;
  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    // URL 文字列に入力が含まれ得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (url.protocol !== 'https:') {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return url.toString();
}

/**
 * did:web 文字列を HTTPS 経由で DID Document に解決する。
 *
 * 手順:
 * 1. `didWebToUrl` で HTTPS URL に変換。
 * 2. キャッシュ（`deps.cache`）を参照。TTL 内なら取得せずに返す。
 * 3. `fetch`（タイムアウト 10 秒、AbortController）で GET。
 * 4. 最終 URL が HTTPS であること（リダイレクト後のスキーム）を検証。
 * 5. HTTP ステータス 2xx 以外は解決失敗。
 * 6. Content-Type が `application/did+json` / `application/json` であることを検証。
 * 7. JSON.parse して DIDDocument を構築し、`Cache-Control` に従ってキャッシュへ格納。
 *
 * キャッシュキーは**DID 文字列**であり取得先 URL ではない。`did:web:host%3A8443` と
 * `did:web:host:8443` は同一 URL に解決されるが、`doc.id` はバイト単位完全一致で照合するため
 * 両者で受理される文書は異なる。URL をキーにすると片方の DID 向けに検証済みの文書が
 * もう片方に返り、`doc.id` 検証を素通りさせてしまうため、DID をキーにする（fail-closed）。
 *
 * `deps.cache` を渡さない場合はキャッシュしない。この関数自体は状態を持たず、キャッシュの
 * 寿命は保持者（`MethodWeb` インスタンスまたはアプリケーション）に委ねる設計である。
 *
 * DID の形式、取得、文書の検証の各段階で次のエラーを返す:
 * - did → URL 変換時の DID 文字列形式不正 → `INVALID_DID`（code `2001`）。
 * - 取得失敗（ネットワークエラー / タイムアウト / HTTP 4xx・5xx / 非 HTTPS リダイレクト）
 *   → `DID_NOT_FOUND`（code `2003`、再試行可。30 秒の negative cache 対象）。
 * - Content-Type 不一致 / JSON parse 失敗 / DID Document スキーマ不正 / `id` 不一致
 *   → `DID_DOC_INVALID`（code `2010`）。
 *
 * @param did did:web 文字列（`did:web:...`）。
 * @param deps 注入する依存（fetch 実装・時計・キャッシュ・TTL 上限・観測フック）。任意。
 * @param scope 解決スコープ全体の予算（取得・保持した本文の文字数を計上する。省略時は計上しない）。
 * @returns DID Document。
 * @throws 形式不正（code `2001`）・取得失敗（code `2003`）・Content-Type / JSON / スキーマ
 *         不正（code `2010`）・TTL 上限設定の緩和（code `3002`）の場合（VericertsError）。
 */
export async function resolveDidWeb(
  did: string,
  deps: ResolveDidWebDeps = {},
  scope?: ResolutionWorkBudget,
): Promise<DIDDocument> {
  // 変換失敗（2001）はネットワークに到達しないため、キャッシュ参照より前に投げる。
  const url = didWebToUrl(did);
  return resolveWithDidWebCache(
    did,
    deps,
    () => {
      // 本文量が尽きたスコープでは取得自体を始めない。
      assertResolutionWorkRemaining(scope, 0);
      // 取得シームはプロトタイプメソッドで実装されるのが正当な DI なので own 限定にはしない。
      // `Object.prototype` 由来（汚染）だけを弾く。
      return fetchDidWebDocument(
        url,
        did,
        nonObjectPrototypeProperty<typeof fetch>(deps, 'fetchFn'),
        scope,
      );
    },
    scope,
  );
}

/**
 * did:web メソッドプラグイン。
 *
 * `resolve` のみを提供する。did:web の生成・更新・失効は静的 `did.json` の配置/差し替えで
 * 運用するため、`create` / `update` / `deactivate` は非対応で
 * `METHOD_NOT_SUPPORTED`（code `2002`）を投げる。
 */
export class MethodWeb implements DIDMethod {
  /** 解決時に使う依存（キャッシュ・fetch 実装・観測フック）。 */
  private readonly deps: ResolveDidWebDeps;

  /**
   * @param deps 注入する依存（任意）。`cache` を省略した場合はこのインスタンス専用の
   *   DID Document キャッシュを生成する。`MethodWeb` は Resolver に登録されて生存し続ける
   *   オブジェクトであり寿命が明確なため、既定でキャッシュを持たせてよい
   *   （関数版 `resolveDidWeb` は状態を持たないので既定ではキャッシュしない）。
   *   複数の Resolver でキャッシュを共有したい場合は `cache` を明示的に渡す。
   * @throws `maxTtlSeconds` が上限 600 秒を超える場合（VericertsError、code `3002`）。
   */
  constructor(deps: ResolveDidWebDeps = {}) {
    // 設定ミスは解決時ではなく構築時に落とす。ここで正規化した上限を以後そのまま使う。
    // 読み出しは own 限定（`Object.prototype` 汚染で省略した設定が攻撃者値に化けるのを防ぐ）。
    const nowSeconds = ownProperty<() => number>(deps, 'nowSeconds');
    const maxTtlSeconds = resolveMaxTtlSeconds(
      ownProperty<number>(deps, 'maxTtlSeconds'),
      DID_WEB_CACHE_MAX_TTL_SECONDS,
    );
    this.deps = {
      ...deps,
      maxTtlSeconds,
      cache: ownProperty<TtlCache<DIDDocument>>(deps, 'cache') ?? createDidWebCache(nowSeconds),
    };
  }

  /** メソッド名（`'web'`）。 */
  method(): string {
    return 'web';
  }

  /** did:web は静的ファイル配置で運用するため生成非対応（code `2002`）。 */
  async create(_opts: CreateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** did:web 文字列を HTTPS 経由で DID Document に解決する（インスタンスのキャッシュを使う）。 */
  async resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    return resolveDidWeb(did, this.deps, scope);
  }

  /** did:web はファイル差し替えで更新するため更新 API は非対応（code `2002`）。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** did:web は失効トレイルを持たないため無効化 API は非対応（code `2002`）。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }
}
