/**
 * `validateCredentialSchema`テストの共有フィクスチャ。
 *
 * 実ネットワークを使わないために `fetchImpl` を注入する（`sdjwt/type-metadata` のテストと同方針）。
 * グローバル `fetch` は差し替えず、実装が公開している DI シームのみを使う。
 * `requested` に要求 URL を記録するので、フェッチ回数（キャッシュ / リモート `$ref` 不取得）を
 * そのまま assert できる。
 */

import type { VerifiableCredential } from '../../vc.js';

/** 1 URL 分の応答定義。 */
export interface StubResponse {
  /** JSON 本文（`body` / `chunks` を指定しない場合に直列化される）。 */
  readonly json?: unknown;
  /** 生の本文（JSON パース失敗のテスト用）。 */
  readonly body?: string;
  /** 分割送信する本文（`content-length` の付かないストリーム応答を作る）。 */
  readonly chunks?: readonly string[];
  /** HTTP ステータス（既定 200）。 */
  readonly status?: number;
  /** Content-Type（既定 `application/json`）。 */
  readonly contentType?: string;
  /** `content-length` ヘッダの明示値（自己申告値のテスト用）。 */
  readonly contentLength?: string;
  /** リダイレクト後の最終 URL（既定はリクエスト URL）。 */
  readonly finalUrl?: string;
  /** `true` ならネットワークエラーとして reject する。 */
  readonly networkError?: boolean;
  /** `true` なら AbortError として reject する（タイムアウト相当）。 */
  readonly abortError?: boolean;
}

/** URL → 応答のスタブと、実際に要求された URL の記録。 */
export interface FetchStub {
  /** 実装へ渡す `fetchImpl`。 */
  readonly fetchImpl: typeof fetch;
  /** 要求された URL の履歴（フェッチ回数の検証に使う）。 */
  readonly requested: string[];
}

/** 文字列の配列を 1 チャンクずつ流す ReadableStream を作る。 */
function toStream(chunks: readonly string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index >= chunks.length) {
        controller.close();
        return;
      }
      controller.enqueue(encoder.encode(chunks[index] ?? ''));
      index += 1;
    },
  });
}

/** URL → 応答定義のマップから `fetchImpl` を組み立てる。 */
export function createFetchStub(routes: Readonly<Record<string, StubResponse>>): FetchStub {
  const requested: string[] = [];
  const fetchImpl = (async (input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input.toString();
    requested.push(url);
    const route = routes[url];
    if (route === undefined || route.networkError === true) {
      throw new TypeError('fetch failed');
    }
    if (route.abortError === true) {
      throw new DOMException('The operation was aborted.', 'AbortError');
    }
    const headers = new Headers({ 'Content-Type': route.contentType ?? 'application/json' });
    if (route.contentLength !== undefined) {
      headers.set('Content-Length', route.contentLength);
    }
    const payload =
      route.chunks !== undefined
        ? toStream(route.chunks)
        : (route.body ?? JSON.stringify(route.json ?? {}));
    const response = new Response(payload, { status: route.status ?? 200, headers });
    // Response.url は読み取り専用のため、リダイレクト後 URL の検証用に上書きする。
    Object.defineProperty(response, 'url', { value: route.finalUrl ?? url });
    return response;
  }) as unknown as typeof fetch;
  return { fetchImpl, requested };
}

/** 通常のスキーマ URL。 */
export const SCHEMA_URL = 'https://issuer.example.com/schemas/person.json';
/** 明示 `schema` 引数で上書きするときの URL。 */
export const OVERRIDE_SCHEMA_URL = 'https://issuer.example.com/schemas/person-strict.json';

/**
 * 秘密漏えい検知用の識別トークン。
 *
 * URL / クレーム値にこのトークンを埋め、例外メッセージ・`context`・違反メッセージの
 * いずれにも現れないことを検証する。
 */
export const URL_TOKEN = 'zzurlsecrettokenzz';
/** クレーム値側の識別トークン。 */
export const CLAIM_TOKEN = 'zzclaimsecrettokenzz';

/** `name`（必須）と `nickname`（任意）を持つスキーマ。 */
export const PERSON_SCHEMA = {
  type: 'object',
  required: ['name'],
  properties: {
    name: { type: 'string', minLength: 1 },
    nickname: { type: 'string', maxLength: 8 },
  },
};

/** テスト用 VC を組み立てる。 */
export function buildVc(
  credentialSubject: Readonly<Record<string, unknown>>,
  credentialSchema?: VerifiableCredential['credentialSchema'],
): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    issuanceDate: '2026-08-27T00:00:00Z',
    credentialSubject,
    ...(credentialSchema === undefined ? {} : { credentialSchema }),
  };
}
