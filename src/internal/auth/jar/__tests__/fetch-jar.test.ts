/**
 * `fetchJAR` の単体テスト。
 *
 * `request_uri` は deep link / QR 由来 = 攻撃者が値を選べる URL のため、取得の入口検査
 * （HTTPS 限定・リダイレクト後の最終 URL・タイムアウト・非 2xx）が実際に効くことを固定する。
 * 取得済み JWT の解析規則は `request.test.ts` が、署名検証の規則は `jar-signature.test.ts` が
 * 固定しているため、ここでは「取得結果が署名検証と `parseJarRequest` の正規化を通っていること」
 * を確認する。
 *
 * 現在、`fetchJAR` は Trust Anchor を必須で受け取る（署名検証を省ける呼び出しが
 * 型として存在しない）。本ファイルの正常系はすべて実際に署名した JAR を使う。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { MAX_DOCUMENT_BYTES } from '../../../http/body-limit.js';
import { fetchJAR } from '../fetch-jar.js';
import { CLIENT_ID, jarClaims, makeJarSigner, REQUEST_URI, signJar } from './jar-fixtures.js';

/** 署名鍵と Trust Anchor は 1 組で足りる（鍵生成は重いのでモジュールスコープで共有する）。 */
const VERIFIER = makeJarSigner();
const TRUST = { trustAnchors: VERIFIER.anchors } as const;
/** 正常系で使う署名済み JAR。 */
const SIGNED_JAR = signJar(VERIFIER);

/** `Response` を返す fetch スタブ。呼ばれた URL / init を記録する。 */
function stubFetch(
  response: Response | (() => Response | Promise<Response>),
  calls?: { url: string; init: Parameters<FetchLike>[1] }[],
): FetchLike {
  return async (url, init) => {
    calls?.push({ url, init });
    return typeof response === 'function' ? await response() : response;
  };
}

function jarResponse(jwt: string, init?: ResponseInit): Response {
  return new Response(jwt, {
    status: 200,
    headers: { 'Content-Type': 'application/oauth-authz-req+jwt' },
    ...init,
  });
}

async function expectCode(promise: Promise<unknown>, reason: string): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    const error = err as VericertsError;
    expect(error.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(error.context).toMatchObject({ reason });
  }
}

describe('fetchJAR: 取得と正規化', () => {
  it('取得した JAR JWT が PresentationRequest へ正規化される', async () => {
    const calls: { url: string; init: Parameters<FetchLike>[1] }[] = [];
    const request = await fetchJAR(REQUEST_URI, {
      ...TRUST,
      fetchImpl: stubFetch(jarResponse(SIGNED_JAR), calls),
    });

    expect(request.clientId).toBe(CLIENT_ID);
    expect(request.nonce).toBe('n-0S6_WzA2Mj-0123456789');
    expect(request.responseUri).toBe(`${CLIENT_ID}/callback`);
    // GET で取りに行き、JAR の媒体型を Accept で要求する（RFC 9101 §5.2）。
    expect(calls[0]?.url).toBe(REQUEST_URI);
    expect(calls[0]?.init.method).toBe('GET');
    expect(calls[0]?.init.headers.Accept).toBe('application/oauth-authz-req+jwt');
  });

  it('前後の空白は取り除いてから解析する', async () => {
    const request = await fetchJAR(REQUEST_URI, {
      ...TRUST,
      fetchImpl: stubFetch(jarResponse(`\n${SIGNED_JAR}\n`)),
    });
    expect(request.state).toBe('af0ifjsldkj');
  });

  it('応答の Content-Type は検査しない（中身が JWS なら受け入れる）', async () => {
    // 稼働中の Verifier は application/jwt や text/plain を返すものがあり、媒体型で落とすと
    // 正当な要求を Wallet 側で拒否してしまう（検査は中身に置く）。
    const request = await fetchJAR(REQUEST_URI, {
      ...TRUST,
      fetchImpl: stubFetch(
        new Response(SIGNED_JAR, { status: 200, headers: { 'Content-Type': 'text/plain' } }),
      ),
    });
    expect(request.clientId).toBe(CLIENT_ID);
  });

  it('取得した JWT にも response_uri のオリジン一致検査が効く', async () => {
    // ドメインの一致も署名検証時に確認するため、ここで拒否される。
    const crossOrigin = signJar(VERIFIER, {
      claims: jarClaims({ response_uri: 'https://attacker.example/callback' }),
    });
    await expectCode(
      fetchJAR(REQUEST_URI, { ...TRUST, fetchImpl: stubFetch(jarResponse(crossOrigin)) }),
      'jar_response_uri_domain_mismatch',
    );
  });
});

describe('fetchJAR: 入口検査', () => {
  it('非 HTTPS の request_uri は fetch せずに 8030', async () => {
    let called = false;
    const fetchImpl: FetchLike = async () => {
      called = true;
      return jarResponse(SIGNED_JAR);
    };
    await expectCode(
      fetchJAR('http://verifier.example.com/request/123', { ...TRUST, fetchImpl }),
      'non_https_request_uri',
    );
    // 平文 HTTP へは 1 バイトも出さない。
    expect(called).toBe(false);
  });

  it('URL として不正な request_uri も fetch せずに 8030', async () => {
    await expectCode(
      fetchJAR('not a url', { ...TRUST, fetchImpl: stubFetch(jarResponse('x')) }),
      'non_https_request_uri',
    );
  });

  it('空文字・空白のみの request_uri は 8030', async () => {
    await expectCode(
      fetchJAR('   ', { ...TRUST, fetchImpl: stubFetch(jarResponse('x')) }),
      'missing_request_uri',
    );
  });

  it('通信失敗は 8030（fetch_failed）へ正規化される', async () => {
    const fetchImpl: FetchLike = async () => {
      throw new Error('network down');
    };
    await expectCode(fetchJAR(REQUEST_URI, { ...TRUST, fetchImpl }), 'fetch_failed');
  });

  it('非 2xx は 8030（http_error）', async () => {
    await expectCode(
      fetchJAR(REQUEST_URI, {
        ...TRUST,
        fetchImpl: stubFetch(new Response('nope', { status: 404 })),
      }),
      'http_error',
    );
  });

  it('HTTPS から降格したリダイレクト先は 8030（insecure_redirect）', async () => {
    const downgraded = jarResponse(SIGNED_JAR);
    Object.defineProperty(downgraded, 'url', { value: 'http://verifier.example.com/request/123' });
    await expectCode(
      fetchJAR(REQUEST_URI, { ...TRUST, fetchImpl: stubFetch(downgraded) }),
      'insecure_redirect',
    );
  });

  it('空本文は 8030（empty_request_object）', async () => {
    await expectCode(
      fetchJAR(REQUEST_URI, { ...TRUST, fetchImpl: stubFetch(jarResponse('   ')) }),
      'empty_request_object',
    );
  });

  it('本文が JWS でなければ 8030', async () => {
    const promise = fetchJAR(REQUEST_URI, {
      ...TRUST,
      fetchImpl: stubFetch(jarResponse('not-a-jws')),
    });
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
    });
  });

  it('例外に request_uri・本文・cause を載せない', async () => {
    const secretUri = `${REQUEST_URI}?session=super-secret`;
    try {
      await fetchJAR(secretUri, {
        ...TRUST,
        fetchImpl: stubFetch(new Response('body-with-secret', { status: 500 })),
      });
      throw new Error('should have thrown');
    } catch (err) {
      const error = err as VericertsError;
      const dump = JSON.stringify({ message: error.message, context: error.context });
      expect(dump).not.toContain('super-secret');
      expect(dump).not.toContain('body-with-secret');
      expect(error.cause).toBeUndefined();
    }
  });
});

describe('fetchJAR: 本文バイト上限', () => {
  // `request_uri` は QR 由来で攻撃者が値を選べるうえ、署名検証は本文読み出しの **後** なので、
  // 上限が無いと未検証の Verifier 応答だけでウォレットのメモリを枯渇させられる。
  it('MAX_DOCUMENT_BYTES を超える本文は 8030（oversized_body）で拒否する', async () => {
    await expectCode(
      fetchJAR(REQUEST_URI, {
        ...TRUST,
        fetchImpl: stubFetch(jarResponse('a'.repeat(MAX_DOCUMENT_BYTES + 1))),
      }),
      'oversized_body',
    );
  });

  it('content-length が上限超過を宣言する応答は本文を読む前に拒否する', async () => {
    await expectCode(
      fetchJAR(REQUEST_URI, {
        ...TRUST,
        fetchImpl: stubFetch(
          new Response(SIGNED_JAR, {
            status: 200,
            headers: { 'content-length': String(MAX_DOCUMENT_BYTES + 1) },
          }),
        ),
      }),
      'oversized_body',
    );
  });
});

describe('fetchJAR: fetchImpl DI の解決（internal/fetch-di.ts）', () => {
  it('prototype メソッドとして実装された fetchImpl も採用される', async () => {
    class Deps {
      calls = 0;
      async fetchImpl(_url: string, _init: Parameters<FetchLike>[1]): Promise<Response> {
        // `this` 参照が壊れていればここで例外になる。
        this.calls += 1;
        return jarResponse(SIGNED_JAR);
      }
    }
    const deps = new Deps();
    const request = await fetchJAR(REQUEST_URI, {
      ...TRUST,
      fetchImpl: deps.fetchImpl.bind(deps) as FetchLike,
    });
    expect(request.clientId).toBe(CLIENT_ID);
    expect(deps.calls).toBe(1);
  });

  it('Object.prototype.fetchImpl の汚染値を掴まずグローバル fetch を使う', async () => {
    // 入口検査を通る **HTTPS** の request_uri を使い、実際に `resolveInjectedFetch` まで到達させる
    // （非 HTTPS では HTTPS ガードで throw して DI 解決に届かず、実装を鎖読みへ戻しても
    // 検知できない空回りのテストになる）。
    let pollutedFetchUsed = false;
    let globalFetchUsed = false;
    const attackerJar = signJar(VERIFIER, { claims: jarClaims({ nonce: 'attacker-nonce' }) });
    Object.defineProperty(Object.prototype, 'fetchImpl', {
      configurable: true,
      get() {
        pollutedFetchUsed = true;
        return async () => jarResponse(attackerJar);
      },
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      globalFetchUsed = true;
      return jarResponse(SIGNED_JAR);
    }) as unknown as typeof globalThis.fetch;
    try {
      // fetchImpl 未指定 = グローバル fetch。汚染値へ委譲されると Verifier の Request Object を
      // 攻撃者が差し替えられる（nonce / response_uri / dcql_query ごと）。渡すオプションは
      // `Object.prototype` を継承したリテラルなので、鎖読みに戻せば必ず汚染値を掴む。
      const request = await fetchJAR(REQUEST_URI, { trustAnchors: VERIFIER.anchors });
      expect(request.nonce).toBe('n-0S6_WzA2Mj-0123456789');
      expect(globalFetchUsed).toBe(true);
      expect(pollutedFetchUsed).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
      // prototype 汚染テストの後片付け。
      delete (Object.prototype as unknown as Record<string, unknown>).fetchImpl;
    }
  });
});
