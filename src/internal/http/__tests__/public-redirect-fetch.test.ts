/**
 * `fetchFollowingPublicRedirects` の回帰テスト。
 *
 * ブラウザの拡張 service worker では `redirect: 'manual'` の 3xx が常に `opaqueredirect`
 * （`Location` 不可視）になる。これを `redirect: 'follow'` で取り直すと、中間ホップの
 * `isPublicHttpsUrl` 検査が一度も効かないまま内部 https ホストへ GET が送出される。
 *
 * 取得先を攻撃者が選べる全 GET 経路の SSRF 防御の単一点なので、ホップ上限・`Location` 欠落・
 * 相対 `Location` の解決・追従対象ステータス・`init` の引き継ぎと最終 URLも固定する。
 */

import { describe, expect, it } from 'bun:test';
import {
  fetchFollowingPublicRedirects,
  fetchFollowingPublicRedirectsWithFinalUrl,
  MAX_PUBLIC_REDIRECTS,
  PublicRedirectRejection,
} from '../public-redirect-fetch.js';

function opaqueRedirect(): Response {
  const response = new Response(null, { status: 200 });
  Object.defineProperty(response, 'type', { value: 'opaqueredirect' });
  return response;
}

describe('fetchFollowingPublicRedirects — opaqueredirect', () => {
  it('opaqueredirect は redirect:follow で再取得せず失敗する（fetch は 1 回だけ）', async () => {
    const calls: { url: string; redirect: RequestRedirect | undefined }[] = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      calls.push({ url, redirect: init?.redirect });
      return opaqueRedirect();
    }) as unknown as typeof fetch;

    await expect(
      fetchFollowingPublicRedirects(fetchFn, 'https://issuer.example/.well-known/did.json', {
        method: 'GET',
      }),
    ).rejects.toThrow('opaque_redirect');
    expect(calls).toEqual([
      { url: 'https://issuer.example/.well-known/did.json', redirect: 'manual' },
    ]);
  });

  it('公開 HTTPS 宛の 3xx は Location を検査して追従し、内部宛は fetch せず拒否する', async () => {
    const seen: string[] = [];
    const fetchFn = (async (url: string) => {
      seen.push(url);
      if (url === 'https://a.example/x') {
        return new Response(null, { status: 302, headers: { location: 'https://b.example/y' } });
      }
      if (url === 'https://b.example/y') return new Response('ok', { status: 200 });
      return new Response(null, { status: 302, headers: { location: 'https://10.0.0.5/' } });
    }) as unknown as typeof fetch;

    const ok = await fetchFollowingPublicRedirects(fetchFn, 'https://a.example/x', {});
    expect(await ok.text()).toBe('ok');

    const internal = (async (url: string) => {
      seen.push(url);
      return new Response(null, { status: 302, headers: { location: 'https://10.0.0.5/' } });
    }) as unknown as typeof fetch;
    seen.length = 0;
    await expect(fetchFollowingPublicRedirects(internal, 'https://c.example/', {})).rejects.toThrow(
      'non_public_url',
    );
    expect(seen).toEqual(['https://c.example/']);
  });
});

/** 呼び出しごとの `(url, init)` を記録しつつ、`respond` の応答を返す fetch。 */
function recordingFetch(respond: (url: string, call: number) => Response) {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  const fetchFn = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return respond(url, calls.length);
  }) as unknown as typeof fetch;
  return { fetchFn, calls };
}

const redirectTo = (location: string, status = 302): Response =>
  new Response(null, { status, headers: { location } });

describe('fetchFollowingPublicRedirects — ホップ上限', () => {
  it('MAX_PUBLIC_REDIRECTS 回の 3xx までは追従し、次の 3xx で too_many_redirects', async () => {
    // ちょうど上限回の 3xx のあとに 200 を返す: 追従して成功する（初回 + 上限回 = 上限 + 1 回の fetch）。
    const within = recordingFetch((_url, call) =>
      call <= MAX_PUBLIC_REDIRECTS ? redirectTo(`https://h${call}.example/`) : new Response('ok'),
    );
    const ok = await fetchFollowingPublicRedirects(within.fetchFn, 'https://a.example/', {});
    expect(await ok.text()).toBe('ok');
    expect(within.calls).toHaveLength(MAX_PUBLIC_REDIRECTS + 1);

    // 常に 3xx: 上限 + 1 回 fetch したところで打ち切る（無限ループにならない）。
    const forever = recordingFetch((_url, call) => redirectTo(`https://h${call}.example/`));
    await expect(
      fetchFollowingPublicRedirects(forever.fetchFn, 'https://a.example/', {}),
    ).rejects.toThrow('too_many_redirects');
    expect(forever.calls).toHaveLength(MAX_PUBLIC_REDIRECTS + 1);
  });
});

describe('fetchFollowingPublicRedirects — Location', () => {
  it('Location の無い 3xx は missing_location で失敗する', async () => {
    const { fetchFn, calls } = recordingFetch(() => new Response(null, { status: 302 }));
    await expect(fetchFollowingPublicRedirects(fetchFn, 'https://a.example/', {})).rejects.toThrow(
      'missing_location',
    );
    expect(calls).toHaveLength(1);
  });

  it('スキーム相対 Location（//10.0.0.5/x）は非公開ホストとして fetch せず拒否する', async () => {
    const { fetchFn, calls } = recordingFetch(() => redirectTo('//10.0.0.5/x'));
    await expect(fetchFollowingPublicRedirects(fetchFn, 'https://a.example/', {})).rejects.toThrow(
      'non_public_url',
    );
    expect(calls.map((c) => c.url)).toEqual(['https://a.example/']);
  });

  it('パス相対 Location は現在の URL 基準で解決して追従する', async () => {
    const { fetchFn, calls } = recordingFetch((url) =>
      url === 'https://a.example/dir/start' ? redirectTo('/moved/x?q=1') : new Response('ok'),
    );
    await fetchFollowingPublicRedirects(fetchFn, 'https://a.example/dir/start', {});
    expect(calls.map((c) => c.url)).toEqual([
      'https://a.example/dir/start',
      'https://a.example/moved/x?q=1',
    ]);
  });

  it('相対 Location は次ホップの公開 HTTPS 検査も受ける（http への降格は拒否）', async () => {
    const { fetchFn, calls } = recordingFetch(() => redirectTo('http://a.example/plain'));
    await expect(fetchFollowingPublicRedirects(fetchFn, 'https://a.example/', {})).rejects.toThrow(
      'non_public_url',
    );
    expect(calls).toHaveLength(1);
  });
});

describe('fetchFollowingPublicRedirects — 追従対象ステータス', () => {
  it.each([301, 302, 303, 307, 308])('%d は Location へ追従する', async (status) => {
    const { fetchFn, calls } = recordingFetch((url) =>
      url === 'https://a.example/' ? redirectTo('https://b.example/', status) : new Response('ok'),
    );
    const res = await fetchFollowingPublicRedirects(fetchFn, 'https://a.example/', {});
    expect(await res.text()).toBe('ok');
    expect(calls.map((c) => c.url)).toEqual(['https://a.example/', 'https://b.example/']);
  });

  it.each([300, 304])('%d は追従せずそのまま返す', async (status) => {
    const { fetchFn, calls } = recordingFetch(() => redirectTo('https://b.example/', status));
    const res = await fetchFollowingPublicRedirects(fetchFn, 'https://a.example/', {});
    expect(res.status).toBe(status);
    expect(calls).toHaveLength(1);
  });
});

describe('fetchFollowingPublicRedirects — init の引き継ぎ', () => {
  it('追従するホップごとに signal / headers を引き継ぎ、redirect は manual に上書きする', async () => {
    const controller = new AbortController();
    const headers = { Accept: 'application/json' };
    const { fetchFn, calls } = recordingFetch((_url, call) =>
      call < 3 ? redirectTo(`https://h${call}.example/`) : new Response('ok'),
    );
    // 呼び出し側が `redirect: 'follow'` を渡しても（型では除外されているが）上書きされる。
    const init = { method: 'GET', headers, signal: controller.signal, redirect: 'follow' };
    await fetchFollowingPublicRedirects(fetchFn, 'https://a.example/', init);
    expect(calls).toHaveLength(3);
    for (const { init: sent } of calls) {
      expect(sent?.redirect).toBe('manual');
      expect(sent?.method).toBe('GET');
      expect(sent?.headers).toBe(headers);
      expect(sent?.signal).toBe(controller.signal);
    }
  });
});

describe('fetchFollowingPublicRedirectsWithFinalUrl', () => {
  it('追従した最終ホップの URL を返す（Response.url が空でも）', async () => {
    const { fetchFn } = recordingFetch((url) =>
      url === 'https://a.example/x'
        ? redirectTo('/y')
        : url === 'https://a.example/y'
          ? redirectTo('https://b.example/z')
          : new Response('ok'),
    );
    const { response, finalUrl } = await fetchFollowingPublicRedirectsWithFinalUrl(
      fetchFn,
      'https://a.example/x',
      {},
    );
    expect(response.url).toBe('');
    expect(finalUrl).toBe('https://b.example/z');
  });

  it('リダイレクトが無ければ最初の URL をそのまま返す', async () => {
    const { fetchFn } = recordingFetch(() => new Response('ok'));
    const { finalUrl } = await fetchFollowingPublicRedirectsWithFinalUrl(
      fetchFn,
      'https://a.example/x',
      {},
    );
    expect(finalUrl).toBe('https://a.example/x');
  });
});

describe('fetchFollowingPublicRedirects — 検査拒否とネットワークエラーの区別', () => {
  const rejectsWith = async (fetchFn: typeof fetch): Promise<unknown> => {
    try {
      await fetchFollowingPublicRedirects(fetchFn, 'https://a.example/x', {});
    } catch (error) {
      return error;
    }
    return undefined;
  };

  it('opaqueredirect / 非公開ホップ / Location 欠落・不正 / ホップ超過は PublicRedirectRejection', async () => {
    const redirectTo = (location?: string) =>
      (async () =>
        new Response(null, {
          status: 302,
          headers: location === undefined ? {} : { location },
        })) as unknown as typeof fetch;
    const opaque = (async () => opaqueRedirect()) as unknown as typeof fetch;
    for (const fetchFn of [
      opaque,
      redirectTo('https://10.0.0.5/'),
      redirectTo(undefined),
      redirectTo('http://[bad'),
      redirectTo('https://a.example/loop'),
    ]) {
      expect(await rejectsWith(fetchFn)).toBeInstanceOf(PublicRedirectRejection);
    }
  });

  it('fetchFn 自身が投げたネットワークエラーは PublicRedirectRejection ではない', async () => {
    const network = (async () => {
      throw new TypeError('network down');
    }) as unknown as typeof fetch;
    const error = await rejectsWith(network);
    expect(error).toBeInstanceOf(TypeError);
    expect(error).not.toBeInstanceOf(PublicRedirectRejection);
  });
});
