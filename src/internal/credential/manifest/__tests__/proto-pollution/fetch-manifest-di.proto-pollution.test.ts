/**
 * `fetchCredentialManifest` の `deps.fetchImpl`（関数値 DI）に関する回帰テスト
 *
 * `submitCredentialApplication`（`application.ts`）と同じ `resolveInjectedFetch` 共有ヘルパーを使う
 * が、呼び出し箇所（DI の解決・レシーバの束ね直し）はこちらの関数にも個別に配線されているため、
 * このファイル自身の呼び出しがヘルパーを正しく使っているかは別途固定する必要がある。
 *
 * 1. `Object.prototype` に仕込んだ関数は「未指定」として弾かれ、グローバル `fetch` に
 *    フォールバックすること（own 限定にすると逆に prototype メソッド DI が弾かれるため、
 *    両方向を固定する）。
 * 2. `class Deps { fetchImpl() {…} }` のようなプロトタイプメソッド DI は `this` 付きで
 *    呼ばれ、正しく動作すること（レシーバ束ね直しの固定）。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { fetchCredentialManifest } from '../../parse.js';

const SUPPORTED_SPEC_VERSION = 'https://identity.foundation/credential-manifest/spec/v1.0.0/';
const MANIFEST_URL = 'https://issuer.example/manifest.json';

const MANIFEST_BODY = JSON.stringify({
  id: 'manifest-1',
  spec_version: SUPPORTED_SPEC_VERSION,
  issuer: { id: 'https://issuer.example' },
  output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
});

describe('fetchCredentialManifest: fetchImpl の Object.prototype 汚染耐性', () => {
  it('fetchImpl 未指定の呼び出しは Object.prototype の汚染関数へ委譲せずグローバル fetch にフォールバックする', async () => {
    const original = globalThis.fetch;
    const seen: unknown[] = [];
    globalThis.fetch = function stubFetch(this: unknown): Promise<Response> {
      seen.push(this);
      return Promise.resolve(new Response(MANIFEST_BODY, { status: 200 }));
    } as unknown as typeof fetch;
    try {
      const attackerFetch = async () => {
        throw new Error('attacker fetch must not be called');
      };
      await withPollutedPrototypeAsync({ fetchImpl: attackerFetch }, async () => {
        const manifest = await fetchCredentialManifest(MANIFEST_URL);
        expect(manifest.id).toBe('manifest-1');
      });
    } finally {
      globalThis.fetch = original;
    }
    // グローバル fetch にはレシーバを束ねない（ネイティブ fetch なら Illegal invocation になる）。
    expect(seen).toEqual([undefined]);
  });

  it('プロトタイプメソッドとして注入した fetchImpl は this 付きで呼ばれる（レシーバ束ね直し）', async () => {
    class DepsWithFetch {
      readonly requestedUrls: string[] = [];
      async fetchImpl(url: string): Promise<Response> {
        this.requestedUrls.push(url);
        return new Response(MANIFEST_BODY, { status: 200 });
      }
    }
    const deps = new DepsWithFetch();
    const manifest = await fetchCredentialManifest(MANIFEST_URL, deps);

    expect(manifest.id).toBe('manifest-1');
    // `this` 経由でインスタンス状態を積めた ＝ レシーバが `deps` に束ね直されている。
    expect(deps.requestedUrls).toEqual([MANIFEST_URL]);
  });
});
