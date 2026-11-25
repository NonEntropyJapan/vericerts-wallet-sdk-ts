/**
 * `new MethodIpid(config)` の Gateway / API URL は自身のプロパティだけを読む。
 *
 * `config?.gatewayUrl ?? 既定` が鎖読みだと、`Object.prototype.gatewayUrl` の汚染だけで、省略した
 * 正当な呼び出しの解決先 Gateway（偽造 DID Document の出所）と、`key/import` で IPNS 秘密鍵を送る
 * API の宛先が攻撃者の値になる。
 */

import { afterEach, describe, expect, test } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { IpidGatewayConfig } from '../../gateway.js';
import { MethodIpid } from '../../method-ipid.js';
import { rawCidOf } from '../cid-fixture.js';

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

const BODY = JSON.stringify({ '@context': ['https://www.w3.org/ns/did/v1'] });
const CID = rawCidOf(BODY);

describe('MethodIpid のコンストラクタ設定', () => {
  test.each<[string, Partial<IpidGatewayConfig> | undefined]>([
    ['config 省略', undefined],
    ['空の config', {}],
    ['gatewayUrl だけ own', { gatewayUrl: 'https://own.example' }],
  ])('%s: 汚染された gatewayUrl / apiUrl は採用されない', async (_name, config) => {
    const urls: string[] = [];
    globalThis.fetch = (async (input: string | URL | Request) => {
      urls.push(String(input));
      return new Response(BODY, { status: 200, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;
    await withPollutedPrototypeAsync(
      { gatewayUrl: 'https://attacker.example', apiUrl: 'https://attacker-api.example' },
      () => new MethodIpid(config).resolve(`did:ipid:${CID}`),
    );
    expect(urls).toHaveLength(1);
    const expectedHost =
      config?.gatewayUrl === undefined ? 'https://ipfs.io/' : 'https://own.example/';
    expect(urls[0]?.startsWith(expectedHost)).toBe(true);
  });
});
