/**
 * `createStatusListResolver` の Token Status List キャッシュ層の回帰テスト。
 *
 * Status List キャッシュの各経路で `cache` ラベルを確認する。
 *
 * 検証内容:
 * - TTL 内は再取得せず `hot`、TTL 切れは `warm` で再取得、初回は `cold`。
 * - 配信側の過大な `max-age` は上限 60 秒でキャップし、短い `max-age` はそのまま尊重する。
 * - `no-store` は格納しない。Token 自身の `exp` は TTL よりさらに手前で切り詰める。
 * - SDK 利用者の TTL 上限は厳しくする方向のみ許可し、緩める指定は 3002 で拒否する。
 * - negative cache は 30 秒固定で、その間はネットワークに出ない。
 * - `fetchToken` が素の文字列を返す従来どおりの配線を壊さない。
 */

import { describe, expect, it } from 'bun:test';
import type { CacheState } from '../../../cache/index.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { createStatusListCache, type StatusListTokenResponse } from '../../status-list-cache.js';
import { createStatusListResolver } from '../../status-list-resolver.js';
import { StatusListManager } from '../../token-status-list.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const PUB = getP256PublicKey(ISSUER_KEY, false);
const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const ISSUER_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: b64u(PUB.subarray(1, 33)),
  y: b64u(PUB.subarray(33, 65)),
};

const URI = 'https://issuer.example/status/1';
const NOW = 1_700_000_000;
const MANAGER = new StatusListManager({
  uri: URI,
  issuer: 'did:web:issuer.example',
  size: 100,
  bits: 1,
});
const REF = MANAGER.reference(MANAGER.allocate());
const TOKEN = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW });
/** `exp` が TTL より手前（NOW + 10）の Token。 */
const SHORT_EXP_TOKEN = await MANAGER.issueToken(SIGNER, {
  iatSeconds: NOW,
  expSeconds: NOW + 10,
});
/** 十分に先の `exp` を持つ再署名済み Token（配信側が新しい Token に差し替えた状況を表す）。 */
const RESIGNED_TOKEN = await MANAGER.issueToken(SIGNER, {
  iatSeconds: NOW,
  expSeconds: NOW + 3600,
});

/** キャッシュを配線した解決器と、時計・呼び出し回数・観測イベントを組み立てる。 */
function setup(
  opts: {
    cacheControl?: string;
    maxTtlSeconds?: number;
    token?: string;
    /** 取得のたびに順に配信する Token 列（末尾は以降ずっと配信される）。 */
    tokens?: readonly string[];
  } = {},
): {
  resolve: () => Promise<number>;
  states: CacheState[];
  calls: () => number;
  at: (offsetSeconds: number) => void;
} {
  let now = NOW;
  let calls = 0;
  const states: CacheState[] = [];
  const sequence = opts.tokens ?? [opts.token ?? TOKEN];
  const resolver = createStatusListResolver({
    fetchToken: async (): Promise<string | StatusListTokenResponse> => {
      // 取得ごとに次の Token を配信し、列を使い切ったら最後の Token を配信し続ける。
      const token = sequence[Math.min(calls, sequence.length - 1)] as string;
      calls += 1;
      return opts.cacheControl === undefined ? token : { token, cacheControl: opts.cacheControl };
    },
    issuerPublicKey: ISSUER_JWK,
    purpose: 'revocation',
    statusCache: createStatusListCache(() => now),
    onCacheEvent: (event) => states.push(event.state),
    nowSeconds: () => now,
    ...(opts.maxTtlSeconds === undefined ? {} : { maxTtlSeconds: opts.maxTtlSeconds }),
  });
  return {
    resolve: async () => (await resolver.resolve(REF)).value,
    states,
    calls: () => calls,
    at: (offsetSeconds) => {
      now = NOW + offsetSeconds;
    },
  };
}

describe('Token Status List キャッシュ層', () => {
  it('TTL 内の 2 回目は再取得せず hot として観測される', async () => {
    const s = setup();
    expect(await s.resolve()).toBe(0);
    s.at(59);
    expect(await s.resolve()).toBe(0);
    expect(s.calls()).toBe(1);
    expect(s.states).toEqual(['cold', 'hot']);
  });

  it('TTL 切れは warm として再取得する', async () => {
    const s = setup();
    await s.resolve();
    s.at(61);
    await s.resolve();
    expect(s.calls()).toBe(2);
    expect(s.states).toEqual(['cold', 'warm']);
  });

  it('配信側の過大な max-age は上限 60 秒でキャップされる', async () => {
    const s = setup({ cacheControl: 'max-age=99999' });
    await s.resolve();
    s.at(59);
    await s.resolve();
    expect(s.calls()).toBe(1);
    s.at(61);
    await s.resolve();
    expect(s.calls()).toBe(2);
  });

  it('上限より短い max-age はそのまま尊重される', async () => {
    const s = setup({ cacheControl: 'max-age=30' });
    await s.resolve();
    s.at(29);
    await s.resolve();
    expect(s.calls()).toBe(1);
    s.at(31);
    await s.resolve();
    expect(s.calls()).toBe(2);
  });

  it('no-store は格納せず毎回再取得する', async () => {
    const s = setup({ cacheControl: 'no-store' });
    await s.resolve();
    s.at(1);
    await s.resolve();
    s.at(2);
    await s.resolve();
    expect(s.calls()).toBe(3);
    expect(s.states).toEqual(['cold', 'cold', 'cold']);
  });

  it('Token の exp が TTL より手前なら exp で失効する', async () => {
    // 配信側は exp 到来後に再署名した Token に差し替える（実運用と同じ挙動）。
    const s = setup({ tokens: [SHORT_EXP_TOKEN, RESIGNED_TOKEN] });
    await s.resolve();
    s.at(9);
    await s.resolve();
    expect(s.calls()).toBe(1);
    // exp（NOW + 10）到来。TTL 上限 60 秒は残っているが exp で切り詰められ再取得になる。
    s.at(10);
    expect(await s.resolve()).toBe(0);
    expect(s.calls()).toBe(2);
  });

  it('TTL 上限を緩める設定は 3002 で拒否し、厳しくする設定は受理する', async () => {
    try {
      setup({ maxTtlSeconds: 61 });
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
    }

    const s = setup({ maxTtlSeconds: 30 });
    await s.resolve();
    s.at(29);
    await s.resolve();
    expect(s.calls()).toBe(1);
    s.at(31);
    await s.resolve();
    expect(s.calls()).toBe(2);
  });
});

/** 取得が失敗する解決器と、共有キャッシュ・時計・呼び出し回数を組み立てる。 */
function negativeSetup(): {
  resolve: () => Promise<number>;
  cache: ReturnType<typeof createStatusListCache>;
  calls: () => number;
  at: (offsetSeconds: number) => void;
  recover: () => void;
} {
  let now = NOW;
  let calls = 0;
  let broken = true;
  const cache = createStatusListCache(() => now);
  const resolver = createStatusListResolver({
    fetchToken: async () => {
      calls += 1;
      if (broken) {
        throw new Error('network unreachable');
      }
      return TOKEN;
    },
    issuerPublicKey: ISSUER_JWK,
    purpose: 'revocation',
    statusCache: cache,
    nowSeconds: () => now,
  });
  return {
    resolve: async () => (await resolver.resolve(REF)).value,
    cache,
    calls: () => calls,
    at: (offsetSeconds) => {
      now = NOW + offsetSeconds;
    },
    recover: () => {
      broken = false;
    },
  };
}

describe('Token Status List negative cache', () => {
  it('取得失敗は 30 秒記憶され、その間はネットワークに出ない', async () => {
    const s = negativeSetup();
    await expect(s.resolve()).rejects.toThrow('network unreachable');
    expect(s.calls()).toBe(1);

    s.at(29);
    await expect(s.resolve()).rejects.toThrow('network unreachable');
    expect(s.calls()).toBe(1);

    s.at(30);
    await expect(s.resolve()).rejects.toThrow('network unreachable');
    expect(s.calls()).toBe(2);
  });

  it('取得に成功すると記憶済みの失敗は残らない', async () => {
    const s = negativeSetup();
    await expect(s.resolve()).rejects.toThrow('network unreachable');
    expect(s.cache.getNegative(URI, NOW + 1)).toBeDefined();

    s.at(30);
    s.recover();
    expect(await s.resolve()).toBe(0);
    // 成功時に破棄されるため、直後（記憶が生きているはずの時刻）にも残っていない。
    expect(s.cache.getNegative(URI, NOW + 31)).toBeUndefined();

    s.at(31);
    expect(await s.resolve()).toBe(0);
    expect(s.calls()).toBe(2);
  });

  it('記憶した失敗にもエラーメッセージにも URI / Token は含まれない', async () => {
    const s = negativeSetup();
    await expect(s.resolve()).rejects.toThrow('network unreachable');
    const remembered = s.cache.getNegative(URI, NOW);
    expect(String((remembered as Error).message)).not.toContain(URI);
    expect(String((remembered as Error).message)).not.toContain(TOKEN);
  });
});

describe('Token Status List キャッシュ層の後方互換', () => {
  it('statusCache 未指定で素の文字列を返す fetchToken は従来どおり毎回取得する', async () => {
    let calls = 0;
    const resolver = createStatusListResolver({
      fetchToken: async () => {
        calls += 1;
        return TOKEN;
      },
      issuerPublicKey: ISSUER_JWK,
      purpose: 'revocation',
      nowSeconds: () => NOW,
    });

    expect(await resolver.resolve(REF)).toEqual({ valid: true, purpose: 'revocation', value: 0 });
    expect(await resolver.resolve(REF)).toEqual({ valid: true, purpose: 'revocation', value: 0 });
    expect(calls).toBe(2);
  });
});
