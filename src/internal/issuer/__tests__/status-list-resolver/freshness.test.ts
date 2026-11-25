/**
 * 新規取得した Status List Token の鮮度判定（`iat` / `ttl` / rollback ガード）の回帰テスト。
 *
 * 検証内容:
 * - 失効**前**に発行された正規署名の古い Token（`exp` 無し）を配信経路が再生しても、年齢が上限以上なら
 *   `VC_EXPIRED`（3024）で拒否する（以前は失効済み VC が `valid: true` になった）。
 * - 上限は `ttl` クレームがあればそれ、無ければ `maxTokenAgeSeconds`（既定 24 時間）。境界は両側で固定。
 * - 未来の `iat`（`now + skew` 超）は `CLOCK_SKEW_EXCEEDED`（4014）。
 * - 同じ URI で既に受理した `iat` より古い Token は、年齢内でも rollback として拒否する。
 * - `iat` 不在・不正、`ttl` 不正は `VC_SCHEMA_INVALID`（3002）。
 * - キャッシュは Token の寿命（`iat + 上限`）を超えて古い Token を返さない。
 * - FO-2 の stale 再利用は対象外（古い Token でもビット値を返す）。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../../__tests__/heavy-input-timeout.js';
import { signCompactJws } from '../../../credential/vc/compact-jws.js';
import { decodeCompactJws } from '../../../credential/vc/jws.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import {
  DEFAULT_STATUS_TOKEN_MAX_AGE_SECONDS,
  MAX_TRACKED_STATUS_LIST_URIS,
} from '../../freshness/status-list-freshness.js';
import { createStatusListCache } from '../../status-list-cache.js';
import { createStatusListResolver } from '../../status-list-resolver.js';
import { StatusListManager } from '../../token-status-list.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

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
const DAY = DEFAULT_STATUS_TOKEN_MAX_AGE_SECONDS;

const MANAGER = new StatusListManager({
  uri: URI,
  issuer: 'did:web:issuer.example',
  size: 100,
  bits: 1,
});
const IDX = MANAGER.allocate();
const REF = MANAGER.reference(IDX);
/** 失効前（value 0）に 2 年前の iat・exp 無しで発行した Token。 */
const OLD_VALID = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW - 2 * 365 * DAY });
MANAGER.revoke(IDX);
/** 失効後（value 1）に現在の iat で発行した Token。 */
const CURRENT_REVOKED = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW });

/** 署名済み Token の payload を差し替えて同じ鍵で再署名する（`undefined` 値はクレーム削除）。 */
async function reissue(token: string, patch: Record<string, unknown>): Promise<string> {
  const genuine = decodeCompactJws(token);
  const payload: Record<string, unknown> = { ...genuine.payload, ...patch };
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined) {
      delete payload[key];
    }
  }
  return signCompactJws(genuine.header, payload, SIGNER);
}

async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
}

/** 呼び出しごとに `queue` の先頭 Token を返す解決器（尽きたら最後を返し続ける）。 */
function resolverOf(
  queue: string[],
  extra: { maxTokenAgeSeconds?: number; now?: () => number } = {},
) {
  let i = 0;
  const now = extra.now ?? (() => NOW);
  return createStatusListResolver({
    fetchToken: async () => queue[Math.min(i++, queue.length - 1)] as string,
    issuerPublicKey: ISSUER_JWK,
    purpose: 'revocation',
    nowSeconds: now,
    ...(extra.maxTokenAgeSeconds === undefined
      ? {}
      : { maxTokenAgeSeconds: extra.maxTokenAgeSeconds }),
    onPolicyEvent: () => {},
  });
}

describe('Status List Token の鮮度（iat / ttl）', () => {
  it('失効前の古い Token（exp 無し）の再生は VC_EXPIRED で拒否し、valid にしない', async () => {
    await expectRejectCode(resolverOf([OLD_VALID]).resolve(REF), ErrorCodes.VC_EXPIRED);
    // 対照: 現在の Token は失効を正しく返す。
    expect(await resolverOf([CURRENT_REVOKED]).resolve(REF)).toEqual({
      valid: false,
      purpose: 'revocation',
      value: 1,
    });
  });

  it('既定上限（24 時間）: 年齢が上限未満なら受理し、ちょうどなら拒否する', async () => {
    const token = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW - DAY + 1 });
    expect((await resolverOf([token]).resolve(REF)).valid).toBe(false);
    const boundary = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW - DAY });
    await expectRejectCode(resolverOf([boundary]).resolve(REF), ErrorCodes.VC_EXPIRED);
  });

  it('maxTokenAgeSeconds で上限を変えられ、ttl クレームがあればそちらが優先される', async () => {
    const token = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW - 100 });
    await expectRejectCode(
      resolverOf([token], { maxTokenAgeSeconds: 100 }).resolve(REF),
      ErrorCodes.VC_EXPIRED,
    );
    const ttlToken = await reissue(token, { ttl: 101 });
    // ttl=101 > 年齢 100 なので maxTokenAgeSeconds=100 を無視して受理する。
    expect((await resolverOf([ttlToken], { maxTokenAgeSeconds: 100 }).resolve(REF)).valid).toBe(
      false,
    );
    const shortTtl = await reissue(token, { ttl: 100 });
    await expectRejectCode(
      resolverOf([shortTtl], { maxTokenAgeSeconds: DAY }).resolve(REF),
      ErrorCodes.VC_EXPIRED,
    );
  });

  it('未来の iat は skew（120 秒）を超えると CLOCK_SKEW_EXCEEDED、以内なら受理する', async () => {
    const within = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW + 120 });
    expect((await resolverOf([within]).resolve(REF)).valid).toBe(false);
    const beyond = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW + 121 });
    await expectRejectCode(resolverOf([beyond]).resolve(REF), ErrorCodes.CLOCK_SKEW_EXCEEDED);
  });

  it('既に受理した iat より古い Token は年齢内でも rollback として拒否する', async () => {
    const newer = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW });
    const older = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW - 60 });
    const resolver = resolverOf([newer, older]);
    expect((await resolver.resolve(REF)).valid).toBe(false);
    await expectRejectCode(resolver.resolve(REF), ErrorCodes.VC_EXPIRED);
  });

  it('rollback ガードは URI ごと: 別 URI の古い iat は影響しない', async () => {
    const other = new StatusListManager({
      uri: 'https://issuer.example/status/2',
      issuer: 'did:web:issuer.example',
      size: 8,
      bits: 1,
    });
    const otherRef = other.reference(other.allocate());
    const otherToken = await other.issueToken(SIGNER, { iatSeconds: NOW - 60 });
    const resolver = createStatusListResolver({
      fetchToken: async (uri) => (uri === URI ? CURRENT_REVOKED : otherToken),
      issuerPublicKey: ISSUER_JWK,
      purpose: 'revocation',
      nowSeconds: () => NOW,
    });
    expect((await resolver.resolve(REF)).valid).toBe(false);
    expect((await resolver.resolve(otherRef)).valid).toBe(true);
  });

  it('記憶する URI 数は上限で打ち切られ、最も古い URI から忘れる', async () => {
    const tokens = new Map<string, string>();
    const refs: ReturnType<StatusListManager['reference']>[] = [];
    for (let i = 0; i <= MAX_TRACKED_STATUS_LIST_URIS; i += 1) {
      const m = new StatusListManager({
        uri: `https://issuer.example/status/many/${i}`,
        issuer: 'did:web:issuer.example',
        size: 8,
        bits: 1,
      });
      refs.push(m.reference(m.allocate()));
      tokens.set(m.uri, await m.issueToken(SIGNER, { iatSeconds: NOW }));
    }
    const older = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW - 60 });
    let firstFetches = 0;
    const resolver = createStatusListResolver({
      fetchToken: async (uri) => {
        if (uri === URI) {
          firstFetches += 1;
          return firstFetches === 1 ? CURRENT_REVOKED : older;
        }
        return tokens.get(uri) as string;
      },
      issuerPublicKey: ISSUER_JWK,
      purpose: 'revocation',
      nowSeconds: () => NOW,
    });
    await resolver.resolve(REF);
    await expectRejectCode(resolver.resolve(REF), ErrorCodes.VC_EXPIRED);
    // 上限 + 1 件の別 URI を観測すると URI の記憶が 1 つ押し出される（Map の挿入順で最古＝REF の URI）。
    for (const ref of refs) {
      await resolver.resolve(ref);
    }
    expect((await resolver.resolve(REF)).valid).toBe(false);
  });

  it('iat 不在・不正、ttl 不正の Token は VC_SCHEMA_INVALID', async () => {
    for (const token of [
      await reissue(CURRENT_REVOKED, { iat: undefined }),
      await reissue(CURRENT_REVOKED, { iat: 'now' }),
      await reissue(CURRENT_REVOKED, { iat: -1 }),
      await reissue(CURRENT_REVOKED, { ttl: 0 }),
      await reissue(CURRENT_REVOKED, { ttl: -5 }),
      await reissue(CURRENT_REVOKED, { ttl: '60' }),
    ]) {
      await expectRejectCode(resolverOf([token]).resolve(REF), ErrorCodes.VC_SCHEMA_INVALID);
    }
  });

  it('maxTokenAgeSeconds が正の整数でなければ生成時に VC_SCHEMA_INVALID', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => resolverOf([CURRENT_REVOKED], { maxTokenAgeSeconds: bad })).toThrow();
    }
  });

  it('キャッシュは Token の寿命（iat + 上限）を超えて古い Token を返さず、再取得する', async () => {
    let now = NOW;
    let calls = 0;
    const resolver = createStatusListResolver({
      fetchToken: async () => {
        calls += 1;
        // iat = 取得時刻。ttl=30 なので 30 秒を超えて使い回してはならない。
        return reissue(await MANAGER.issueToken(SIGNER, { iatSeconds: now }), { ttl: 30 });
      },
      issuerPublicKey: ISSUER_JWK,
      purpose: 'revocation',
      nowSeconds: () => now,
      statusCache: createStatusListCache(() => now),
      onPolicyEvent: () => {},
    });
    await resolver.resolve(REF);
    now = NOW + 29;
    await resolver.resolve(REF);
    expect(calls).toBe(1);
    now = NOW + 30;
    await resolver.resolve(REF);
    expect(calls).toBe(2);
  });
});

// 発行側 `ttlSeconds` は `exp` だけでなく `ttl` クレームも出す。出さないと、検証側は
// 既定の年齢上限（24 時間）へフォールバックし、SDK 自身が発行した長命 Token を SDK 自身の既定
// resolver が `exp` 内でも 3024 で拒否する（発行 API と検証 API が噛み合わない）。
describe('発行側 ttlSeconds と検証側の年齢上限の整合', () => {
  it('ttlSeconds で発行した 24 時間超の Token は、既定の年齢上限でも exp 内なら受理される', async () => {
    const manager = new StatusListManager({
      uri: URI,
      issuer: 'did:web:issuer.example',
      size: 100,
      bits: 1,
    });
    const index = manager.allocate();
    const ref = manager.reference(index);
    // iat は 2 日前、ttl / exp は 7 日。既定の年齢上限（24 時間）より古いが exp 内。
    const token = await manager.issueToken(SIGNER, {
      iatSeconds: NOW - 2 * DAY,
      ttlSeconds: 7 * DAY,
    });

    const result = await resolverOf([token]).resolve(ref);

    expect(result.valid).toBe(true);
  });

  it('ttl は ttlSeconds と同じ値で出力する（exp だけを見て推測しない）', async () => {
    const manager = new StatusListManager({
      uri: URI,
      issuer: 'did:web:issuer.example',
      size: 100,
      bits: 1,
    });
    manager.allocate();
    const token = await manager.issueToken(SIGNER, { iatSeconds: NOW, ttlSeconds: 7 * DAY });

    const { payload } = decodeCompactJws(token);
    expect(payload.ttl).toBe(7 * DAY);
    expect(payload.exp).toBe(NOW + 7 * DAY);
  });

  it('expSeconds 優先時は ttl を出さない（寿命の起点が iat とは限らない）', async () => {
    const manager = new StatusListManager({
      uri: URI,
      issuer: 'did:web:issuer.example',
      size: 100,
      bits: 1,
    });
    manager.allocate();
    const token = await manager.issueToken(SIGNER, {
      iatSeconds: NOW,
      expSeconds: NOW + 7 * DAY,
      ttlSeconds: 60,
    });

    const { payload } = decodeCompactJws(token);
    expect(payload.ttl).toBeUndefined();
    expect(payload.exp).toBe(NOW + 7 * DAY);
  });
});
