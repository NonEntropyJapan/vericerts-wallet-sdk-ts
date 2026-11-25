/**
 * 新規取得した Status List Token の `exp` 評価の回帰テスト。
 *
 * 新規取得した Token は `exp` を過ぎていれば拒否する。FO-2 で期限切れキャッシュを
 * 再利用する場合も署名を検証し、Token から実際のステータスビットを読む。
 *
 * 検証内容:
 * - ネットワークから**新規取得**した Token が既に `exp` を過ぎていれば `VC_EXPIRED`（3024）で拒否する。
 *   以前は署名検証しか行わず、期限切れの Token が warnings 無しの通常結果として返っていた。
 * - この拒否は新規取得経路に限る。FO-2 では stale な Token を再利用でき、期限切れの
 *   Token でも実ビット値を返さなければならない（ここまで弾くと FO-2 が成立しない）。
 * - `exp` が**あるのに不正**（非整数 / 負値 / 文字列）な Token は `VC_SCHEMA_INVALID`（3002）で
 *   拒否する。以前は不正値を `undefined` に丸めていたため、上の 3024 拒否と `exp` による TTL
 *   切り詰めが同時に黙って無効化され、Token が上限いっぱいの TTL を得ていた（fail-open の回帰）。
 *   `exp` **不在**は許容されるため、不在と不正を取り違えてはならない。
 */

import { describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import type { FailSafeWarning } from '../../../failsafe/index.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { createStatusListCache } from '../../status-list-cache.js';
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
const BOOM = new Error('network unreachable');
const FO2_WARNING: FailSafeWarning = { policyEvent: 'FO-2', auditEvent: 'status_list_stale' };

const MANAGER = new StatusListManager({
  uri: URI,
  issuer: 'did:web:issuer.example',
  size: 100,
  bits: 1,
});
const IDX = MANAGER.allocate();
const REF = MANAGER.reference(IDX);
/** `exp` が NOW + 30 の Token（NOW + 30 以降は使ってはならない）。 */
const SHORT_LIVED = await MANAGER.issueToken(SIGNER, {
  iatSeconds: NOW,
  expSeconds: NOW + 30,
});

/** 可変時計・故障スイッチ付きの解決器を組み立てる。 */
function setup(opts: { withCache?: boolean } = {}): {
  resolve: () => Promise<unknown>;
  at: (offsetSeconds: number) => void;
  breakFetch: () => void;
} {
  let now = NOW;
  let broken = false;
  const resolver = createStatusListResolver({
    fetchToken: async () => {
      if (broken) {
        throw BOOM;
      }
      return SHORT_LIVED;
    },
    issuerPublicKey: ISSUER_JWK,
    purpose: 'revocation',
    nowSeconds: () => now,
    ...(opts.withCache === true ? { statusCache: createStatusListCache(() => now) } : {}),
    ...(opts.withCache === true ? { failSafePolicy: { suppressPrompt: ['FO-2' as const] } } : {}),
    // Fail-open には判断を監査ログに記録するコールバックが必要。
    onPolicyEvent: () => {},
  });
  return {
    resolve: () => resolver.resolve(REF),
    at: (offsetSeconds) => {
      now = NOW + offsetSeconds;
    },
    breakFetch: () => {
      broken = true;
    },
  };
}

/** `promise` が指定コードの VericertsError で reject することを検証する。 */
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

describe('新規取得した Token の exp 評価', () => {
  it('exp 前に取得した Token は通常どおり評価する', async () => {
    const s = setup();
    expect(await s.resolve()).toEqual({ valid: true, purpose: 'revocation', value: 0 });
  });

  // 回帰の中心: 以前は署名検証のみで通り、期限切れの Token が通常結果として返っていた。
  it('exp を過ぎた Token を新規取得したら VC_EXPIRED（3024）で拒否する', async () => {
    const s = setup();
    s.at(30);
    await expectRejectCode(s.resolve(), ErrorCodes.VC_EXPIRED);
  });

  it('exp 到達は境界を含む（now === exp で拒否する）', async () => {
    const s = setup();
    s.at(30);
    await expectRejectCode(s.resolve(), ErrorCodes.VC_EXPIRED);
    s.at(31);
    await expectRejectCode(s.resolve(), ErrorCodes.VC_EXPIRED);
  });

  it('例外に URI・Token を漏らさない', async () => {
    const s = setup();
    s.at(60);
    let caught: unknown;
    try {
      await s.resolve();
    } catch (error) {
      caught = error;
    }
    const error = caught as VericertsError;
    const serialized = `${error.message}${JSON.stringify(error.context ?? {})}`;
    expect(serialized).not.toContain(URI);
    expect(serialized).not.toContain(SHORT_LIVED);
  });
});

describe('FO-2 の stale 再利用はこの制限の対象外', () => {
  // FO-2 では古い Token を検証して実ビット値を読み取る。
  // 新規取得の exp 判定をここまで広げると FO-2 が成立しなくなるため、経路を分けている。
  it('exp を過ぎた stale な Token でも FO-2 なら実ビット値を返す', async () => {
    const s = setup({ withCache: true });
    // TTL 内にキャッシュを温める（この時点では exp 前）。
    expect(await s.resolve()).toEqual({ valid: true, purpose: 'revocation', value: 0 });
    // exp・TTL の双方を跨ぎ、再取得を失敗させる → stale なエントリしか無い状態。
    s.at(120);
    s.breakFetch();
    expect(await s.resolve()).toEqual({
      valid: true,
      purpose: 'revocation',
      value: 0,
      warnings: [FO2_WARNING],
    });
  });
});

/**
 * 指定した `exp` を持つ Status List Token を組み立てる。
 *
 * `issueToken` の `expSeconds` は `number` 型なので、型で弾けない不正値（文字列・小数・負値）を
 * 注入するには payload を直接書き換えて再署名するしかない。署名自体は正当なので、Token は
 * 署名検証を通過したうえで `exp` の型検証に到達する。
 */
function tokenWithExp(exp: unknown): string {
  const parts = SHORT_LIVED.split('.');
  const header = parts[0] ?? '';
  const payload = JSON.parse(Buffer.from(parts[1] ?? '', 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  if (exp === undefined) {
    delete payload.exp;
  } else {
    payload.exp = exp;
  }
  const signingInput = `${header}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
  const signature = SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

/** 指定した Token だけを返す解決器（時刻は NOW 固定）。 */
function resolverFor(token: string): { resolve: () => Promise<unknown> } {
  const resolver = createStatusListResolver({
    fetchToken: async () => token,
    issuerPublicKey: ISSUER_JWK,
    purpose: 'revocation',
    nowSeconds: () => NOW,
    statusCache: createStatusListCache(() => NOW),
    onPolicyEvent: () => {},
  });
  return { resolve: () => resolver.resolve(REF) };
}

describe('不正な exp を持つ Token（fail-open の回帰）', () => {
  // 回帰の中心: いずれも以前は `undefined` に丸められ、3024 判定と TTL 切り詰めが揃って無効化され、
  // Token が warnings 無しの通常結果として返りつつ上限 TTL でキャッシュされていた。
  const malformed: readonly (readonly [string, unknown])[] = [
    ['文字列', 'soon'],
    ['小数', NOW + 0.5],
    ['負値', -1],
    ['NaN は JSON 化で null になる（非数値）', null],
    ['真偽値', true],
  ];
  for (const [label, exp] of malformed) {
    it(`exp が${label}なら VC_SCHEMA_INVALID（3002）で拒否する`, async () => {
      await expectRejectCode(
        resolverFor(tokenWithExp(exp)).resolve(),
        ErrorCodes.VC_SCHEMA_INVALID,
      );
    });
  }

  it('拒否された Token はキャッシュされない（再取得しても同じく拒否する）', async () => {
    const r = resolverFor(tokenWithExp('soon'));
    await expectRejectCode(r.resolve(), ErrorCodes.VC_SCHEMA_INVALID);
    await expectRejectCode(r.resolve(), ErrorCodes.VC_SCHEMA_INVALID);
  });

  // 不在と不正の区別: `exp` は任意であり、無い Token は拒否してはならない。
  it('exp が不在の Token は通常どおり評価する', async () => {
    expect(await resolverFor(tokenWithExp(undefined)).resolve()).toEqual({
      valid: true,
      purpose: 'revocation',
      value: 0,
    });
  });
});
