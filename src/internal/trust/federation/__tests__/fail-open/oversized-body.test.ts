/**
 * 本文サイズ上限超過（1 MiB）が FO-6 の引き金にならないことの回帰テスト。
 *
 * 検証内容:
 * - 上限超過は `context.reason = 'oversized_body'` を立てる（ゼロバイト応答と区別できる）。
 * - `failOpenWindow` / 監査シンク / 同意が揃っていても、上限超過では陳腐化した Statement が
 *   復活しない（`resolveFailOpen` に到達しないので監査記録も残らない）。
 *   これが無いと、攻撃者が制御するエンティティは「一度正当に応答させてキャッシュを作らせ、
 *   以後 1 MiB 超を返す」だけで FO-6 を任意に作り出せる。
 * - 到達不能（503）なら従来どおり FO-6 が成立する（本修正が FO-6 自体を殺していないこと）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { resolveEntityConfiguration } from '../../entity-configuration.js';
import { LEAF_KEY, NOW_SECONDS, signStatement, toJwk } from '../federation-fixtures.js';
import {
  expectRejectCode,
  type FailOpenHarness,
  FO6_WARNING,
  failOpenHarness,
  STALE_AFTER_SECONDS,
} from './harness.js';

const ENTITY_ID = 'https://leaf.example.eu';
const WELL_KNOWN = `${ENTITY_ID}/.well-known/openid-federation`;

/** `exp` を十分先に置いた自己署名 Entity Configuration（TTL 切れ後も再検証が通る）。 */
function selfSigned(): string {
  return signStatement(
    LEAF_KEY,
    {
      iss: ENTITY_ID,
      sub: ENTITY_ID,
      iat: NOW_SECONDS - 3600,
      exp: NOW_SECONDS + 4000,
      jwks: { keys: [toJwk(LEAF_KEY, 'leaf-1')] },
    },
    { kid: 'leaf-1' },
  );
}

/** 「一度取得に成功 → TTL 切れ」まで進めた環境を返す（FO-6 の前提状態）。 */
async function staleCache(): Promise<FailOpenHarness> {
  const h = failOpenHarness(new Map([[WELL_KNOWN, selfSigned()]]));
  await resolveEntityConfiguration(ENTITY_ID, h.base);
  h.advance(STALE_AFTER_SECONDS);
  return h;
}

/** FO-6 が成立し得る依存一式（ウィンドウ・監査シンク・同意が揃った状態）。 */
function failOpenDeps(h: FailOpenHarness): Parameters<typeof resolveEntityConfiguration>[1] {
  return {
    ...h.base,
    failOpenWindow: createFailOpenWindow(),
    onPolicyEvent: h.onPolicyEvent,
    requestConsent: h.requestConsent,
  };
}

describe('Entity Configuration の本文上限超過', () => {
  it('上限超過は oversized_body として立ち、空本文と区別できる', async () => {
    const h = failOpenHarness(new Map([[WELL_KNOWN, selfSigned()]]));
    h.goOversized();
    const failure = await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, h.base),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    expect(failure.context).toEqual({ reason: 'oversized_body' });
  });

  it('ゼロバイト応答には oversized_body を立てない', async () => {
    const h = failOpenHarness(new Map([[WELL_KNOWN, '']]));
    const failure = await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, h.base),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    expect(failure.context).toBeUndefined();
  });

  it('failOpenWindow が揃っていても上限超過では stale な Statement を復活させない', async () => {
    const h = await staleCache();
    h.goOversized();
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, failOpenDeps(h)),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    // gate に到達していない ＝ 監査記録も時間上限の消費も発生していない。
    expect(h.records).toEqual([]);
    expect(h.consents).toEqual([]);
  });

  it('negative cache から再送出される上限超過でも FO-6 は成立しない', async () => {
    const h = await staleCache();
    h.goOversized();
    const deps = failOpenDeps(h);
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, deps),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    // 2 回目は negative cache（30 秒）命中でネットワークに出ない経路を通る。
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, deps),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    expect(h.records).toEqual([]);
  });

  it('到達不能（503）では従来どおり FO-6 が成立する', async () => {
    const h = await staleCache();
    h.goOffline();
    const config = await resolveEntityConfiguration(ENTITY_ID, failOpenDeps(h));
    expect(config.warnings).toEqual([FO6_WARNING]);
    expect(h.records).toHaveLength(1);
  });
});
