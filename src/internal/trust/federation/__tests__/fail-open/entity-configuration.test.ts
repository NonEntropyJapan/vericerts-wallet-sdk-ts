/**
 * FO-6（Entity Configuration 到達不能時に stale なキャッシュで警告通過）の回帰テスト。
 *
 * 検証内容:
 * - stale なキャッシュがあり、ウィンドウ・監査シンク・同意が揃っていれば警告付きで通過する。
 *   返る Statement は **stale な実データ由来**であり、データ無しの近道ではない。
 * - キャッシュが無ければ常に fail-closed（`resolveFailOpen` すら呼ばない ＝ 監査記録も残らない）。
 * - `failOpenWindow` 未注入なら FO-6 は完全に不活性（従来と同じ挙動）。
 * - `escalate: ['FO-6']` / 同意拒否 / 時間上限超過はいずれも fail-closed。
 * - negative cache（30 秒）が生きている連続呼び出しでも FO-6 は消えない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { resolveEntityConfiguration } from '../../entity-configuration.js';
import { LEAF_KEY, NOW_SECONDS, signStatement, toJwk, WRONG_KEY } from '../federation-fixtures.js';
import {
  expectRejectCode,
  type FailOpenHarness,
  FO6_WARNING,
  failOpenHarness,
  STALE_AFTER_SECONDS,
} from './harness.js';

const ENTITY_ID = 'https://leaf.example.eu';
const WELL_KNOWN = `${ENTITY_ID}/.well-known/openid-federation`;

/**
 * `exp` を十分先に置いた自己署名 Entity Configuration。
 *
 * TTL は `min(exp - now, 600)` なので 600 秒で頭打ちになり、`STALE_AFTER_SECONDS` 進めると
 * 「TTL 切れだが `exp` 内」という FO-6 の対象状態になる。
 */
function selfSigned(key: Uint8Array = LEAF_KEY): string {
  return signStatement(
    key,
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

/** 応答マップ（well-known のみ）。 */
function responses(jwt = selfSigned()): Map<string, string> {
  return new Map([[WELL_KNOWN, jwt]]);
}

/** 「一度取得に成功 → TTL 切れ → オフライン」までを進めた環境を返す。 */
async function staleAndOffline(): Promise<FailOpenHarness> {
  const h = failOpenHarness(responses());
  await resolveEntityConfiguration(ENTITY_ID, h.base);
  h.advance(STALE_AFTER_SECONDS);
  h.goOffline();
  return h;
}

describe('FO-6 成立（stale キャッシュ + ウィンドウ + 監査 + 同意）', () => {
  it('警告付きで通過し、stale な実データのクレームを返す', async () => {
    const h = await staleAndOffline();
    const config = await resolveEntityConfiguration(ENTITY_ID, {
      ...h.base,
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: h.onPolicyEvent,
      requestConsent: h.requestConsent,
    });
    expect(config.warnings).toEqual([FO6_WARNING]);
    expect(config.statement.sub).toBe(ENTITY_ID);
    expect(config.statement.exp).toBe(NOW_SECONDS + 4000);
    expect(h.records).toHaveLength(1);
    expect(h.records[0]?.policy_event).toBe('FO-6');
    expect(h.records[0]?.user_consent).toBe('accepted');
    expect(h.consents).toHaveLength(1);
  });

  it('stale な JWT も再検証される（署名不成立なら 5010 で拒否する）', async () => {
    // payload の jwks は LEAF_KEY 由来だが署名は WRONG_KEY → 自己署名が成立しない。
    const h = failOpenHarness(responses(selfSigned(WRONG_KEY)));
    // 初回取得自体が 5010 になるため、キャッシュへは検証不能な JWT を直接入れて stale にする。
    h.base.statementCache?.set(WELL_KNOWN, selfSigned(WRONG_KEY), 60, NOW_SECONDS);
    h.advance(STALE_AFTER_SECONDS);
    h.goOffline();
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        ...h.base,
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  // 回帰の中心: negative cache が生きている 30 秒間だけ FO-6 が消えると、障害継続中に
  // 通過と拒否が周期的に入れ替わる。
  it('negative cache が生きている連続呼び出しでも通過する', async () => {
    const h = await staleAndOffline();
    const deps = {
      ...h.base,
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: h.onPolicyEvent,
      requestConsent: h.requestConsent,
    };
    expect((await resolveEntityConfiguration(ENTITY_ID, deps)).warnings).toEqual([FO6_WARNING]);
    h.advance(10);
    expect((await resolveEntityConfiguration(ENTITY_ID, deps)).warnings).toEqual([FO6_WARNING]);
    expect(h.records).toHaveLength(2);
  });

  it('時間上限（既定 60 秒）を超えた継続失敗は fail-closed に戻る', async () => {
    const h = await staleAndOffline();
    const deps = {
      ...h.base,
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: h.onPolicyEvent,
      requestConsent: h.requestConsent,
    };
    await resolveEntityConfiguration(ENTITY_ID, deps);
    h.advance(61);
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, deps),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
  });
});

describe('FO-6 不成立（いずれも元の 5011 を伝播する）', () => {
  it('キャッシュが一切無ければ resolveFailOpen を呼ばない（監査記録も残らない）', async () => {
    const h = failOpenHarness(responses());
    h.goOffline();
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        ...h.base,
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    expect(h.records).toEqual([]);
    expect(h.consents).toEqual([]);
  });

  it('failOpenWindow 未注入なら stale キャッシュがあっても発動しない（既定の挙動）', async () => {
    const h = await staleAndOffline();
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        ...h.base,
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    expect(h.records).toEqual([]);
  });

  it('escalate: ["FO-6"] は監査シンクと同意が揃っていても fail-closed', async () => {
    const h = await staleAndOffline();
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        ...h.base,
        failSafePolicy: { escalate: ['FO-6'] },
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    // deny は Fail-open を選択していないため監査記録の対象ではない。
    expect(h.records).toEqual([]);
  });

  it('監査シンク未指定は fail-closed', async () => {
    const h = await staleAndOffline();
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        ...h.base,
        failOpenWindow: createFailOpenWindow(),
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
  });

  it('同意が得られなければ fail-closed（rejected として監査記録する）', async () => {
    const h = await staleAndOffline();
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, {
        ...h.base,
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: () => false,
      }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    expect(h.records).toHaveLength(1);
    expect(h.records[0]?.user_consent).toBe('rejected');
  });
});

describe('時計巻き戻りと negative cache の併存', () => {
  it('負のキャッシュ命中時、TTL 内に戻って新鮮に見えるエントリを stale な代替として差し出さない', async () => {
    // `staleAndOffline()`: t=0 で取得成功（TTL=600 で格納）→ t=700 まで進めて TTL 切れ
    // （700 >= 600）→ オフライン化。
    const h = await staleAndOffline();
    const deps = {
      ...h.base,
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: h.onPolicyEvent,
      requestConsent: h.requestConsent,
    };

    // t=700 時点の 1 回目の取得失敗。エントリは本当に stale（700 >= TTL 600）かつ `exp`
    // （NOW+4000）内なので FO-6 が成立する。negative cache も t=700 起点で 30 秒
    // （expiresAt=730）記憶される。
    const primed = await resolveEntityConfiguration(ENTITY_ID, deps);
    expect(primed.warnings).toEqual([FO6_WARNING]);
    expect(h.records).toHaveLength(1);

    // t=100 まで巻き戻す（700 → 100）。エントリは「経過 100 秒 < TTL 600 秒」で新鮮に見えるが、
    // negative cache（expiresAt=730）はまだ生きている。
    h.advance(-600);

    // 新鮮な（TTL 内の）エントリが FO-6 の代替候補として差し出されてはならない。
    // 差し出されれば FO-6 が誤って再成立してしまうが、正しくは gate に到達すらせず
    // 元の取得失敗（negative cache の記憶）をそのまま伝播する（監査記録も増えない）。
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, deps),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    expect(h.records).toHaveLength(1);
  });
});
