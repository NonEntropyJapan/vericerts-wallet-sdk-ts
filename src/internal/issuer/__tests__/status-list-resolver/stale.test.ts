/**
 * `createStatusListResolver` の FO-2（staleness > TTL）Fail-open 経路の回帰テスト。
 *
 * FO-2 の stale 再利用について時間上限と監査記録を検証する。
 *
 * FO-1 との違いが要点である。FO-1 は失効状態を一切確認できないため「有効とみなす」が、FO-2 は
 * TTL 切れとはいえ実データを持っているため **stale な Token を検証してビットを読み、実際の失効
 * 状態を返す**。したがって失効済み VC が Fail-open で有効に戻ることは無い。
 *
 * 検証内容:
 * - stale なキャッシュ + 再取得失敗 → FO-2 で通過し、実ビット値と警告を返す。
 * - stale な Token が失効を示していれば失効のまま返る（Fail-open が失効を打ち消さない）。
 * - `escalate: ['FO-2']` で Fail-closed に固定できる。
 * - キャッシュが無い状態での取得失敗は従来どおり FO-1 のまま。
 * - 監査レコード・警告に URI / Token を含めない。
 */

import { describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import type {
  FailSafeAuditRecord,
  FailSafePolicy,
  FailSafeWarning,
} from '../../../failsafe/index.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { createStatusListCache } from '../../status-list-cache.js';
import { createStatusListResolver } from '../../status-list-resolver.js';
import { evaluateStatusEntry } from '../../status-list-verifier.js';
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
const VALID_TOKEN = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW });
MANAGER.setStatus(IDX, 1);
const REVOKED_TOKEN = await MANAGER.issueToken(SIGNER, { iatSeconds: NOW });

/** キャッシュ配線済みの解決器と、時計・故障スイッチ・監査 sink を組み立てる。 */
function setup(opts: { token: string; policy?: FailSafePolicy; withCache?: boolean }): {
  resolver: ReturnType<typeof createStatusListResolver>;
  records: FailSafeAuditRecord[];
  at: (offsetSeconds: number) => void;
  breakFetch: () => void;
} {
  let now = NOW;
  let broken = false;
  const records: FailSafeAuditRecord[] = [];
  const resolver = createStatusListResolver({
    fetchToken: async () => {
      if (broken) {
        throw BOOM;
      }
      return opts.token;
    },
    issuerPublicKey: ISSUER_JWK,
    purpose: 'revocation',
    nowSeconds: () => now,
    onPolicyEvent: (r) => records.push(r),
    ...(opts.withCache === false ? {} : { statusCache: createStatusListCache(() => now) }),
    ...(opts.policy === undefined ? {} : { failSafePolicy: opts.policy }),
  });
  return {
    resolver,
    records,
    at: (offsetSeconds) => {
      now = NOW + offsetSeconds;
    },
    breakFetch: () => {
      broken = true;
    },
  };
}

/** キャッシュを温めてから TTL を跨ぎ、再取得を失敗させた状態にする。 */
async function makeStale(s: ReturnType<typeof setup>): Promise<void> {
  await s.resolver.resolve(REF);
  s.at(61);
  s.breakFetch();
}

describe('FO-2 Fail-open（stale な Status List キャッシュ）', () => {
  it('stale な Token の実ビット値を返し、FO-2 の警告と accepted の監査記録が残る', async () => {
    const s = setup({ token: VALID_TOKEN, policy: { suppressPrompt: ['FO-2'] } });
    await makeStale(s);

    expect(await s.resolver.resolve(REF)).toEqual({
      valid: true,
      purpose: 'revocation',
      value: 0,
      warnings: [FO2_WARNING],
    });
    expect(s.records).toHaveLength(1);
    expect(s.records[0]?.policy_event).toBe('FO-2');
    expect(s.records[0]?.audit_event).toBe('status_list_stale');
    expect(s.records[0]?.user_consent).toBe('accepted');
  });

  it('stale な Token が失効を示していれば失効のまま返る（Fail-open が失効を打ち消さない）', async () => {
    const s = setup({ token: REVOKED_TOKEN, policy: { suppressPrompt: ['FO-2'] } });
    await makeStale(s);

    const result = await s.resolver.resolve(REF);
    expect(result.valid).toBe(false);
    expect(result.value).toBe(1);
    expect(result.warnings).toEqual([FO2_WARNING]);
    expect(evaluateStatusEntry(result)).toBe('revoked');
  });

  it('escalate: ["FO-2"] なら元の取得エラーを throw する（fail-closed）', async () => {
    const s = setup({
      token: VALID_TOKEN,
      policy: { escalate: ['FO-2'], suppressPrompt: ['FO-2'] },
    });
    await makeStale(s);

    await expect(s.resolver.resolve(REF)).rejects.toThrow(BOOM);
    expect(s.records).toEqual([]);
  });

  it('同意コールバックが無ければ throw し、rejected が監査記録される', async () => {
    const s = setup({ token: VALID_TOKEN });
    await makeStale(s);

    await expect(s.resolver.resolve(REF)).rejects.toThrow(BOOM);
    expect(s.records[0]?.policy_event).toBe('FO-2');
    expect(s.records[0]?.user_consent).toBe('rejected');
  });

  it('TTL 内のキャッシュ命中では Fail-open 判定自体が起きない', async () => {
    const s = setup({ token: VALID_TOKEN, policy: { suppressPrompt: ['FO-2'] } });
    await s.resolver.resolve(REF);
    s.at(59);
    s.breakFetch();

    expect(await s.resolver.resolve(REF)).toEqual({ valid: true, purpose: 'revocation', value: 0 });
    expect(s.records).toEqual([]);
  });

  it('キャッシュに Token が無い取得失敗は従来どおり FO-1 のまま', async () => {
    const s = setup({
      token: VALID_TOKEN,
      policy: { suppressPrompt: ['FO-1', 'FO-2'] },
      withCache: false,
    });
    s.breakFetch();

    expect(await s.resolver.resolve(REF)).toEqual({
      valid: true,
      purpose: 'revocation',
      value: 0,
      warnings: [{ policyEvent: 'FO-1', auditEvent: 'status_check_unreachable' }],
    });
    expect(s.records[0]?.policy_event).toBe('FO-1');
    expect(s.records[0]?.audit_event).toBe('status_check_unreachable');
  });

  it('監査レコードと警告に URI / Token / ビット値は含まれない', async () => {
    const s = setup({ token: REVOKED_TOKEN, policy: { suppressPrompt: ['FO-2'] } });
    await makeStale(s);

    const result = await s.resolver.resolve(REF);
    const serializedRecord = JSON.stringify(s.records[0]);
    expect(serializedRecord).not.toContain(URI);
    expect(serializedRecord).not.toContain(REVOKED_TOKEN);
    expect(JSON.stringify(result.warnings)).toEqual(JSON.stringify([FO2_WARNING]));
  });
});
