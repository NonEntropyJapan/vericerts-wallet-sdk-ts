/**
 * Status List 取得失敗時の**既定**（FO-1 / FO-2）と、その成立条件・opt-in の
 * 回帰テスト。
 *
 * FO-1 / FO-2 は「ユーザー同意 + 監査ログ記録」の条件下で Fail-open が
 * **既定**であり、SDK 利用者が `failSafePolicy` を一切渡さなくても（override 無し）成立する。条件の
 * 片方でも満たせない（同意コールバックが無い・監査記録先が無い）場合は Fail-open せず元の失敗を伝播する。
 * Fail-closed へ戻す opt-in は `escalate`、同意プロンプトを省く opt-in は `suppressPrompt`。
 * 署名不正・`sub` 不一致などの検証失敗（Fail-closed 必須事象）は取得失敗ではないので、同意が
 * あっても Fail-open しない。
 *
 * 検証内容:
 * - 既定（`failSafePolicy` 無し）+ 同意 + 監査記録先で FO-1 / FO-2 が警告付きで通過する（FO-2 は実ビット値）。
 * - 同意コールバックが `FailSafeDecision`（`warn` / プロンプト要）を受け取り、拒否すれば伝播する。
 * - 同意が無い・監査記録先が無い場合は同意が true でも伝播する（記録先が無ければ監査記録も出ない）。
 * - opt-in: `escalate` は同意と記録先があっても Fail-closed、`suppressPrompt` は同意無しで通過。
 * - 署名検証に失敗する応答は同意があっても Fail-open しない。
 */

import { describe, expect, it } from 'bun:test';
import type { StatusReference } from '../../../credential/sdjwt/sdjwt.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import type {
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafePolicy,
} from '../../../failsafe/index.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { createStatusListCache } from '../../status-list-cache.js';
import { createStatusListResolver } from '../../status-list-resolver.js';
import { StatusListManager } from '../../token-status-list.js';

const URI = 'https://issuer.example/status/default-policy';
const NOW = 1_700_000_000;
const BOOM = new Error('network unreachable');

const jwkOf = (seed: number): { key: Uint8Array; jwk: PublicKeyJwk } => {
  const key = new Uint8Array(32).fill(seed);
  const pub = getP256PublicKey(key, false);
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return {
    key,
    jwk: { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) },
  };
};
const ISSUER = jwkOf(7);
const OTHER = jwkOf(8);

const MANAGER = new StatusListManager({
  uri: URI,
  issuer: 'did:web:issuer.example',
  size: 100,
  bits: 1,
});
const IDX = MANAGER.allocate();
const REF: StatusReference = MANAGER.reference(IDX);
const VALID_TOKEN = await MANAGER.issueToken(createPrivateKeySigner(ISSUER.key, 'ES256'), {
  iatSeconds: NOW,
});
MANAGER.setStatus(IDX, 1);
const REVOKED_TOKEN = await MANAGER.issueToken(createPrivateKeySigner(ISSUER.key, 'ES256'), {
  iatSeconds: NOW,
});
const FORGED_TOKEN = await MANAGER.issueToken(createPrivateKeySigner(OTHER.key, 'ES256'), {
  iatSeconds: NOW,
});

interface Harness {
  readonly resolver: ReturnType<typeof createStatusListResolver>;
  readonly records: FailSafeAuditRecord[];
  readonly decisions: FailSafeDecision[];
  /** 以降の取得を失敗させ、時計を TTL（60 秒）超過まで進める（キャッシュがあれば stale になる）。 */
  readonly goOffline: () => void;
}

interface HarnessOptions {
  readonly token: string;
  readonly consent?: boolean;
  readonly audit?: boolean;
  readonly policy?: FailSafePolicy;
  readonly withCache?: boolean;
  readonly startOffline?: boolean;
}

/** `consent` / `audit` は既定で「渡す」。`failSafePolicy` は `policy` を渡したときだけ設定する。 */
function harness(opts: HarnessOptions): Harness {
  let now = NOW;
  let offline = opts.startOffline === true;
  const records: FailSafeAuditRecord[] = [];
  const decisions: FailSafeDecision[] = [];
  const resolver = createStatusListResolver({
    fetchToken: async () => {
      if (offline) {
        throw BOOM;
      }
      return opts.token;
    },
    issuerPublicKey: ISSUER.jwk,
    purpose: 'revocation',
    nowSeconds: () => now,
    ...(opts.withCache === false ? {} : { statusCache: createStatusListCache(() => now) }),
    ...(opts.audit === false ? {} : { onPolicyEvent: (r: FailSafeAuditRecord) => records.push(r) }),
    ...(opts.consent === undefined
      ? {}
      : {
          requestConsent: (d: FailSafeDecision) => {
            decisions.push(d);
            return opts.consent as boolean;
          },
        }),
    ...(opts.policy === undefined ? {} : { failSafePolicy: opts.policy }),
  });
  return {
    resolver,
    records,
    decisions,
    goOffline: () => {
      now = NOW + 61;
      offline = true;
    },
  };
}

const FO1 = { policyEvent: 'FO-1', auditEvent: 'status_check_unreachable' } as const;
const FO2 = { policyEvent: 'FO-2', auditEvent: 'status_list_stale' } as const;

describe('既定（failSafePolicy 無し）: ユーザー同意 + 監査ログのもとで Fail-open', () => {
  it('FO-1: 同意があれば警告付きで有効として通過し、同意が監査記録される', async () => {
    const h = harness({ token: VALID_TOKEN, consent: true, startOffline: true });

    expect(await h.resolver.resolve(REF)).toEqual({
      valid: true,
      purpose: 'revocation',
      value: 0,
      warnings: [FO1],
    });
    expect(h.decisions).toEqual([
      {
        policyEvent: 'FO-1',
        severity: 'warn',
        auditEvent: 'status_check_unreachable',
        promptRequired: true,
      },
    ]);
    expect(h.records).toHaveLength(1);
    expect(h.records[0]).toMatchObject({
      policy_event: 'FO-1',
      audit_event: 'status_check_unreachable',
      user_consent: 'accepted',
      override: {},
    });
  });

  it('FO-1: 同意されなければ元の取得エラーを伝播し、rejected が監査記録される', async () => {
    const h = harness({ token: VALID_TOKEN, consent: false, startOffline: true });

    await expect(h.resolver.resolve(REF)).rejects.toThrow(BOOM);
    expect(h.records).toHaveLength(1);
    expect(h.records[0]?.user_consent).toBe('rejected');
  });

  it('FO-2: stale な Token の実ビット値で通過し（有効な Token は valid）、警告と同意の監査記録が残る', async () => {
    const h = harness({ token: VALID_TOKEN, consent: true });
    await h.resolver.resolve(REF);
    h.goOffline();

    expect(await h.resolver.resolve(REF)).toEqual({
      valid: true,
      purpose: 'revocation',
      value: 0,
      warnings: [FO2],
    });
    expect(h.decisions.map((d) => d.policyEvent)).toEqual(['FO-2']);
    expect(h.records[0]).toMatchObject({ policy_event: 'FO-2', user_consent: 'accepted' });
  });

  it('FO-2: stale な Token が失効を示していれば、Fail-open でも失効のまま返る', async () => {
    const h = harness({ token: REVOKED_TOKEN, consent: true });
    await h.resolver.resolve(REF);
    h.goOffline();

    const result = await h.resolver.resolve(REF);

    expect(result).toMatchObject({ valid: false, value: 1, warnings: [FO2] });
  });

  it('FO-2: 同意されなければ元の取得エラーを伝播する', async () => {
    const h = harness({ token: VALID_TOKEN, consent: false });
    await h.resolver.resolve(REF);
    h.goOffline();

    await expect(h.resolver.resolve(REF)).rejects.toThrow(BOOM);
    expect(h.records[0]).toMatchObject({ policy_event: 'FO-2', user_consent: 'rejected' });
  });
});

describe('Fail-open の成立条件: 同意手段と監査記録先の両方が要る', () => {
  it('同意コールバックが無ければ Fail-open せず元の失敗を伝播する（rejected を記録）', async () => {
    const h = harness({ token: VALID_TOKEN, startOffline: true });

    await expect(h.resolver.resolve(REF)).rejects.toThrow(BOOM);
    expect(h.records[0]?.user_consent).toBe('rejected');
  });

  it('監査記録先が無ければ、同意が true でも Fail-open せず元の失敗を伝播する（同意も求めない）', async () => {
    const h = harness({ token: VALID_TOKEN, consent: true, audit: false, startOffline: true });

    await expect(h.resolver.resolve(REF)).rejects.toThrow(BOOM);
    expect(h.decisions).toEqual([]);
  });

  it('FO-2 も監査記録先が無ければ stale な Token で通過しない', async () => {
    const h = harness({ token: VALID_TOKEN, consent: true, audit: false });
    await h.resolver.resolve(REF);
    h.goOffline();

    await expect(h.resolver.resolve(REF)).rejects.toThrow(BOOM);
  });
});

describe('opt-in（Override）', () => {
  it.each([
    ['FO-1', true],
    ['FO-2', false],
  ] as const)('escalate: ["%s"] は同意と監査記録先があっても Fail-closed（元の失敗を伝播し記録しない）', async (id, cold) => {
    const h = harness({
      token: VALID_TOKEN,
      consent: true,
      policy: { escalate: [id] },
      startOffline: cold,
    });
    if (!cold) {
      await h.resolver.resolve(REF);
      h.goOffline();
    }

    await expect(h.resolver.resolve(REF)).rejects.toThrow(BOOM);
    expect(h.decisions).toEqual([]);
    expect(h.records).toEqual([]);
  });

  it('escalate に挙げない側（FO-2 のみ escalate のとき FO-1）は既定の Fail-open のまま', async () => {
    const h = harness({
      token: VALID_TOKEN,
      consent: true,
      policy: { escalate: ['FO-2'] },
      startOffline: true,
    });

    expect((await h.resolver.resolve(REF)).warnings).toEqual([FO1]);
  });

  it('suppressPrompt: ["FO-1"] は同意コールバック無しで通過し、同意を呼ばず accepted を記録する', async () => {
    const h = harness({
      token: VALID_TOKEN,
      policy: { suppressPrompt: ['FO-1'] },
      startOffline: true,
    });

    expect((await h.resolver.resolve(REF)).warnings).toEqual([FO1]);
    expect(h.decisions).toEqual([]);
    expect(h.records[0]).toMatchObject({ user_consent: 'accepted' });
  });
});

describe('取得失敗以外（検証失敗）は同意があっても Fail-open しない', () => {
  it('別の鍵で署名された Token（取得は成功）は 3010 で拒否され、Fail-open の判定自体が起きない', async () => {
    const h = harness({ token: FORGED_TOKEN, consent: true, withCache: false });

    const error = await h.resolver.resolve(REF).catch((e: unknown) => e);

    expect((error as VericertsError).code).toBe(ErrorCodes.SIG_INVALID);
    expect(h.decisions).toEqual([]);
    expect(h.records).toEqual([]);
  });
});
