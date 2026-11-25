/**
 * `createStatusListResolver` の FO-1（Status List URL 到達不能）Fail-open 経路の回帰テスト。
 *
 * FO-1 の取得失敗時の判断と、その上書き・監査を検証する。
 * fail-secure を選んだ場合に従来どおり throw することの担保を含む。
 *
 * 検証内容:
 * - override / 同意コールバック無しでは従来どおり取得エラーを伝播する（既定は fail-secure）。
 * - `escalate: ['FO-1']` で Fail-closed に固定できる。
 * - `suppressPrompt` / 同意 true で警告付き通過し、監査ログに `accepted` が残る。
 * - 同意 false では throw し、監査ログに `rejected` が残る。
 * - Fail-open は 60 秒で失効し、署名検証まで通った取得成功でだけウィンドウが破棄される。
 * - Fail-open の結果を `evaluateStatusEntry` が受理する（valid とビット値が矛盾しない）。
 */

import { describe, expect, it } from 'bun:test';
import type { StatusReference } from '../../../credential/sdjwt/sdjwt.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import type { FailSafeAuditRecord } from '../../../failsafe/index.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import {
  createStatusListResolver,
  type StatusListResolverOptions,
} from '../../status-list-resolver.js';
import { evaluateStatusEntry } from '../../status-list-verifier.js';
import { StatusListManager } from '../../token-status-list.js';

const URI = 'https://issuer.example/status/1';

/** 取得が必ず失敗するため署名検証には到達しない。形式だけ満たすダミー鍵。 */
const DUMMY_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};

/** 署名検証を通る本物の Status List Token（取得成功の判定に使う）。 */
const ISSUER_KEY = new Uint8Array(32).fill(7);
const SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const ISSUER_PUB = getP256PublicKey(ISSUER_KEY, false);
const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const ISSUER_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: b64u(ISSUER_PUB.subarray(1, 33)),
  y: b64u(ISSUER_PUB.subarray(33, 65)),
};
const MANAGER = new StatusListManager({
  uri: URI,
  issuer: 'did:web:issuer.example',
  size: 100,
  bits: 1,
});
const VALID_TOKEN = await MANAGER.issueToken(SIGNER, { iatSeconds: 1_000 });

const REF: StatusReference = { status_list: { idx: 3, uri: URI } };

/** 常に失敗する fetchToken と、その呼び出し回数を返す。 */
function failingFetcher(error: Error): {
  fetchToken: (uri: string) => Promise<string>;
  calls: () => number;
} {
  let calls = 0;
  return {
    fetchToken: async () => {
      calls += 1;
      throw error;
    },
    calls: () => calls,
  };
}

/** 記録された監査レコードを溜める sink を作る。 */
function auditSink(): {
  records: FailSafeAuditRecord[];
  onPolicyEvent: (r: FailSafeAuditRecord) => void;
} {
  const records: FailSafeAuditRecord[] = [];
  return { records, onPolicyEvent: (r) => records.push(r) };
}

/** ダミー鍵・revocation 用途の resolver を作る。 */
function resolverWith(
  overrides: Omit<StatusListResolverOptions, 'issuerPublicKey' | 'purpose'>,
): ReturnType<typeof createStatusListResolver> {
  return createStatusListResolver({
    issuerPublicKey: DUMMY_JWK,
    purpose: 'revocation',
    ...overrides,
  });
}

describe('FO-1 Fail-open（Status List 取得失敗）', () => {
  it('override も同意コールバックも無ければ従来どおり取得エラーを伝播する（fail-secure 回帰）', async () => {
    const boom = new Error('network unreachable');
    const fetcher = failingFetcher(boom);
    const resolver = resolverWith({ fetchToken: fetcher.fetchToken });

    await expect(resolver.resolve(REF)).rejects.toThrow(boom);
    expect(fetcher.calls()).toBe(1);
  });

  it('同意コールバックが無い場合は監査ログに rejected を残して throw する', async () => {
    const boom = new Error('network unreachable');
    const sink = auditSink();
    const resolver = resolverWith({
      fetchToken: failingFetcher(boom).fetchToken,
      onPolicyEvent: sink.onPolicyEvent,
    });

    await expect(resolver.resolve(REF)).rejects.toThrow(boom);
    expect(sink.records[0]?.user_consent).toBe('rejected');
  });

  it('escalate: ["FO-1"] なら元の取得エラーを throw し、accepted の監査記録は出ない', async () => {
    const boom = new Error('network unreachable');
    const sink = auditSink();
    const resolver = resolverWith({
      fetchToken: failingFetcher(boom).fetchToken,
      failSafePolicy: { escalate: ['FO-1'] },
      requestConsent: () => true,
      onPolicyEvent: sink.onPolicyEvent,
    });

    await expect(resolver.resolve(REF)).rejects.toThrow(boom);
    expect(sink.records).toEqual([]);
  });

  it('suppressPrompt: ["FO-1"] なら警告付きで通過し、accepted が監査記録される', async () => {
    const sink = auditSink();
    const resolver = resolverWith({
      fetchToken: failingFetcher(new Error('network unreachable')).fetchToken,
      failSafePolicy: { suppressPrompt: ['FO-1'] },
      onPolicyEvent: sink.onPolicyEvent,
    });

    expect(await resolver.resolve(REF)).toEqual({
      valid: true,
      purpose: 'revocation',
      value: 0,
      warnings: [{ policyEvent: 'FO-1', auditEvent: 'status_check_unreachable' }],
    });
    expect(sink.records).toHaveLength(1);
    expect(sink.records[0]?.policy_event).toBe('FO-1');
    expect(sink.records[0]?.audit_event).toBe('status_check_unreachable');
    expect(sink.records[0]?.user_consent).toBe('accepted');
    expect(sink.records[0]?.override).toEqual({ suppressPrompt: ['FO-1'] });
  });

  it('requestConsent が同意すれば警告付きで通過する', async () => {
    const sink = auditSink();
    const resolver = resolverWith({
      fetchToken: failingFetcher(new Error('network unreachable')).fetchToken,
      failSafePolicy: {},
      requestConsent: (decision) => decision.policyEvent === 'FO-1' && decision.severity === 'warn',
      onPolicyEvent: sink.onPolicyEvent,
    });

    const result = await resolver.resolve(REF);
    expect(result.valid).toBe(true);
    expect(result.warnings).toEqual([
      { policyEvent: 'FO-1', auditEvent: 'status_check_unreachable' },
    ]);
    expect(sink.records[0]?.user_consent).toBe('accepted');
  });

  it('requestConsent が拒否すれば throw し、rejected が監査記録される', async () => {
    const boom = new Error('network unreachable');
    const sink = auditSink();
    const resolver = resolverWith({
      fetchToken: failingFetcher(boom).fetchToken,
      requestConsent: () => false,
      onPolicyEvent: sink.onPolicyEvent,
    });

    await expect(resolver.resolve(REF)).rejects.toThrow(boom);
    expect(sink.records[0]?.user_consent).toBe('rejected');
  });

  it('Fail-open は既定 60 秒で失効し、超過後は取得成功まで throw し続ける', async () => {
    const boom = new Error('network unreachable');
    let now = 1_000;
    const resolver = resolverWith({
      fetchToken: failingFetcher(boom).fetchToken,
      failSafePolicy: { suppressPrompt: ['FO-1'] },
      onPolicyEvent: auditSink().onPolicyEvent,
      nowSeconds: () => now,
    });

    expect((await resolver.resolve(REF)).valid).toBe(true);
    now = 1_060;
    expect((await resolver.resolve(REF)).valid).toBe(true);
    now = 1_061;
    await expect(resolver.resolve(REF)).rejects.toThrow(boom);
    // ウィンドウの破棄条件は取得成功のみ。失敗が続く限り新しいウィンドウは開かない。
    await expect(resolver.resolve(REF)).rejects.toThrow(boom);
    now = 2_000;
    await expect(resolver.resolve(REF)).rejects.toThrow(boom);
  });

  it('failOpenMaxSeconds で時間上限を短縮できる', async () => {
    const boom = new Error('network unreachable');
    let now = 1_000;
    const resolver = resolverWith({
      fetchToken: failingFetcher(boom).fetchToken,
      failSafePolicy: { suppressPrompt: ['FO-1'] },
      failOpenMaxSeconds: 5,
      onPolicyEvent: auditSink().onPolicyEvent,
      nowSeconds: () => now,
    });

    expect((await resolver.resolve(REF)).valid).toBe(true);
    now = 1_006;
    await expect(resolver.resolve(REF)).rejects.toThrow(boom);
  });

  it('検証できない応答（200 の HTML 等）ではウィンドウが巻き戻らず、60 秒上限が効き続ける', async () => {
    const boom = new Error('network unreachable');
    let now = 1_000;
    let junk = false;
    const resolver = resolverWith({
      fetchToken: async () => {
        if (junk) {
          return '<html>captive portal</html>';
        }
        throw boom;
      },
      failSafePolicy: { suppressPrompt: ['FO-1'] },
      onPolicyEvent: auditSink().onPolicyEvent,
      nowSeconds: () => now,
    });

    // t=1000 で Fail-open のウィンドウが開始する。
    expect((await resolver.resolve(REF)).valid).toBe(true);

    // 上限超過後に検証不能な 200 応答を挟んでも、取得成功とは見なさずウィンドウを巻き戻さない。
    now = 1_061;
    await expect(resolver.resolve(REF)).rejects.toThrow(boom);
    junk = true;
    now = 1_062;
    await expect(resolver.resolve(REF)).rejects.toThrow();
    junk = false;
    now = 1_063;
    await expect(resolver.resolve(REF)).rejects.toThrow(boom);
  });

  it('署名検証まで通った取得成功でウィンドウが破棄され、次の失敗は新しい 60 秒から数え直す', async () => {
    const boom = new Error('network unreachable');
    let now = 1_000;
    let shouldFail = true;
    const resolver = createStatusListResolver({
      fetchToken: async () => {
        if (shouldFail) {
          throw boom;
        }
        return VALID_TOKEN;
      },
      issuerPublicKey: ISSUER_JWK,
      purpose: 'revocation',
      failSafePolicy: { suppressPrompt: ['FO-1'] },
      onPolicyEvent: auditSink().onPolicyEvent,
      nowSeconds: () => now,
    });
    const ref = MANAGER.reference(MANAGER.allocate());

    // t=1000 で Fail-open のウィンドウが開始する。
    expect((await resolver.resolve(ref)).valid).toBe(true);

    // t=1010 の取得成功（署名検証済み）でウィンドウを破棄する。
    shouldFail = false;
    now = 1_010;
    expect((await resolver.resolve(ref)).valid).toBe(true);

    // 破棄済みなので t=1070（最初の開始から 70 秒後）でも新しいウィンドウとして許可される。
    shouldFail = true;
    now = 1_070;
    expect((await resolver.resolve(ref)).valid).toBe(true);
    // 新しいウィンドウも 60 秒で閉じる。
    now = 1_131;
    await expect(resolver.resolve(ref)).rejects.toThrow(boom);
  });

  it('監査レコードに auditContext が透過され、URI は含まれない', async () => {
    const sink = auditSink();
    const resolver = resolverWith({
      fetchToken: failingFetcher(new Error('network unreachable')).fetchToken,
      failSafePolicy: { suppressPrompt: ['FO-1'] },
      onPolicyEvent: sink.onPolicyEvent,
      auditContext: { verifier: 'sha256:rp', vc_id: 'vc-1', trace_id: 'trace-1' },
    });

    await resolver.resolve(REF);
    expect(sink.records[0]?.verifier).toBe('sha256:rp');
    expect(sink.records[0]?.vc_id).toBe('vc-1');
    expect(sink.records[0]?.trace_id).toBe('trace-1');
    expect(JSON.stringify(sink.records[0])).not.toContain(URI);
  });

  it('Fail-open の結果を evaluateStatusEntry が valid として受理する（3002 にならない）', async () => {
    const resolver = resolverWith({
      fetchToken: failingFetcher(new Error('network unreachable')).fetchToken,
      failSafePolicy: { suppressPrompt: ['FO-1'] },
      onPolicyEvent: auditSink().onPolicyEvent,
    });

    expect(evaluateStatusEntry(await resolver.resolve(REF))).toBe('valid');
  });
});
