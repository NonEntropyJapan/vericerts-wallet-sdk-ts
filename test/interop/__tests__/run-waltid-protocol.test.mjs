// test/interop/__tests__/run-waltid-protocol.test.mjs
//
// test/interop/run-waltid-protocol.mjs のプロトコル分岐処理の回帰テスト。
// walt.id issuer-api/verifier-api への実 HTTP 呼び出しはすべてモックし、レスポンス解釈・
// リトライ・タイムアウト・Offer→Receive→Present の成否振り分けを単体で検証する
// （実ピアとの通信は `docker compose -f test/interop/docker-compose.yml up -d` 済みの環境でのみ
// 動く `run()` 本体を、モックした依存の注入で置き換える。実行には Bun が必要
// （ドライバは Bun の TLS と `import.meta.main` を使う）: `bun test test/interop/__tests__/run-waltid-protocol.test.mjs`。

import { describe, expect, it } from 'bun:test';
import {
  createIssuerOffer,
  createVerifierRequest,
  fetchJson,
  pollVerifierSession,
  run,
} from '../run-waltid-protocol.mjs';
import {
  describeAdminBaseUrlRequired,
  ISSUER_ENV,
  useWaltidAdminEnv,
  VERIFIER_ENV,
} from '../test-support/waltid-admin-env.mjs';
import {
  jsonResponse,
  sequenceFetch,
  VALID_REQUEST_URI,
} from '../test-support/waltid-protocol-stubs.mjs';

// 実 `createIssuerOffer` / `createVerifierRequest` / `pollVerifierSession` は URL の既定値を持たず、
// 呼び出し時に env を読む。各テストで env を明示し、終わったら戻す。
useWaltidAdminEnv();

describe('fetchJson: レスポンス解釈', () => {
  it('JSON ボディはパースして返す', async () => {
    const result = await fetchJson(
      'https://example.test/api',
      undefined,
      sequenceFetch([jsonResponse({ hello: 'world' })]),
    );
    expect(result).toEqual({ ok: true, status: 200, body: { hello: 'world' } });
  });

  it('JSON としてパースできないボディはテキストのまま返す（walt.id の offer/request URI はプレーン文字列で返る）', async () => {
    const result = await fetchJson(
      'https://example.test/api',
      undefined,
      sequenceFetch([jsonResponse('openid-credential-offer://example')]),
    );
    expect(result).toEqual({
      ok: true,
      status: 200,
      body: 'openid-credential-offer://example',
    });
  });

  it('非 2xx はボディ解釈と独立して ok: false を返す', async () => {
    const result = await fetchJson(
      'https://example.test/api',
      undefined,
      sequenceFetch([jsonResponse({ error: 'boom' }, { ok: false, status: 500 })]),
    );
    expect(result.ok).toBe(false);
    expect(result.status).toBe(500);
  });
});

describe('createVerifierRequest: レスポンス解釈の分岐', () => {
  it('openid4vp:// で始まる文字列を返したら成功として request URI を返す', async () => {
    const requestUri = await createVerifierRequest(
      sequenceFetch([jsonResponse('openid4vp://authorize?state=abc')]),
    );
    expect(requestUri).toBe('openid4vp://authorize?state=abc');
  });

  it('非 ok レスポンスは投げる', async () => {
    await expect(
      createVerifierRequest(sequenceFetch([jsonResponse({ error: 'bad' }, { ok: false })])),
    ).rejects.toThrow('waltid-verifier request creation failed');
  });

  it('プレフィックスの合わない文字列は投げる（walt.id 側のレスポンス形式変化を検知する）', async () => {
    await expect(
      createVerifierRequest(sequenceFetch([jsonResponse('https://unexpected.example/')])),
    ).rejects.toThrow('waltid-verifier request creation failed');
  });

  it('JSON オブジェクトが返る（walt.id が文字列でなく構造化エラーを返す既知の形）と投げる', async () => {
    await expect(
      createVerifierRequest(sequenceFetch([jsonResponse({ message: 'unexpected shape' })])),
    ).rejects.toThrow('waltid-verifier request creation failed');
  });
});

describe('createIssuerOffer: レスポンス解釈の分岐', () => {
  it('openid-credential-offer:// で始まる文字列を返したら成功として offerUri と issuer 公開鍵を返す', async () => {
    const { offerUri, issuerPublicKeyJwk } = await createIssuerOffer(
      sequenceFetch([jsonResponse('openid-credential-offer://issue?x=1')]),
    );
    expect(offerUri).toBe('openid-credential-offer://issue?x=1');
    expect(issuerPublicKeyJwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
  });

  it('非 ok レスポンスは投げる', async () => {
    await expect(
      createIssuerOffer(sequenceFetch([jsonResponse({ error: 'bad' }, { ok: false })])),
    ).rejects.toThrow('waltid-issuer offer creation failed');
  });

  it('プレフィックスの合わない文字列は投げる', async () => {
    await expect(
      createIssuerOffer(sequenceFetch([jsonResponse('not-an-offer-uri')])),
    ).rejects.toThrow('waltid-issuer offer creation failed');
  });
});

describe('pollVerifierSession: リトライ・タイムアウト・レスポンス解釈', () => {
  it('verificationResult: true を返した時点で即座に verified: true を返す（リトライしない）', async () => {
    let calls = 0;
    const fetchImpl = async () => {
      calls += 1;
      return jsonResponse({ verificationResult: true });
    };
    const result = await pollVerifierSession(VALID_REQUEST_URI, { fetchImpl, intervalMs: 0 });
    expect(result).toEqual({ verified: true });
    expect(calls).toBe(1);
  });

  it('verificationResult: false は理由付きで verified: false を返す', async () => {
    const fetchImpl = sequenceFetch([
      jsonResponse({ verificationResult: false, policyResults: { reason: 'signature-invalid' } }),
    ]);
    const result = await pollVerifierSession(VALID_REQUEST_URI, { fetchImpl, intervalMs: 0 });
    expect(result.verified).toBe(false);
    expect(result.reason).toContain('signature-invalid');
  });

  it('保留中（verificationResult 未確定）の応答は maxAttempts に達するまでリトライする', async () => {
    let calls = 0;
    const fetchImpl = async () => {
      calls += 1;
      if (calls < 3) {
        return jsonResponse({ verificationResult: null });
      }
      return jsonResponse({ verificationResult: true });
    };
    const result = await pollVerifierSession(VALID_REQUEST_URI, {
      fetchImpl,
      intervalMs: 0,
      maxAttempts: 10,
    });
    expect(result).toEqual({ verified: true });
    expect(calls).toBe(3);
  });

  it('maxAttempts 回リトライしても確定しなければタイムアウト理由で verified: false を返す', async () => {
    let calls = 0;
    const fetchImpl = async () => {
      calls += 1;
      return jsonResponse({ verificationResult: null });
    };
    const result = await pollVerifierSession(VALID_REQUEST_URI, {
      fetchImpl,
      intervalMs: 0,
      maxAttempts: 3,
    });
    expect(result).toEqual({
      verified: false,
      reason: 'verifier session did not report a result in time',
    });
    expect(calls).toBe(3);
  });
});

describeAdminBaseUrlRequired([
  {
    name: 'createIssuerOffer',
    env: ISSUER_ENV,
    body: 'openid-credential-offer://issue?x=1',
    call: (f) => createIssuerOffer(f),
  },
  {
    name: 'createVerifierRequest',
    env: VERIFIER_ENV,
    body: 'openid4vp://authorize?state=abc',
    call: (f) => createVerifierRequest(f),
  },
  {
    name: 'pollVerifierSession',
    env: VERIFIER_ENV,
    body: { verificationResult: true },
    call: (f) => pollVerifierSession(VALID_REQUEST_URI, { fetchImpl: f, intervalMs: 0 }),
  },
]);

describe('run: Offer→Receive→Present の成否振り分け', () => {
  it('Offer 発行が失敗したら Offer→Receive を fail、Present を skipped 理由で fail にし Present 系依存を一切呼ばない', async () => {
    let presentCalled = false;
    const output = await run({
      createIssuerOfferImpl: async () => {
        throw new Error('offer failed: waltid unreachable');
      },
      createVerifierRequestImpl: async () => {
        presentCalled = true;
        throw new Error('should not be called');
      },
    });
    expect(output.results).toEqual([
      {
        pair: 'interop:waltid-issuer:vericerts',
        status: 'fail',
        reason: 'offer failed: waltid unreachable',
      },
      {
        pair: 'interop:vericerts:waltid-verifier',
        status: 'fail',
        reason: 'skipped: Offer → Receive が先に失敗した',
        // regression: 巻き添えだと起票側が見分けられるよう元のペアを持つ。
        // これが無いと verifier ペアが同根の重複 Issue として起票される。
        causedBy: 'interop:waltid-issuer:vericerts',
      },
    ]);
    expect(presentCalled).toBe(false);
  });

  it('Offer→Receive が成功し検証が verified: true の場合は両ペアとも pass', async () => {
    const output = await run({
      createIssuerOfferImpl: async () => ({
        offerUri: 'openid-credential-offer://fake',
        issuerPublicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'fake' },
      }),
      receiveCredentialImpl: async () => ({ raw: 'fake.jwt.vc' }),
      createVerifierRequestImpl: async () => VALID_REQUEST_URI,
      buildVPTokenImpl: () => 'fake-vp-token',
      submitPresentationImpl: async () => undefined,
      pollVerifierSessionImpl: async () => ({ verified: true }),
    });
    expect(output.results).toEqual([
      { pair: 'interop:waltid-issuer:vericerts', status: 'pass' },
      { pair: 'interop:vericerts:waltid-verifier', status: 'pass' },
    ]);
  });

  it('Present 検証が verified: false の場合は理由付きで fail', async () => {
    const output = await run({
      createIssuerOfferImpl: async () => ({
        offerUri: 'openid-credential-offer://fake',
        issuerPublicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'fake' },
      }),
      receiveCredentialImpl: async () => ({ raw: 'fake.jwt.vc' }),
      createVerifierRequestImpl: async () => VALID_REQUEST_URI,
      buildVPTokenImpl: () => 'fake-vp-token',
      submitPresentationImpl: async () => undefined,
      pollVerifierSessionImpl: async () => ({
        verified: false,
        reason: 'policy denied',
      }),
    });
    expect(output.results).toEqual([
      { pair: 'interop:waltid-issuer:vericerts', status: 'pass' },
      {
        pair: 'interop:vericerts:waltid-verifier',
        status: 'fail',
        reason: 'policy denied',
      },
    ]);
  });

  it('Present フェーズで例外（submitPresentation の通信失敗等）が起きたら Offer→Receive は pass のまま Present だけ fail', async () => {
    const output = await run({
      createIssuerOfferImpl: async () => ({
        offerUri: 'openid-credential-offer://fake',
        issuerPublicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'fake' },
      }),
      receiveCredentialImpl: async () => ({ raw: 'fake.jwt.vc' }),
      createVerifierRequestImpl: async () => VALID_REQUEST_URI,
      buildVPTokenImpl: () => 'fake-vp-token',
      submitPresentationImpl: async () => {
        throw new Error('waltid-verifier submit failed: network timeout');
      },
    });
    expect(output.results).toEqual([
      { pair: 'interop:waltid-issuer:vericerts', status: 'pass' },
      {
        pair: 'interop:vericerts:waltid-verifier',
        status: 'fail',
        reason: 'waltid-verifier submit failed: network timeout',
      },
    ]);
  });
});
