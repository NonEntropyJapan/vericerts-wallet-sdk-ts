// test/interop/__tests__/sd-jwt/run-waltid-sdjwt.test.mjs
//
// test/interop/run-waltid-sdjwt.mjs のプロトコル分岐の回帰テスト。
// walt.id への実 HTTP 呼び出しはすべてモックし、Offer→Receive→Present の成否振り分け・
// walt.id 未起動 / タイムアウトが pass に見えないこと・公開ホスト検査での `skipped` を単体で検証する。
//
// 実行には Bun が必要（ドライバは Bun の TLS と `import.meta.main` を使う）:
//   bun test test/interop/__tests__/sd-jwt/run-waltid-sdjwt.test.mjs

import { describe, expect, it } from 'bun:test';
import { run } from '../../run-waltid-sdjwt.mjs';
import {
  ADVERTISED_VCT,
  deps,
  LOOPBACK_RESPONSE_URI_REQUEST,
  PAIR_ISSUE,
  PAIR_PRESENT,
} from './fixtures.mjs';

describe('run: SD-JWT の Offer→Receive→Present の成否振り分け', () => {
  it('Receive も提示検証も成功したら両ペアとも pass', async () => {
    const output = await run(deps());
    expect(output.results).toEqual([
      { pair: PAIR_ISSUE, status: 'pass' },
      { pair: PAIR_PRESENT, status: 'pass' },
    ]);
    expect(output.generator).toBe('test/interop/run-waltid-sdjwt.mjs');
    expect(typeof output.generatedAt).toBe('string');
  });

  it('Offer 発行が失敗したら 1 ペア目は fail、2 ペア目も「提示する VC が無い」fail にし、Present 系依存を呼ばない', async () => {
    let presentCalled = false;
    const output = await run(
      deps({
        createIssuerOfferImpl: async () => {
          throw new Error('offer failed: waltid unreachable');
        },
        createVerifierRequestImpl: async () => {
          presentCalled = true;
          throw new Error('should not be called');
        },
      }),
    );
    expect(output.results).toEqual([
      { pair: PAIR_ISSUE, status: 'fail', reason: 'offer failed: waltid unreachable' },
      {
        pair: PAIR_PRESENT,
        status: 'fail',
        reason: 'skipped: Offer → Receive が先に失敗し提示する SD-JWT VC が無い',
        // レポートの処理側で同根と判別できるよう、先行ペアを記録する。
        causedBy: PAIR_ISSUE,
      },
    ]);
    expect(presentCalled).toBe(false);
  });

  it('受領した SD-JWT の検証（verifySdJwt）が失敗したら 1 ペア目は fail（受け取れただけでは pass にしない）', async () => {
    const output = await run(
      deps({
        receiveCredentialImpl: async (_offerUri, options) => {
          options.verifyReceived('issuer.jwt.sd~disclosure~');
          return { raw: 'issuer.jwt.sd~disclosure~' };
        },
        verifySdJwtImpl: () => {
          throw new Error('3010: SD-JWT の署名検証に失敗しました');
        },
      }),
    );
    expect(output.results[0]).toEqual({
      pair: PAIR_ISSUE,
      status: 'fail',
      reason: '3010: SD-JWT の署名検証に失敗しました',
    });
    expect(output.results[1].status).toBe('fail');
  });

  it('提示検証が verified: false なら 2 ペア目だけ理由付きで fail（提示側の非互換を検知する）', async () => {
    const output = await run(
      deps({
        pollVerifierSessionImpl: async () => ({
          verified: false,
          reason: '{"presentation-definition":"path $.family_name did not match"}',
        }),
      }),
    );
    expect(output.results).toEqual([
      { pair: PAIR_ISSUE, status: 'pass' },
      {
        pair: PAIR_PRESENT,
        status: 'fail',
        reason: '{"presentation-definition":"path $.family_name did not match"}',
      },
    ]);
  });

  it('verified: false に理由が無くても fail の理由を必ず付ける', async () => {
    const output = await run(deps({ pollVerifierSessionImpl: async () => ({ verified: false }) }));
    expect(output.results[1]).toEqual({
      pair: PAIR_PRESENT,
      status: 'fail',
      reason: '検証が verified=false を返した',
    });
  });

  it('提示の送信が失敗したら 1 ペア目は pass のまま 2 ペア目だけ fail（HTTP ステータスを理由に添える）', async () => {
    const output = await run(
      deps({
        fetchImpl: async () => ({ ok: false, status: 400, text: async () => 'bad request' }),
        submitPresentationImpl: async (_request, _vpToken, options) => {
          await options.fetchImpl('https://verifier.example.test/present', { method: 'POST' });
          throw new Error('VP Token の送信に失敗しました');
        },
      }),
    );
    expect(output.results[0]).toEqual({ pair: PAIR_ISSUE, status: 'pass' });
    expect(output.results[1]).toEqual({
      pair: PAIR_PRESENT,
      status: 'fail',
      reason: 'VP Token の送信に失敗しました (HTTP 400)',
    });
  });
});

describe('run: walt.id 未起動・タイムアウトは pass にも skipped にもしない', () => {
  it('issuer が未起動（接続拒否）なら fail で、skipped にはしない', async () => {
    const output = await run(
      deps({
        createIssuerOfferImpl: async () => {
          throw new Error('fetch failed / cause: ECONNREFUSED');
        },
      }),
    );
    expect(output.results.map((r) => r.status)).toEqual(['fail', 'fail']);
    expect(output.results[0].reason).toContain('ECONNREFUSED');
  });

  it('verifier がセッション結果を返さないまま時間切れになったら fail', async () => {
    const output = await run(
      deps({
        pollVerifierSessionImpl: async () => ({
          verified: false,
          reason: 'verifier session did not report a result in time',
        }),
      }),
    );
    expect(output.results[1]).toEqual({
      pair: PAIR_PRESENT,
      status: 'fail',
      reason: 'verifier session did not report a result in time',
    });
  });

  it('提示の送信がタイムアウト（AbortError）しても fail で、pass・skipped にはならない', async () => {
    const output = await run(
      deps({
        submitPresentationImpl: async () => {
          const error = new Error('The operation was aborted due to timeout');
          error.name = 'TimeoutError';
          throw error;
        },
      }),
    );
    expect(output.results[1].status).toBe('fail');
    expect(output.results[1].reason).toContain('timeout');
  });
});

describe('run: 公開ホスト検査で拒否された場合だけ skipped', () => {
  it('response_uri が公開ホスト検査で拒否されたら 2 ペア目だけ skipped（1 ペア目は pass のまま）', async () => {
    const output = await run(
      deps({
        createVerifierRequestImpl: async () => LOOPBACK_RESPONSE_URI_REQUEST,
      }),
    );
    expect(output.results[0]).toEqual({ pair: PAIR_ISSUE, status: 'pass' });
    expect(output.results[1].status).toBe('skipped');
    expect(output.results[1].reason).toContain('non_public_response_uri');
  });
});

describe('run: ペア名の接尾辞（新版検知 job が pinned 側と結果を混ぜないための仕組み）', () => {
  it('pairSuffix を渡すと両ペア名の末尾に付く', async () => {
    const output = await run(deps({ pairSuffix: ':next' }));
    expect(output.results.map((r) => r.pair)).toEqual([
      `${PAIR_ISSUE}:next`,
      `${PAIR_PRESENT}:next`,
    ]);
  });

  it('接尾辞は失敗経路（Offer 発行の失敗）でも付く', async () => {
    const output = await run(
      deps({
        pairSuffix: ':next',
        createIssuerOfferImpl: async () => {
          throw new Error('boom');
        },
      }),
    );
    expect(output.results.map((r) => r.pair)).toEqual([
      `${PAIR_ISSUE}:next`,
      `${PAIR_PRESENT}:next`,
    ]);
  });
});

describe('run: knownIncompatible の分類は他のランナーと同じ規則を通る', () => {
  const entry = {
    pair: PAIR_PRESENT,
    issue: 1,
    reasonIncludes: 'JSONPath',
    note: 'walt.id の SD-JWT 解析が JSONPath 非対応',
  };

  it('登録どおりの理由で fail したペアは known-incompatible になる', async () => {
    const output = await run(
      deps({
        knownIncompatible: [entry],
        pollVerifierSessionImpl: async () => ({ verified: false, reason: 'JSONPath unsupported' }),
      }),
    );
    expect(output.results[1].status).toBe('known-incompatible');
  });

  it('登録外の理由で fail したペアは fail のまま', async () => {
    const output = await run(
      deps({
        knownIncompatible: [entry],
        pollVerifierSessionImpl: async () => ({ verified: false, reason: 'signature invalid' }),
      }),
    );
    expect(output.results[1].status).toBe('fail');
  });

  it('登録ペアが pass したら unexpected-pass の fail にする', async () => {
    const output = await run(deps({ knownIncompatible: [entry] }));
    expect(output.results[1].status).toBe('fail');
    expect(output.results[1].reason).toContain('unexpected-pass');
  });
});

describe('run: SD-JWT の受領は dc+sd-jwt と告知 vct で要求する', () => {
  it('format は新識別子 dc+sd-jwt（旧 vc+sd-jwt は walt.id の format 突合で 400 になる）', async () => {
    const receivedOptions = [];
    await run(deps({}, receivedOptions));
    expect(receivedOptions).toHaveLength(1);
    expect(receivedOptions[0].format).toBe('dc+sd-jwt');
  });

  it('受領後の照合は walt.id が告知した vct で行う（pairs.json の固定値ではない）', async () => {
    const receivedOptions = [];
    const verified = [];
    // `verifyReceived` は本物の `receiveCredential` が呼ぶコールバックなので、
    // スタブ経由では呼ばれない。記録したものをテストから呼んで中身を見る。
    await run(deps({ verifySdJwtImpl: (_raw, opts) => verified.push(opts) }, receivedOptions));
    receivedOptions[0].verifyReceived('issuer.jwt.sd~disclosure~');
    expect(verified).toHaveLength(1);
    expect(verified[0].expectedVct).toBe(ADVERTISED_VCT);
  });
});
