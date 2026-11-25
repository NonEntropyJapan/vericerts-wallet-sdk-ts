/**
 * `receiveCredentialViaAuthorizationCode` の入口検査・fail-closed・プロトタイプ汚染耐性。
 *
 * オーケストレータは呼び出し側から署名鍵・ブラウザ起動関数・エンドポイントを受け取り、
 * それらは `JSON.parse` を通らないため `parse-json.ts` のパース境界が効かない。読み取り時点の
 * 判定が唯一の防御線であり、その判定が実際に効くことを固定する。
 * あわせて「落ちるときは HTTP を出さない」ことを呼び出し記録の空で確認する。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, type VericertsError } from '../../../../errors.js';
import { receiveCredentialViaAuthorizationCode } from '../receive.js';
import type { AuthorizationCodeFlowDeps } from '../types.js';

/** `readonly` を外した可変版（`delete` で必須フィールドを落として fail-closed を確かめるため）。 */
type MutableDeps = {
  -readonly [K in keyof AuthorizationCodeFlowDeps]?: AuthorizationCodeFlowDeps[K];
};

import {
  AS,
  createHappyStub,
  flowDeps,
  flowOptions,
  PAR_URL,
  type StubFetch,
  TOKEN_URL,
} from './flow-fixtures.js';

async function expectFailure(
  promise: Promise<unknown>,
  code: ErrorCode,
  reason?: string,
): Promise<VericertsError> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    const error = err as VericertsError;
    expect(error.code).toBe(code);
    if (reason !== undefined) {
      expect(error.context).toMatchObject({ reason });
    }
    return error;
  }
}

describe('receiveCredentialViaAuthorizationCode: 認可リダイレクトの検査', () => {
  it('state 不一致は 8010 で落ち、Token Request は 1 度も飛ばない', async () => {
    const stub = createHappyStub();
    const deps = flowDeps(stub, {
      authorize: async () => ({ code: 'authz-code-value', state: 'attacker-state' }),
    });

    await expectFailure(
      receiveCredentialViaAuthorizationCode(flowOptions(), deps),
      ErrorCodes.TOKEN_REQUEST_FAILED,
      'state_mismatch',
    );
    // 認可コードを使わずに落とす（CSRF 経路で受けたコードを交換しない）。
    expect(stub.callTo(TOKEN_URL)).toBeUndefined();
  });

  it('authorize が例外を投げた場合（ユーザー拒否・期限切れ）は 8010', async () => {
    const stub = createHappyStub();
    const deps = flowDeps(stub, {
      authorize: async () => {
        throw new Error('user cancelled');
      },
    });
    const error = await expectFailure(
      receiveCredentialViaAuthorizationCode(flowOptions(), deps),
      ErrorCodes.TOKEN_REQUEST_FAILED,
      'authorization_failed',
    );
    // 呼び出し側の例外詳細を漏らさない。
    expect(error.cause).toBeUndefined();
    expect(JSON.stringify(error.context)).not.toContain('user cancelled');
  });

  it('code を持たないリダイレクト値は 8010', async () => {
    const stub = createHappyStub();
    const deps = flowDeps(stub, {
      authorize: async () =>
        ({ state: stub.formTo(PAR_URL)?.get('state') ?? '' }) as unknown as {
          code: string;
          state: string;
        },
    });
    await expectFailure(
      receiveCredentialViaAuthorizationCode(flowOptions(), deps),
      ErrorCodes.TOKEN_REQUEST_FAILED,
      'invalid_authorization_redirect',
    );
  });

  it('リダイレクト値が object でなければ 8010', async () => {
    const stub = createHappyStub();
    const deps = flowDeps(stub, {
      authorize: async () => 'authz-code-value' as unknown as { code: string; state: string },
    });
    await expectFailure(
      receiveCredentialViaAuthorizationCode(flowOptions(), deps),
      ErrorCodes.TOKEN_REQUEST_FAILED,
      'invalid_authorization_redirect',
    );
  });

  it('Object.prototype.code の汚染値を認可コードとして採用しない', async () => {
    Object.defineProperty(Object.prototype, 'code', {
      configurable: true,
      value: 'attacker-code',
    });
    try {
      const stub = createHappyStub();
      const deps = flowDeps(stub, {
        // `code` を持たない戻り値。鎖読みなら汚染値を拾って Token Request が成立してしまう。
        authorize: async () =>
          ({ state: stub.formTo(PAR_URL)?.get('state') ?? '' }) as unknown as {
            code: string;
            state: string;
          },
      });
      await expectFailure(
        receiveCredentialViaAuthorizationCode(flowOptions(), deps),
        ErrorCodes.TOKEN_REQUEST_FAILED,
        'invalid_authorization_redirect',
      );
      expect(stub.callTo(TOKEN_URL)).toBeUndefined();
    } finally {
      delete (Object.prototype as unknown as Record<string, unknown>).code;
    }
  });

  const redirectWithIss = (stub: StubFetch, iss: unknown) => async () =>
    ({ code: 'authz-code-value', state: stub.formTo(PAR_URL)?.get('state') ?? '', iss }) as {
      code: string;
      state: string;
    };

  it('iss（RFC 9207）が authorizationServerIssuer と不一致なら 8010 で、Token Request は 1 度も飛ばない', async () => {
    for (const iss of ['https://honest-as.example', `${AS}/`, 'HTTPS://AS.EXAMPLE.COM', 42]) {
      const stub = createHappyStub();
      const deps = flowDeps(stub, { authorize: redirectWithIss(stub, iss) });
      await expectFailure(
        receiveCredentialViaAuthorizationCode(flowOptions(), deps),
        ErrorCodes.TOKEN_REQUEST_FAILED,
        'iss_mismatch',
      );
      expect(stub.callTo(TOKEN_URL)).toBeUndefined();
    }
  });

  it('iss が無い認可応答は fail-closed（AS が RFC 9207 未対応でも Token Request を送らない）', async () => {
    const stub = createHappyStub();
    const deps = flowDeps(stub, { authorize: redirectWithIss(stub, undefined) });
    await expectFailure(
      receiveCredentialViaAuthorizationCode(flowOptions(), deps),
      ErrorCodes.TOKEN_REQUEST_FAILED,
      'iss_missing',
    );
    expect(stub.callTo(TOKEN_URL)).toBeUndefined();
  });

  it('Object.prototype.iss の汚染値を iss として採用しない', async () => {
    Object.defineProperty(Object.prototype, 'iss', { configurable: true, value: AS });
    try {
      const stub = createHappyStub();
      const deps = flowDeps(stub, { authorize: redirectWithIss(stub, undefined) });
      // `iss` を持たない戻り値。鎖読みなら汚染値が正しい発行元に見えてしまう。
      await expectFailure(
        receiveCredentialViaAuthorizationCode(flowOptions(), {
          ...deps,
          authorize: async () =>
            ({ code: 'authz-code-value', state: stub.formTo(PAR_URL)?.get('state') ?? '' }) as {
              code: string;
              state: string;
            },
        }),
        ErrorCodes.TOKEN_REQUEST_FAILED,
        'iss_missing',
      );
      expect(stub.callTo(TOKEN_URL)).toBeUndefined();
    } finally {
      delete (Object.prototype as unknown as Record<string, unknown>).iss;
    }
  });
});

describe('receiveCredentialViaAuthorizationCode: 依存の検査', () => {
  it('authorize 未指定は 8010 で落ち、HTTP を 1 度も出さない', async () => {
    const stub = createHappyStub();
    const deps = { ...flowDeps(stub) } as MutableDeps;
    delete deps.authorize;

    await expectFailure(
      receiveCredentialViaAuthorizationCode(flowOptions(), deps as AuthorizationCodeFlowDeps),
      ErrorCodes.TOKEN_REQUEST_FAILED,
      'missing_authorize',
    );
    // 「認可をスキップする」と解釈せず、PAR も送らない。
    expect(stub.calls).toHaveLength(0);
  });

  it('signer / holderDid / keyId の欠落は 8010', async () => {
    const stub = createHappyStub();
    for (const key of ['signer', 'holderDid', 'keyId'] as const) {
      const deps = { ...flowDeps(stub) } as MutableDeps;
      delete deps[key];
      await expectFailure(
        receiveCredentialViaAuthorizationCode(flowOptions(), deps as AuthorizationCodeFlowDeps),
        ErrorCodes.TOKEN_REQUEST_FAILED,
        'invalid_flow_deps',
      );
    }
    expect(stub.calls).toHaveLength(0);
  });

  it('prototype メソッドとして実装された authorize / fetchImpl も採用される（this を壊さない）', async () => {
    const stub = createHappyStub();
    const base = flowDeps(stub);
    class Deps {
      readonly signer = base.signer;
      readonly holderDid = base.holderDid;
      readonly keyId = base.keyId;
      authorizeCalls = 0;
      async authorize(_url: string): Promise<{ code: string; state: string; iss: string }> {
        // `this` 参照が壊れていればここで例外になる。
        this.authorizeCalls += 1;
        return {
          code: 'authz-code-value',
          state: stub.formTo(PAR_URL)?.get('state') ?? '',
          iss: AS,
        };
      }
      fetchImpl = stub.fetchImpl;
    }
    const deps = new Deps();
    const result = await receiveCredentialViaAuthorizationCode(flowOptions(), deps);
    expect(result.status).toBe('issued');
    expect(deps.authorizeCalls).toBe(1);
  });

  it('Object.prototype.fetchImpl の汚染値を掴まない', async () => {
    let polluted = false;
    Object.defineProperty(Object.prototype, 'fetchImpl', {
      configurable: true,
      get() {
        polluted = true;
        return async () => new Response('{}', { status: 200 });
      },
    });
    try {
      const stub = createHappyStub();
      const deps = { ...flowDeps(stub) } as MutableDeps;
      delete deps.fetchImpl;
      // 非 HTTPS の PAR エンドポイントで PAR プリミティブが fetch 前に落ちる。汚染値が
      // 採用されていれば、そこに至る前に攻撃者の fetch が呼ばれてしまう。
      await expectFailure(
        receiveCredentialViaAuthorizationCode(
          flowOptions({
            endpoints: { ...flowOptions().endpoints, parEndpoint: 'http://as.example.com/par' },
          }),
          deps as AuthorizationCodeFlowDeps,
        ),
        ErrorCodes.TOKEN_REQUEST_FAILED,
      );
      expect(polluted).toBe(false);
    } finally {
      delete (Object.prototype as unknown as Record<string, unknown>).fetchImpl;
    }
  });
});
