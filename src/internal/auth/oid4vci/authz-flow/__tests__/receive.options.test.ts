/**
 * `receiveCredentialViaAuthorizationCode` のオプション検査。
 *
 * `options` は呼び出し側が組み立てたオブジェクトで `JSON.parse` を通らないため、`parse-json.ts` の
 * パース境界が効かない。読み取り時点の own 限定判定が唯一の防御線であることと、
 * 落ちるときに HTTP を 1 度も出さないことを固定する。依存（`deps`）側の検査は
 * `receive.guards.test.ts` にある。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, type VericertsError } from '../../../../errors.js';
import { WUA_CLIENT_ASSERTION_TYPE } from '../../../../eudi/wua/types.js';
import { receiveCredentialViaAuthorizationCode } from '../receive.js';
import type { AuthorizationCodeFlowOptions } from '../types.js';
import { createHappyStub, flowDeps, flowOptions, PAR_URL, TOKEN_URL } from './flow-fixtures.js';

/** `readonly` を外した可変版（`delete` で必須フィールドを落として fail-closed を確かめるため）。 */
type MutableOptions = {
  -readonly [K in keyof AuthorizationCodeFlowOptions]?: AuthorizationCodeFlowOptions[K];
};

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

describe('receiveCredentialViaAuthorizationCode: オプションの検査', () => {
  it('4 エンドポイントのいずれが非 HTTPS でも fetch せずに 8010（non_https_endpoint）', async () => {
    // フロー側で 4 つとも無条件に HTTPS を要求する。下流へ委譲すると
    // `requestTokenAuthorizationCode` の HTTPS 検査が `clientAssertion` 指定時のみの条件付きで
    // あるため、`tokenEndpoint: 'http://…'` が素通りして認可コード・code_verifier・
    // access_token が平文で流れる。
    for (const key of [
      'parEndpoint',
      'authorizationEndpoint',
      'tokenEndpoint',
      'credentialEndpoint',
    ] as const) {
      const stub = createHappyStub();
      await expectFailure(
        receiveCredentialViaAuthorizationCode(
          flowOptions({
            endpoints: { ...flowOptions().endpoints, [key]: 'http://as.example.com/plain' },
          }),
          flowDeps(stub),
        ),
        ErrorCodes.TOKEN_REQUEST_FAILED,
        'non_https_endpoint',
      );
      expect(stub.calls).toHaveLength(0);
    }
  });

  it('clientAssertion の指定有無どちらでも非 HTTPS の tokenEndpoint は 8010（non_https_endpoint）', async () => {
    // フロー側の入口検査（`resolveEndpoints`）は `options.endpoints` だけを読み `clientAssertion`
    // を参照しないため、client 認証の指定有無に依存せず 4 エンドポイントすべてに効く。それを
    // `clientAssertion` 指定 / 未指定の両方で固定する。
    // なお下流 `requestTokenAuthorizationCode` の HTTPS 検査は `clientAssertion !== undefined` の
    // 条件付きにしか無いが、本テストは入口で 8010 に落ちて下流へ到達しない（`stub.calls` が 0 件）
    // ため、その条件付き検査の挙動は**本テストの観測範囲外**である。
    const clientAuthCases: readonly (readonly [string, Partial<AuthorizationCodeFlowOptions>])[] = [
      [
        'clientAssertion 指定',
        { clientAssertion: 'wua~wua-pop', clientAssertionType: WUA_CLIENT_ASSERTION_TYPE },
      ],
      ['clientAssertion 未指定', {}],
    ];
    for (const [label, clientAuth] of clientAuthCases) {
      const stub = createHappyStub();
      const options = flowOptions({
        ...clientAuth,
        endpoints: { ...flowOptions().endpoints, tokenEndpoint: 'http://as.example.com/token' },
      });
      // 前提: 既定フィクスチャは client_assertion を載せないため、2 ケースが実際に指定有無で
      // 分かれている（同じ入力を 2 回流していないことの確認）。
      expect(options.clientAssertion === undefined).toBe(label === 'clientAssertion 未指定');
      await expectFailure(
        receiveCredentialViaAuthorizationCode(options, flowDeps(stub)),
        ErrorCodes.TOKEN_REQUEST_FAILED,
        'non_https_endpoint',
      );
      expect(stub.calls).toHaveLength(0);
    }
  });

  it('空文字・空白のみのエンドポイントは 8010（invalid_endpoints）', async () => {
    const stub = createHappyStub();
    for (const key of [
      'parEndpoint',
      'authorizationEndpoint',
      'tokenEndpoint',
      'credentialEndpoint',
    ] as const) {
      await expectFailure(
        receiveCredentialViaAuthorizationCode(
          flowOptions({ endpoints: { ...flowOptions().endpoints, [key]: '  ' } }),
          flowDeps(stub),
        ),
        ErrorCodes.TOKEN_REQUEST_FAILED,
        'invalid_endpoints',
      );
    }
    expect(stub.calls).toHaveLength(0);
  });

  it('endpoints / clientId / redirectUri / format の欠落は 8010', async () => {
    const stub = createHappyStub();
    for (const [key, reason] of [
      ['endpoints', 'invalid_endpoints'],
      ['clientId', 'invalid_options'],
      ['redirectUri', 'invalid_options'],
      ['format', 'invalid_options'],
      ['credentialDefinition', 'invalid_options'],
    ] as const) {
      const options = { ...flowOptions() } as MutableOptions;
      delete options[key];
      await expectFailure(
        receiveCredentialViaAuthorizationCode(
          options as AuthorizationCodeFlowOptions,
          flowDeps(stub),
        ),
        ErrorCodes.TOKEN_REQUEST_FAILED,
        reason,
      );
    }
    expect(stub.calls).toHaveLength(0);
  });

  it('Object.prototype.redirectUri の汚染値を push しない', async () => {
    Object.defineProperty(Object.prototype, 'redirectUri', {
      configurable: true,
      value: 'https://attacker.example/cb',
    });
    try {
      const stub = createHappyStub();
      const options = { ...flowOptions() } as MutableOptions;
      delete options.redirectUri;
      // 鎖読みなら汚染値が「AS 登録済みのコールバック先」として PAR に載り、認可コードが
      // 攻撃者へ返る。own 限定読みなので「未指定」として fail-closed に落ちる。
      await expectFailure(
        receiveCredentialViaAuthorizationCode(
          options as AuthorizationCodeFlowOptions,
          flowDeps(stub),
        ),
        ErrorCodes.TOKEN_REQUEST_FAILED,
        'invalid_options',
      );
      expect(stub.calls).toHaveLength(0);
    } finally {
      delete (Object.prototype as unknown as Record<string, unknown>).redirectUri;
    }
  });

  it('Object.prototype.clientAssertion の汚染値を送出しない', async () => {
    Object.defineProperty(Object.prototype, 'clientAssertion', {
      configurable: true,
      value: 'attacker-assertion',
    });
    try {
      const stub = createHappyStub();
      await receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(stub));
      expect(stub.formTo(PAR_URL)?.get('client_assertion')).toBeNull();
      expect(stub.formTo(TOKEN_URL)?.get('client_assertion')).toBeNull();
    } finally {
      delete (Object.prototype as unknown as Record<string, unknown>).clientAssertion;
    }
  });
});
