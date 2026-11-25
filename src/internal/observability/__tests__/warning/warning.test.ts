/**
 * `emitWarning`（`onWarning`）の単体テスト。
 *
 * - 未指定なら何も起きない。
 * - 渡すエラーの中身は既存の PII マスキング（`maskLogAttributes`）を通っている。例外オブジェクトそのものは渡らない。
 * - 受け口が同期で投げても、Promise で拒否しても、呼び出し側（本処理）へ伝播しない。
 */

import { describe, expect, it } from 'bun:test';
import { runInNewContext } from 'node:vm';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { REDACTED } from '../../pii-mask.js';
import { emitWarning, type SdkWarning } from '../../warning.js';

const META = { code: 'test.warning', message: 'fixed message', component: 'sdk.wallet' } as const;

/** header・payload・signature の 3 部からなる JWT 形の文字列（payload に秘密めいた値を載せる）。 */
function jwtLike(payload: Record<string, unknown>): string {
  const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${b64({ alg: 'ES256' })}.${b64(payload)}.c2lnbmF0dXJl`;
}

describe('emitWarning', () => {
  it('onWarning が未指定なら何も起きない（例外も出さない）', () => {
    expect(() => emitWarning(undefined, META, new Error('boom'))).not.toThrow();
  });

  it('警告の種類・説明・出所と、失敗の名前・メッセージ・VericertsError のコードを渡す', () => {
    const received: SdkWarning[] = [];

    emitWarning(
      (warning) => received.push(warning),
      META,
      new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED),
    );

    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({
      code: 'test.warning',
      message: 'fixed message',
      component: 'sdk.wallet',
    });
    expect(received[0]?.attributes.error_name).toBe('VericertsError');
    expect(received[0]?.attributes.error_code).toBe(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  });

  it('渡すエラーの中身は既存のマスキングを通る（メッセージに載った JWT の payload は出ない）', () => {
    const received: SdkWarning[] = [];
    const secret = 'S3CR3T-SUBJECT-VALUE';

    emitWarning((warning) => received.push(warning), META, new Error(jwtLike({ sub: secret })));

    const message = received[0]?.attributes.error_message;
    expect(typeof message).toBe('string');
    expect(message).toContain(REDACTED);
    expect(JSON.stringify(received[0])).not.toContain(secret);
  });

  it('例外オブジェクトそのもの・cause・スタックは渡さない', () => {
    const received: SdkWarning[] = [];
    const error = new Error('outer', { cause: new Error('inner-secret-cause') });

    emitWarning((warning) => received.push(warning), META, error);

    const serialized = JSON.stringify(received[0]);
    expect(serialized).not.toContain('inner-secret-cause');
    expect(serialized).not.toContain('at ');
    expect(Object.keys(received[0]?.attributes ?? {}).sort()).toEqual([
      'error_message',
      'error_name',
    ]);
  });

  it('Error 以外が投げられても文字列にして渡す', () => {
    const received: SdkWarning[] = [];

    emitWarning((warning) => received.push(warning), META, 'plain string failure');

    expect(received[0]?.attributes).toEqual({ error_message: 'plain string failure' });
  });

  it('一般 Error の独自 code は SDK の error_code として通知しない', () => {
    const received: SdkWarning[] = [];
    const error = Object.assign(new Error('write failed'), { code: 'NON_SDK_CODE' });

    emitWarning((warning) => received.push(warning), META, error);

    expect(received[0]?.attributes).toEqual({ error_name: 'Error', error_message: 'write failed' });
  });

  it('onWarning が同期で投げても本処理へ伝播しない', () => {
    expect(() =>
      emitWarning(
        () => {
          throw new Error('sink failure');
        },
        META,
        new Error('boom'),
      ),
    ).not.toThrow();
  });

  it('onWarning が Promise を拒否しても unhandled rejection にならない', async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      emitWarning(
        (() => Promise.reject(new Error('async sink failure'))) as unknown as (
          w: SdkWarning,
        ) => void,
        META,
        new Error('boom'),
      );
      await new Promise((resolve) => setTimeout(resolve, 20));
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }

    expect(unhandled).toEqual([]);
  });

  it('別 realm の Promise の拒否も捕捉する', async () => {
    const foreignPromise = runInNewContext('Promise.reject(new Error("foreign sink failure"))');
    expect(foreignPromise instanceof Promise).toBe(false);
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      emitWarning(() => foreignPromise, META, new Error('boom'));
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(unhandled).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });

  it('thenable の拒否と then getter の例外も捕捉する', async () => {
    let assimilated = 0;
    const rejecting = {
      // biome-ignore lint/suspicious/noThenProperty: Promise 互換受け口の拒否を再現する意図的な thenable。
      then(_resolve: unknown, reject: (error: Error) => void) {
        assimilated += 1;
        reject(new Error('thenable sink failure'));
      },
    };
    const throwing = {
      // biome-ignore lint/suspicious/noThenProperty: Promise.resolve による getter 例外の隔離を検証する。
      get then() {
        throw new Error('then getter failure');
      },
    };
    emitWarning(() => rejecting, META, new Error('boom'));
    emitWarning(() => throwing, META, new Error('boom'));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(assimilated).toBe(1);
  });
});
