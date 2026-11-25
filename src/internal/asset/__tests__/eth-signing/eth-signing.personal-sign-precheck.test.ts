/**
 * `assertPersonalSignAllowed`（承認前の `personal_sign` 入力検証）のテスト。
 * `eth-signing.test.ts` から分割した。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { assertPersonalSignAllowed, personalSignPayload } from '../../eth-signing.js';

// 承認前検証（extension の `prepareSignRequest`）が使う。署名時ガードと判定を共有するため、結果は常に一致する。
describe('assertPersonalSignAllowed（承認前の personal_sign 入力検証）', () => {
  const segment = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const jws = (header: Record<string, unknown>) =>
    `${segment({ alg: 'ES256K-R', ...header })}.${segment({ iss: 'did:pkh:eip155:1:0xabc' })}`;
  const toHex = (text: string) => `0x${Buffer.from(text).toString('hex')}`;

  test('ES256K-R の JWS signing-input（水増しヘッダ・hex 化を含む）は SIGN_FAILED で拒否する', () => {
    for (const input of [jws({ kid: 'k' }), jws({ pad: 'A'.repeat(6000) })]) {
      for (const data of [input, toHex(input)]) {
        expect(() => assertPersonalSignAllowed(data)).toThrow(
          expect.objectContaining({ code: ErrorCodes.SIGN_FAILED }),
        );
      }
    }
  });

  test('通常のメッセージ・標準の alg の JWS・不正 UTF-8 の hex は拒否しない', () => {
    for (const data of ['Hello', '0x', toHex('Hello'), '0xff', `${segment({ alg: 'ES256K' })}.x`]) {
      expect(() => assertPersonalSignAllowed(data)).not.toThrow();
    }
  });

  test('署名時のガード（personalSignPayload）と同じ入力を拒否する', () => {
    const inputs = ['Hello', '0xff', jws({}), toHex(jws({})), jws({ pad: 'A'.repeat(6000) })];
    for (const data of inputs) {
      const precheck = (() => {
        try {
          assertPersonalSignAllowed(data);
          return true;
        } catch {
          return false;
        }
      })();
      const signing = (() => {
        try {
          personalSignPayload(data);
          return true;
        } catch {
          return false;
        }
      })();
      expect(precheck).toBe(signing);
    }
  });
});
