/** 署名側の時刻入力テスト共通のフィクスチャ。 */

import { expect } from 'bun:test';
import { type CredentialSigner, createPrivateKeySigner } from '../../credential/vc/signer.js';
import { type ErrorCode, VericertsError } from '../../errors.js';

export const SEED = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
export const NOW = 1_700_000_000;
export const BAD_TIMES = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, '5'];
export const BAD_LIFETIMES = [Number.NaN, Number.POSITIVE_INFINITY, 0, -5000, '300'];

/** 署名呼び出しを数える実鍵 signer。 */
export function countingSigner(): { signer: CredentialSigner; calls: () => number } {
  const inner = createPrivateKeySigner(new Uint8Array(32).fill(11), 'ES256');
  let calls = 0;
  return {
    signer: {
      ...inner,
      sign: (msg: Uint8Array) => {
        calls += 1;
        return inner.sign(msg);
      },
    },
    calls: () => calls,
  };
}

export function expectVericerts(fn: () => unknown, code?: ErrorCode): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    if (code !== undefined) {
      expect((err as VericertsError).code).toBe(code);
    }
    return;
  }
  throw new Error('should have thrown');
}

export async function expectVericertsAsync(
  fn: () => Promise<unknown>,
  code?: ErrorCode,
): Promise<void> {
  try {
    await fn();
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    if (code !== undefined) {
      expect((err as VericertsError).code).toBe(code);
    }
    return;
  }
  throw new Error('should have thrown');
}
