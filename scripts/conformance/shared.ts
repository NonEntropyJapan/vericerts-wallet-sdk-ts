/**
 * schemas/conformance-vectors.json の1ケースを表す共通型と、生成スクリプト全体で使う
 * 小さなヘルパ。
 */

import { VericertsError } from '../../src/internal/errors.js';

export interface Case {
  id: string;
  category: 'did-resolve' | 'vc-verify' | 'vc-verify-did' | 'delegated-key-select';
  description: string;
  input: Record<string, unknown>;
  expected: Record<string, unknown>;
}

/** バイト列を base64url（パディング無し）文字列に変換する。 */
export function b64url(b: Uint8Array): string {
  return Buffer.from(b).toString('base64url');
}

/**
 * fn を実行して VericertsError の code を取り出す（エラーケースの expected.errorCode 用）。
 * fn が例外を投げなければ、または VericertsError 以外を投げれば fail-closed で throw する。
 */
export function errorCodeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof VericertsError) return e.code;
    throw e;
  }
  throw new Error('expected VericertsError, function did not throw');
}
