/**
 * 入力内容に応じた早期終了を避けるため、ブラウザでも動作する XOR 累算で比較する。
 * 同等の性質（入力内容によって早期 return しない）を満たす XOR 累算で実装する。
 * 既存の `internal/trust/etsi-tsl/xmldsig.ts` の `bytesEqual` と同じイディオムだが、
 * こちらは長さが異なる場合も早期 return せず、両者の最大長まで走査する。
 *
 * `auth/nonce/` と `credential/sdjwt/verify.ts` の双方から使うため `internal/` 直下に置く
 * （credential → auth の依存を作らないため）。本モジュールは他のどのモジュールにも依存しない。
 */

const encoder = new TextEncoder();

/**
 * 2 つのバイト列を定数時間で比較する。
 *
 * 長さが異なる場合も早期 return せず、`max(a.length, b.length)` 回ループする。
 * 不足分は 0 として扱い、長さの差自体も XOR に畳み込むため結果は正しく `false` になる。
 *
 * @param a 比較対象。
 * @param b 比較対象。
 * @returns 完全一致なら `true`。
 */
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  // 長さの差を先に畳み込む。ループ回数は最大長に依存するが、内容には依存しない。
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * 2 つの文字列を UTF-8 バイト列として定数時間で比較する。
 *
 * `nonce` / `aud` / `client_id` の照合に使う。
 *
 * @param a 比較対象。
 * @param b 比較対象。
 * @returns 完全一致なら `true`。
 */
export function timingSafeEqualString(a: string, b: string): boolean {
  return timingSafeEqualBytes(encoder.encode(a), encoder.encode(b));
}
