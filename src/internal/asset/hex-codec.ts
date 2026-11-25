/**
 * hex 文字列 ⇔ バイト列変換（バイト単位のエンコード/デコード本体）の SSOT。
 *
 * `eth-signing.ts` と `legacy-tx-serializer.ts` に、hex ⇔ バイト列変換のロジック本体（1 バイトずつの
 * パース/フォーマット）がほぼ同一のまま重複実装されていたため、ここへ集約した。
 *
 * `0x` プレフィックスの要否・空文字列の許容・不正入力時のエラー型（`SIGN_FAILED` /
 * `CHAIN_SUBMIT_FAILED`）は呼び出し側ごとに異なるため、バリデーションは各呼び出し側の責務のまま残す。
 * 本モジュールは「正規化済み（`0x` プレフィックス除去済み、偶数長、`[0-9a-fA-F]*` のみ）hex 文字列」を
 * 前提としたバイト列変換のみを提供する（依存ゼロ、純粋な文字列/バイト列処理のみ）。
 */

/**
 * 正規化済み（`0x` プレフィックス除去済み、偶数長、`[0-9a-fA-F]*` のみ）hex 文字列をバイト列へ変換する。
 *
 * 入力バリデーションは行わない（形式チェックは呼び出し側の責務。エラー型が用途ごとに異なるため）。
 *
 * @param normalizedHex `0x` プレフィックスを除いた偶数長 hex 文字列。
 * @returns 変換後のバイト列。
 */
export function decodeHexDigits(normalizedHex: string): Uint8Array {
  const bytes = new Uint8Array(normalizedHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(normalizedHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * バイト列を `0x` プレフィックス付き hex 文字列（小文字）へ変換する。
 *
 * @param bytes 変換対象のバイト列。
 * @returns `0x` プレフィックス付き hex 文字列。
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '0x';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}
