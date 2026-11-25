/**
 * UTF-8 文字列 → パディングなし base64url の唯一の変換元。
 *
 * JWS / JWT / SD-JWT の signing-input（`<header>.<payload>`）は、この関数が返す文字列を
 * そのまま連結して組み立てる。署名はバイト列ではなく **この文字列** に対して施されるため、
 * 出力が 1 文字でも変われば本 SDK が発行する全ての署名（VC-JWT / SD-JWT / KB-JWT /
 * DPoP Proof / OID4VCI JWT Proof / did:jwt / Status List Token / GDPR ダッシュボードログ）の
 * 値が変わり、既存の署名・ハッシュとの互換性が失われる。
 *
 * したがって本関数の実装は「変えない」ことが仕様である。パディング付与、エンコーダ差し替え、
 * 前後空白のトリム、入力の追加検証、メモ化などの「改善」を加えてはならない。
 * 挙動は `src/internal/__tests__/base64url.test.ts` の既知ベクタで固定している。
 *
 * 配置について: 利用者は credential / identity / auth / eudi / gdpr の各ドメインにまたがるため、
 * 特定ドメイン配下ではなく `frozen-set.ts` / `timing-safe.ts` と同じ internal 直下に置く。
 */

import { base64urlnopad } from '@scure/base';

/** UTF-8 文字列を base64url（パディングなし）エンコードする。 */
export function base64urlText(text: string): string {
  return base64urlnopad.encode(new TextEncoder().encode(text));
}
