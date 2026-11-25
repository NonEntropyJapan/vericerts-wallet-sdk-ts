/**
 * DashboardLog 単体テスト（`dashboard-log.test.ts` / `dashboard-log-export.test.ts` /
 * `dashboard-log-import.test.ts`）で共有する signer / now ヘルパ。
 *
 * テストをグループ単位のファイルに分割してもフィクスチャ生成を重複させないため、決定的な signer と
 * 固定時刻 now をここに集約する（`.ts` サフィックスにより bun のテスト収集対象にはならない）。
 */

import { createPrivateKeySigner } from '../../../credential/index.js';

/** 決定的な 32B secp256k1 秘密鍵（全バイト `fill`）から ES256K signer を作る。 */
export function createPrivateKeySignerFromFill(fill: number) {
  return createPrivateKeySigner(new Uint8Array(32).fill(fill), 'ES256K');
}

/** 決定的な 32B secp256k1 秘密鍵から ES256K signer を作る。 */
export function testSigner() {
  return createPrivateKeySignerFromFill(7);
}

/** 決定的な 32B Ed25519 シード（全バイト `fill`）から EdDSA signer を作る。 */
export function createEddsaSignerFromFill(fill: number) {
  return createPrivateKeySigner(new Uint8Array(32).fill(fill), 'EdDSA');
}

/** 固定時刻の now を返す。 */
export function fixedNow(iso: string): () => Date {
  return () => new Date(iso);
}
