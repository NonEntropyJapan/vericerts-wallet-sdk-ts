/**
 * `verifyEd25519` が RFC 8032 準拠の受理集合であることのテスト（実鍵・モック禁止）。
 *
 * `@noble/curves` の `ed25519.verify` は既定が `zip215: true` で、点の「非正準エンコーディング」
 * （`y >= p` の表現）まで受理する。SDK の `EdDSA-Ed25519@1.0` は RFC 8032 に従い、非正準エンコーディングを拒否する。既定のままだと他 Verifier が
 * 拒否する署名を本 SDK だけが受理し、同一 VC の検証結果が実装間で割れる。
 *
 * 検証内容:
 * - 正常な署名は従来どおり検証できる（`zip215: false` にしても非退行）。
 * - R を非正準エンコーディング（`y = p`。`y = 0` と同じ点を指す）にした署名を拒否する。
 *   この署名は ZIP215（旧既定）では有効と判定されるため、RFC 8032 準拠の回帰テストになる。
 */

import { describe, expect, test } from 'bun:test';
import { getEd25519PublicKey, signEd25519, verifyEd25519 } from '../ed25519.js';
import { acceptedUnderZip215, buildZip215OnlySignature } from './zip215/fixtures.js';

const SEED = new Uint8Array(32).fill(5);
const MESSAGE = new TextEncoder().encode('zip215-vs-rfc8032');

describe('verifyEd25519 の RFC 8032 準拠', () => {
  test('正常な署名は検証できる（非退行）', () => {
    const publicKey = getEd25519PublicKey(SEED);
    const signature = signEd25519(MESSAGE, SEED);
    expect(verifyEd25519(MESSAGE, signature, publicKey)).toBe(true);
  });

  test('R が非正準エンコーディングの署名を拒否する（ZIP215 では有効と判定される署名）', () => {
    const publicKey = getEd25519PublicKey(SEED);
    const signature = buildZip215OnlySignature(SEED, MESSAGE);

    // 前提の確認: この署名は ZIP215（@noble の既定）では有効と判定される。
    // したがって本テストは zip215 の指定有無を実際に判別できる。
    expect(acceptedUnderZip215(MESSAGE, signature, publicKey)).toBe(true);

    // RFC 8032 準拠の本実装は拒否する。
    expect(verifyEd25519(MESSAGE, signature, publicKey)).toBe(false);
  });
});
