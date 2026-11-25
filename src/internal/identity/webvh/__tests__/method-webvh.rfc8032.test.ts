/**
 * did:webvh の proof 検証が RFC 8032 準拠の受理集合であることのテスト。
 *
 * `verify.ts` は以前 `@noble/curves` の `ed25519.verify` を直接呼んでおり、既定の
 * `zip215: true` のまま R / A の非正準エンコーディングを受理していた。keymanager の
 * `verifyEd25519`（`zip215: false`）と受理集合が食い違い、同じ SDK 内で経路により検証結果が
 * 割れる。SDK の `EdDSA-Ed25519@1.0` は RFC 8032 に準拠し、他 Verifier が
 * 拒否する DID Log を本 SDK だけが受理すると相互運用上の乖離になる。
 *
 * 検証内容:
 * - 正規の Ed25519 署名 proof は従来どおり受理される（受理集合を狭めたことによる非退行）。
 * - ZIP215 でのみ有効な proof（R が非正準）は拒否される。
 */

import { describe, expect, test } from 'bun:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  acceptedUnderZip215,
  buildZip215OnlySignature,
} from '../../../keymanager/__tests__/zip215/fixtures.js';
import { updateKeysOf, type WebVhLogEntry } from '../codec.js';
import { createDidWebVh } from '../method-webvh.js';
import { verifyEntryProof } from '../proof.js';
import { attachProof, keyFromSeed, signEntry } from './webvh-fixtures.js';

/** 決定的な鍵にするための固定シード。 */
const SEED = new Uint8Array(32).fill(11);

const KEY = keyFromSeed(SEED);

/** proof 前の初版エントリを作る。 */
function genesisEntry(): WebVhLogEntry {
  return createDidWebVh({ domain: 'vericerts.io', updateKeys: [KEY.multikey] }).logEntry;
}

describe('did:webvh proof 検証の RFC 8032 準拠', () => {
  test('正規の Ed25519 署名 proof は受理される（非退行）', () => {
    const signed = signEntry(genesisEntry(), KEY);
    expect(() => verifyEntryProof(signed, updateKeysOf(signed))).not.toThrow();
  });

  test('ZIP215 でのみ有効な proof（R が非正準）を拒否する', () => {
    let signedMessage: Uint8Array = new Uint8Array();
    let craftedSignature: Uint8Array = new Uint8Array();

    const entry = attachProof(genesisEntry(), KEY, (message) => {
      signedMessage = message;
      craftedSignature = buildZip215OnlySignature(SEED, message);
      return craftedSignature;
    });

    // 前提の確認: この proof は ZIP215（@noble の既定 = 修正前の挙動）では有効と判定される。
    // これが成り立たないと「非正準だから拒否した」ことの証明にならず、テストが空虚になる。
    expect(acceptedUnderZip215(signedMessage, craftedSignature, ed25519.getPublicKey(SEED))).toBe(
      true,
    );

    // RFC 8032 準拠の本実装は拒否する（2001 INVALID_DID）。
    expect(() => verifyEntryProof(entry, updateKeysOf(entry))).toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });
});
