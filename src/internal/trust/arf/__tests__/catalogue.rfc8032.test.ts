/**
 * ARF Catalogue のエンベロープ署名検証が RFC 8032 準拠の受理集合であることのテスト。
 *
 * `catalogue.ts` は以前 `@noble/curves` の `ed25519.verify` を直接呼んでおり、既定の
 * `zip215: true` のまま R / A の非正準エンコーディングを受理していた。keymanager の
 * `verifyEd25519`（`zip215: false`）と受理集合が食い違い、同じ SDK 内で経路により検証結果が
 * 割れる。SDK の Ed25519 検証は RFC 8032 に従うため、他 Verifier が
 * 拒否する Catalogue を本 SDK だけが Trust Anchor として受理すると信頼判断が乖離する。
 *
 * 検証内容:
 * - 正規の Ed25519 署名エンベロープは従来どおり受理される（受理集合を狭めたことによる非退行）。
 * - ZIP215 でのみ有効な署名（R が非正準）は 10305 で fail-closed になる。
 */

import { describe, expect, test } from 'bun:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { base64 } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  acceptedUnderZip215,
  buildZip215OnlySignature,
} from '../../../keymanager/__tests__/zip215/fixtures.js';
import type { ArfTrustAnchorFetcher } from '../arf-types.js';
import { loadArfTrustAnchor } from '../catalogue.js';
import { catalogueEnvelope, makeKeyPair, signedCatalogue } from './arf-fixtures.js';

/** `makeKeyPair` と同じ「同一バイトで埋めたシード」表現に揃える。 */
const SEED_BYTE = 13;
const SEED = new Uint8Array(32).fill(SEED_BYTE);
const KEY = makeKeyPair(SEED_BYTE);

const PAYLOAD = {
  version: '2026-08',
  entries: [{ id: 'did:web:issuer.example.eu', role: 'issuer' }],
};

/** 固定文字列を返す fetcher。 */
function fetcherOf(body: string): ArfTrustAnchorFetcher {
  return async () => body;
}

describe('ARF Catalogue 署名検証の RFC 8032 準拠', () => {
  test('正規の Ed25519 署名エンベロープは受理される（非退行）', async () => {
    const result = await loadArfTrustAnchor('https://arf.example/a.json', {
      fetcher: fetcherOf(signedCatalogue(PAYLOAD, KEY)),
      trustAnchorPublicKey: KEY.publicKey,
    });
    expect(result.signatureValid).toBe(true);
    expect(result.entries.length).toBe(1);
  });

  test('ZIP215 でのみ有効な署名（R が非正準）は 10305 で fail-closed', async () => {
    let signedMessage: Uint8Array = new Uint8Array();
    let craftedSignature: Uint8Array = new Uint8Array();

    const body = catalogueEnvelope(PAYLOAD, (message) => {
      signedMessage = message;
      craftedSignature = buildZip215OnlySignature(SEED, message);
      return craftedSignature;
    });

    // 前提の確認: この署名は ZIP215（@noble の既定 = 修正前の挙動）では有効と判定される。
    // これが成り立たないと「非正準だから拒否した」ことの証明にならず、テストが空虚になる。
    expect(acceptedUnderZip215(signedMessage, craftedSignature, ed25519.getPublicKey(SEED))).toBe(
      true,
    );
    // 署名対象・署名バイト列が本番 `verifyEnvelope` の読み取り方（payload の UTF-8 バイト列 /
    // base64 デコードした署名）と一致していることを確かめる。ずれていると拒否の理由が
    // 「非正準エンコーディング」ではなくなり、テストが目的を果たさない。
    const envelope = JSON.parse(body) as { payload: string; signature: string };
    expect(signedMessage).toEqual(new TextEncoder().encode(envelope.payload));
    expect(craftedSignature).toEqual(base64.decode(envelope.signature));

    const promise = loadArfTrustAnchor('https://arf.example/a.json', {
      fetcher: fetcherOf(body),
      trustAnchorPublicKey: KEY.publicKey,
    });
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED,
    });
  });
});
