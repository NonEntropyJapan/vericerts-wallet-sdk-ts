/**
 * DPoP 型 `DpopProof` の公開エクスポート面の回帰テスト。
 *
 * PARRequest.dpop はコンパクト JWS 形式の文字列を表す公開型 DpopProof を受け取る。
 *
 * 本テストは型注釈で公開面を固定する（`DpopProof` の export を落とすと `tsc` が落ちる）。
 * あわせて、別名の実体が文字列であること・`createDpopProof` の戻り値をそのまま
 * `verifyDpopProof` へ渡せることをランタイムでも確認する。内部パスから import すると
 * 公開面の欠落を検知できないため、必ず公開バレル経由で import すること。
 */

import { describe, expect, test } from 'bun:test';
import * as sdk from '../../index.js';
import { createPrivateKeySigner } from '../../internal/credential/vc/signer.js';

const HTM = 'POST';
const HTU = 'https://as.example.com/par';
const SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(11), 'ES256');

describe('公開エクスポート: DpopProof', () => {
  test('createDpopProof の戻り値を公開型 DpopProof として受けられる', () => {
    const proof: sdk.DpopProof = sdk.createDpopProof({ htm: HTM, htu: HTU }, SIGNER);
    // 実体はコンパクト JWS 直列化された文字列（構造体ではない）。
    expect(typeof proof).toBe('string');
    expect(proof.split('.')).toHaveLength(3);
  });

  test('DpopProof は string の別名であり verifyDpopProof の入力にそのまま渡せる', () => {
    const proof: sdk.DpopProof = sdk.createDpopProof({ htm: HTM, htu: HTU }, SIGNER);
    // `string` と構造的に同一であること（別名を跨いだ代入が両方向で通る）。
    const asString: string = proof;
    const backToAlias: sdk.DpopProof = asString;
    const verified = sdk.verifyDpopProof(backToAlias, { htm: HTM, htu: HTU });
    expect(verified.htm).toBe(HTM);
    expect(verified.htu).toBe(HTU);
  });
});
