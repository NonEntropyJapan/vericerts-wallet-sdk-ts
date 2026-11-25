/**
 * 改竄検知の回帰テスト（受入条件「1 バイト改変で必ず検知」）。
 *
 * DID サブパスのハッシュと取得したコンテンツを照合し、1 バイトでも変われば
 * `2009 CONTENT_HASH_MISMATCH` で拒否することを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { hex } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { verifyDidContentHash } from '../verify.js';

const CONTENT = new TextEncoder().encode('vericerts artifact bytes');
const DID = `did:web:acme.example.com:artifacts:sha256-${hex.encode(sha256(CONTENT))}`;

/** 期待どおり 2009 で拒否されることを確認する。 */
async function expectMismatch(content: Uint8Array): Promise<void> {
  try {
    await verifyDidContentHash(DID, content);
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.CONTENT_HASH_MISMATCH);
    return;
  }
  throw new Error('改竄が検知されませんでした');
}

describe('改竄検知', () => {
  it('無改変なら検証を通る（対照）', async () => {
    await expect(verifyDidContentHash(DID, CONTENT)).resolves.toBeDefined();
  });

  it('全バイト位置の 1 ビット反転をすべて検知する', async () => {
    for (let index = 0; index < CONTENT.length; index++) {
      const tampered = Uint8Array.from(CONTENT);
      // biome-ignore lint/style/noNonNullAssertion: index は length 未満で必ず存在する。
      tampered[index] = tampered[index]! ^ 0x01;
      await expectMismatch(tampered);
    }
  });

  it('1 バイト追加を検知する', async () => {
    await expectMismatch(Uint8Array.from([...CONTENT, 0x00]));
  });

  it('1 バイト削除を検知する', async () => {
    await expectMismatch(CONTENT.subarray(0, CONTENT.length - 1));
  });

  it('隣接 2 バイトの入れ替えを検知する', async () => {
    const tampered = Uint8Array.from(CONTENT);
    const first = tampered[0];
    const second = tampered[1];
    if (first === undefined || second === undefined) {
      throw new Error('テストデータが短すぎます');
    }
    tampered[0] = second;
    tampered[1] = first;
    await expectMismatch(tampered);
  });

  it('空コンテンツへのすり替えを検知する', async () => {
    await expectMismatch(new Uint8Array(0));
  });

  it('stream 経由の改竄も検知する', async () => {
    const tampered = Uint8Array.from(CONTENT);
    // biome-ignore lint/style/noNonNullAssertion: 末尾要素は必ず存在する。
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 0xff;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(tampered.subarray(0, 4));
        controller.enqueue(tampered.subarray(4));
        controller.close();
      },
    });
    try {
      await verifyDidContentHash(DID, stream);
    } catch (error) {
      expect((error as VericertsError).code).toBe(ErrorCodes.CONTENT_HASH_MISMATCH);
      return;
    }
    throw new Error('改竄が検知されませんでした');
  });
});
