/**
 * contentHash の計算・照合 API の検証。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad, hex } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  computeContentHash,
  contentHashEquals,
  verifyContentHash,
  verifyDidContentHash,
  verifyVcContentHashClaim,
} from '../verify.js';

const CONTENT = new TextEncoder().encode('vericerts artifact payload');
const DIGEST = sha256(CONTENT);
const HEX = hex.encode(DIGEST);
const DID = `did:web:acme.example.com:artifacts:sha256-${HEX}`;

/** 非同期に投げられた VericertsError のコードを取り出す。 */
async function asyncCodeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    return (error as VericertsError).code;
  }
  throw new Error('例外が発生しませんでした');
}

/** 同期に投げられた VericertsError のコードを取り出す。 */
function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    return (error as VericertsError).code;
  }
  throw new Error('例外が発生しませんでした');
}

describe('computeContentHash', () => {
  it('Uint8Array から sha2-256 ダイジェストを計算する', async () => {
    const parsed = await computeContentHash(CONTENT);
    expect(parsed.algorithm).toBe('sha2-256');
    expect(parsed.digest).toEqual(DIGEST);
    expect(parsed.notation).toBe(`sha2-256-${HEX}`);
  });

  it('AsyncIterable（分割チャンク）でも同じダイジェストになる', async () => {
    async function* chunks(): AsyncGenerator<Uint8Array> {
      yield CONTENT.subarray(0, 5);
      yield CONTENT.subarray(5, 11);
      yield CONTENT.subarray(11);
    }
    expect((await computeContentHash(chunks())).digest).toEqual(DIGEST);
  });

  it('ReadableStream でも同じダイジェストになる', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(CONTENT.subarray(0, 8));
        controller.enqueue(CONTENT.subarray(8));
        controller.close();
      },
    });
    expect((await computeContentHash(stream)).digest).toEqual(DIGEST);
  });

  it('空コンテンツも計算できる', async () => {
    const parsed = await computeContentHash(new Uint8Array(0));
    expect(parsed.digest).toEqual(sha256(new Uint8Array(0)));
  });

  it('未対応アルゴリズムを渡すと 1030 で拒否する', async () => {
    const code = await asyncCodeOf(async () =>
      // biome-ignore lint/suspicious/noExplicitAny: 型の外から未対応値を渡す fail-closed 検証。
      computeContentHash(CONTENT, 'sha3-256' as any),
    );
    expect(code).toBe(ErrorCodes.UNSUPPORTED_ALGORITHM);
  });
});

describe('verifyContentHash', () => {
  it('hex 表記の期待値と一致する', async () => {
    await expect(verifyContentHash(CONTENT, `sha256-${HEX}`)).resolves.toBeDefined();
  });

  it('base64url 表記の期待値とも一致する（表記差の吸収）', async () => {
    const notation = `sha256-${base64urlnopad.encode(DIGEST)}`;
    await expect(verifyContentHash(CONTENT, notation)).resolves.toBeDefined();
  });

  it('不一致は 2009 CONTENT_HASH_MISMATCH で拒否する', async () => {
    const other = hex.encode(sha256(new TextEncoder().encode('other')));
    expect(await asyncCodeOf(() => verifyContentHash(CONTENT, `sha256-${other}`))).toBe(
      ErrorCodes.CONTENT_HASH_MISMATCH,
    );
  });

  it('表記不正は 2016 で拒否する（2009 と区別できる）', async () => {
    expect(await asyncCodeOf(() => verifyContentHash(CONTENT, 'sha256-zzz'))).toBe(
      ErrorCodes.CONTENT_HASH_FORMAT_INVALID,
    );
  });
});

describe('verifyDidContentHash', () => {
  it('DID サブパスと実コンテンツが一致すれば抽出結果を返す', async () => {
    const parsed = await verifyDidContentHash(DID, CONTENT);
    expect(parsed.notation).toBe(`sha2-256-${HEX}`);
  });

  it('stream 入力でも検証できる', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(CONTENT);
        controller.close();
      },
    });
    await expect(verifyDidContentHash(DID, stream)).resolves.toBeDefined();
  });

  it('別コンテンツは 2009 で拒否する', async () => {
    const swapped = new TextEncoder().encode('swapped artifact payload');
    expect(await asyncCodeOf(() => verifyDidContentHash(DID, swapped))).toBe(
      ErrorCodes.CONTENT_HASH_MISMATCH,
    );
  });
});

describe('verifyVcContentHashClaim', () => {
  it('DID サブパスと VC claim が一致すれば正規化結果を返す', () => {
    expect(verifyVcContentHashClaim(DID, `sha256-${HEX}`).notation).toBe(`sha2-256-${HEX}`);
  });

  it('表記が違っても正規化後に一致すれば通る', () => {
    const claim = `sha-256-${base64urlnopad.encode(DIGEST)}`;
    expect(verifyVcContentHashClaim(DID, claim).digest).toEqual(DIGEST);
  });

  it('claim が別ダイジェストなら 2009 で拒否する', () => {
    const other = hex.encode(sha256(new TextEncoder().encode('other')));
    expect(codeOf(() => verifyVcContentHashClaim(DID, `sha256-${other}`))).toBe(
      ErrorCodes.CONTENT_HASH_MISMATCH,
    );
  });
});

describe('contentHashEquals', () => {
  it('アルゴリズムが違えば不一致（fail-closed）', () => {
    const a = { algorithm: 'sha2-256', digest: DIGEST, notation: 'a' } as const;
    // 型の外から別アルゴリズム名を持ち込んだケースを模す。
    const b = { ...a, algorithm: 'sha2-512' } as unknown as typeof a;
    expect(contentHashEquals(a, b)).toBe(false);
  });

  it('ダイジェスト長が違えば不一致', () => {
    const a = { algorithm: 'sha2-256', digest: DIGEST, notation: 'a' } as const;
    const b = { ...a, digest: DIGEST.subarray(0, 31) };
    expect(contentHashEquals(a, b)).toBe(false);
  });
});
