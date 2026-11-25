/**
 * contentHash 検証の例外が入力値を漏らさないことの検証。
 *
 * 例外メッセージや `context` に DID・ダイジェスト等の入力を含めない。
 * DID・contentHash はテナント名や社内 Artifact 名を含み得るうえ、ログ・監視基盤へそのまま
 * 流れるため、エラー経路からの漏洩を不変条件として固定する。
 *
 * 既存の `credential/vc/__tests__/remote-signer/remote-signer.security.test.ts` と同じ方針。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { hex } from '@scure/base';
import { VericertsError } from '../../../errors.js';
import { extractDidContentHash } from '../did-subpath.js';
import { parseContentHash } from '../notation.js';
import {
  computeContentHash,
  verifyContentHash,
  verifyDidContentHash,
  verifyVcContentHashClaim,
} from '../verify.js';

/** 入力に紛れ込ませる「漏れてはいけない」目印。 */
const SECRET = 'SUPERSECRETTENANT';

const CONTENT = new TextEncoder().encode('vericerts artifact');
const OTHER = new TextEncoder().encode('tampered artifact');
const HEX = hex.encode(sha256(CONTENT));
const OTHER_HEX = hex.encode(sha256(OTHER));

/** 秘密目印を含む DID / 表記。 */
const SECRET_DID = `did:web:${SECRET}.example.com:artifacts:sha256-${HEX}`;
const SECRET_BAD_DID = `did:web:${SECRET}.example.com:artifacts:${SECRET}-notahash`;

/** 例外が VericertsError で、観測可能な面に入力を漏らしていないことを確認する。 */
function expectNoLeak(error: unknown, ...needles: readonly string[]): void {
  expect(error).toBeInstanceOf(VericertsError);
  const typed = error as VericertsError;
  const surfaces = [
    typed.message,
    String(typed),
    JSON.stringify(typed.context ?? null),
    JSON.stringify((typed as { cause?: unknown }).cause ?? null),
  ];
  for (const needle of needles) {
    for (const surface of surfaces) {
      expect(surface).not.toContain(needle);
    }
  }
  // context / cause にも入力を残さない。
  expect(typed.context).toBeUndefined();
  expect((typed as { cause?: unknown }).cause).toBeUndefined();
}

/** 同期呼び出しで投げられた例外を取り出す。 */
function caught(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error('例外が発生しませんでした');
}

/** 非同期呼び出しで投げられた例外を取り出す。 */
async function caughtAsync(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
  } catch (error) {
    return error;
  }
  throw new Error('例外が発生しませんでした');
}

describe('contentHash 検証の例外は入力を漏らさない', () => {
  it('parseContentHash: 表記不正でも入力を漏らさない', () => {
    expectNoLeak(
      caught(() => parseContentHash(`${SECRET}-notahash`)),
      SECRET,
    );
  });

  it('parseContentHash: 未対応アルゴリズムでもダイジェストを漏らさない', () => {
    expectNoLeak(
      caught(() => parseContentHash(`md5-${HEX}`)),
      HEX,
    );
  });

  it('extractDidContentHash: DID 形式不正でも DID を漏らさない', () => {
    expectNoLeak(
      caught(() => extractDidContentHash(`web:${SECRET}.example.com`)),
      SECRET,
    );
  });

  it('extractDidContentHash: 表記不正でも DID を漏らさない', () => {
    expectNoLeak(
      caught(() => extractDidContentHash(SECRET_BAD_DID)),
      SECRET,
    );
  });

  it('computeContentHash: 未対応アルゴリズムでもアルゴリズム名を漏らさない', async () => {
    expectNoLeak(
      await caughtAsync(() => computeContentHash(CONTENT, `${SECRET}-alg` as never)),
      SECRET,
    );
  });

  it('verifyContentHash: 不一致でも期待ダイジェストを漏らさない', async () => {
    expectNoLeak(
      await caughtAsync(() => verifyContentHash(OTHER, `sha256-${HEX}`)),
      HEX,
      OTHER_HEX,
    );
  });

  it('verifyDidContentHash: 不一致でも DID とダイジェストを漏らさない', async () => {
    expectNoLeak(await caughtAsync(() => verifyDidContentHash(SECRET_DID, OTHER)), SECRET, HEX);
  });

  it('verifyVcContentHashClaim: 不一致でも DID と claim を漏らさない', () => {
    expectNoLeak(
      caught(() => verifyVcContentHashClaim(SECRET_DID, `sha256-${OTHER_HEX}`)),
      SECRET,
      HEX,
      OTHER_HEX,
    );
  });
});
