import { describe, expect, test } from 'bun:test';
import type { QtspServiceCertificate } from '../../etsi-tsl/tsl.js';
import {
  createRpCertJudgmentCache,
  RP_CERT_JUDGMENT_CACHE_MAX_TOTAL_KEY_LENGTH,
  RP_CERT_JUDGMENT_CACHE_TTL_SECONDS,
  readRpCertJudgment,
  rpCertJudgmentCacheKey,
  storeRpCertJudgment,
} from '../cache.js';

const NOW_SECONDS = 1_700_000_000;

const LEAF = Uint8Array.from([0x30, 0x01, 0x01]);
const OTHER_LEAF = Uint8Array.from([0x30, 0x01, 0x02]);

function anchor(byte: number, granted = true): QtspServiceCertificate {
  return { certDer: Uint8Array.from([byte, byte, byte]), granted };
}

describe('rpCertJudgmentCacheKey', () => {
  test('同一シリアルでも DER が異なるリーフは別キー', () => {
    expect(rpCertJudgmentCacheKey(LEAF, [], [anchor(1)], undefined)).not.toBe(
      rpCertJudgmentCacheKey(OTHER_LEAF, [], [anchor(1)], undefined),
    );
  });

  test('中間証明書が異なれば別キー（チェーン結果は中間にも依存する）', () => {
    const a = rpCertJudgmentCacheKey(LEAF, [Uint8Array.from([1])], [anchor(1)], undefined);
    const b = rpCertJudgmentCacheKey(LEAF, [Uint8Array.from([2])], [anchor(1)], undefined);
    const none = rpCertJudgmentCacheKey(LEAF, [], [anchor(1)], undefined);
    expect(new Set([a, b, none]).size).toBe(3);
  });

  test('同じリーフ・同じ anchors・同じ revokedSerials なら同一キー', () => {
    const anchors = [anchor(1), anchor(2)];
    const revoked = new Set(['aa']);
    const key1 = rpCertJudgmentCacheKey(LEAF, [], anchors, revoked);
    const key2 = rpCertJudgmentCacheKey(LEAF, [], anchors, new Set(['aa']));
    expect(key1).toBe(key2);
  });

  test('anchors の並び順が違っても同一キー（安定ソート）', () => {
    const key1 = rpCertJudgmentCacheKey(LEAF, [], [anchor(1), anchor(2)], undefined);
    const key2 = rpCertJudgmentCacheKey(LEAF, [], [anchor(2), anchor(1)], undefined);
    expect(key1).toBe(key2);
  });

  test('Trust Anchor 集合が違えば別キー', () => {
    expect(rpCertJudgmentCacheKey(LEAF, [], [anchor(1)], undefined)).not.toBe(
      rpCertJudgmentCacheKey(LEAF, [], [anchor(2)], undefined),
    );
  });

  test('Trust Anchor の granted フラグが違えば別キー', () => {
    expect(rpCertJudgmentCacheKey(LEAF, [], [anchor(1, true)], undefined)).not.toBe(
      rpCertJudgmentCacheKey(LEAF, [], [anchor(1, false)], undefined),
    );
  });

  test('revokedSerials 未指定（未確認）と空集合（確認済み・失効なし）は別キー', () => {
    const anchors = [anchor(1)];
    expect(rpCertJudgmentCacheKey(LEAF, [], anchors, undefined)).not.toBe(
      rpCertJudgmentCacheKey(LEAF, [], anchors, new Set()),
    );
  });

  test('revokedSerials の中身が違えば別キー', () => {
    const anchors = [anchor(1)];
    expect(rpCertJudgmentCacheKey(LEAF, [], anchors, new Set(['aa']))).not.toBe(
      rpCertJudgmentCacheKey(LEAF, [], anchors, new Set(['bb'])),
    );
  });
});

describe('createRpCertJudgmentCache / readRpCertJudgment / storeRpCertJudgment', () => {
  test('TTL 内は成功結果を読み出せる', () => {
    const cache = createRpCertJudgmentCache(() => NOW_SECONDS);
    const key = rpCertJudgmentCacheKey(LEAF, [], [anchor(1)], undefined);
    storeRpCertJudgment(cache, key, true, NOW_SECONDS);
    expect(readRpCertJudgment(cache, key, NOW_SECONDS)).toBe(true);
  });

  test('TTL 内は失敗結果も読み出せる（成功/失敗どちらもキャッシュする）', () => {
    const cache = createRpCertJudgmentCache(() => NOW_SECONDS);
    const key = rpCertJudgmentCacheKey(LEAF, [], [anchor(1)], undefined);
    storeRpCertJudgment(cache, key, false, NOW_SECONDS);
    expect(readRpCertJudgment(cache, key, NOW_SECONDS)).toBe(false);
  });

  test('TTL 経過後は undefined（再検証が必要）', () => {
    const cache = createRpCertJudgmentCache(() => NOW_SECONDS);
    const key = rpCertJudgmentCacheKey(LEAF, [], [anchor(1)], undefined);
    storeRpCertJudgment(cache, key, true, NOW_SECONDS);
    const afterTtl = NOW_SECONDS + RP_CERT_JUDGMENT_CACHE_TTL_SECONDS;
    expect(readRpCertJudgment(cache, key, afterTtl)).toBeUndefined();
  });

  test('TTL 直前は依然としてヒットする', () => {
    const cache = createRpCertJudgmentCache(() => NOW_SECONDS);
    const key = rpCertJudgmentCacheKey(LEAF, [], [anchor(1)], undefined);
    storeRpCertJudgment(cache, key, true, NOW_SECONDS);
    const justBeforeTtl = NOW_SECONDS + RP_CERT_JUDGMENT_CACHE_TTL_SECONDS - 1;
    expect(readRpCertJudgment(cache, key, justBeforeTtl)).toBe(true);
  });

  test('未格納のキーは undefined', () => {
    const cache = createRpCertJudgmentCache(() => NOW_SECONDS);
    const key = rpCertJudgmentCacheKey(LEAF, [], [anchor(1)], undefined);
    expect(readRpCertJudgment(cache, key, NOW_SECONDS)).toBeUndefined();
  });

  test('revokedSerials が変化するとキーも変わり別エントリになる（古い判定にヒットしない）', () => {
    const cache = createRpCertJudgmentCache(() => NOW_SECONDS);
    const anchors = [anchor(1)];
    const staleKey = rpCertJudgmentCacheKey(LEAF, [], anchors, undefined);
    storeRpCertJudgment(cache, staleKey, true, NOW_SECONDS);

    // 同じ証明書・同じ anchors で、新たに revokedSerials（この証明書のシリアルを含む）が
    // 渡された場合はキーが変わるため、古い valid:true にはヒットしない。
    const freshKey = rpCertJudgmentCacheKey(LEAF, [], anchors, new Set(['01']));
    expect(readRpCertJudgment(cache, freshKey, NOW_SECONDS)).toBeUndefined();
  });
});

describe('RP Cert 判定キャッシュの保持量', () => {
  // 形状: 少数の巨大中間 / 多数の極小中間 / 中間なし。いずれもキー長は同一の固定長。
  const shapes: Record<string, Uint8Array[]> = {
    none: [],
    tiny_many: Array.from({ length: 10_000 }, (_, i) => Uint8Array.from([i & 0xff, i >> 8])),
    few_huge: [new Uint8Array(1_000_000).fill(7), new Uint8Array(1_000_000).fill(9)],
  };

  test('キー長は中間証明書の枚数・長さに依存しない', () => {
    const lengths = Object.values(shapes).map(
      (intermediates) => rpCertJudgmentCacheKey(LEAF, intermediates, [anchor(1)], undefined).length,
    );
    expect(new Set(lengths).size).toBe(1);
  });

  test('境界をずらした中間列は別キー（[AB, C] と [A, BC]）', () => {
    const ab = Uint8Array.from([1, 2]);
    const c = Uint8Array.from([3]);
    const a = Uint8Array.from([1]);
    const bc = Uint8Array.from([2, 3]);
    expect(rpCertJudgmentCacheKey(LEAF, [ab, c], [anchor(1)], undefined)).not.toBe(
      rpCertJudgmentCacheKey(LEAF, [a, bc], [anchor(1)], undefined),
    );
  });

  test('キー長の総量が上限を超える分は保持しない（巨大キーは格納されない）', () => {
    const cache = createRpCertJudgmentCache(() => NOW_SECONDS);
    const hugeKey = 'k'.repeat(RP_CERT_JUDGMENT_CACHE_MAX_TOTAL_KEY_LENGTH + 1);
    storeRpCertJudgment(cache, hugeKey, true, NOW_SECONDS);
    expect(readRpCertJudgment(cache, hugeKey, NOW_SECONDS)).toBeUndefined();
  });

  test('正常な固定長キーは格納・参照できる', () => {
    const cache = createRpCertJudgmentCache(() => NOW_SECONDS);
    const key = rpCertJudgmentCacheKey(LEAF, [Uint8Array.from([1])], [anchor(1)], undefined);
    storeRpCertJudgment(cache, key, true, NOW_SECONDS);
    expect(readRpCertJudgment(cache, key, NOW_SECONDS)).toBe(true);
  });
});
