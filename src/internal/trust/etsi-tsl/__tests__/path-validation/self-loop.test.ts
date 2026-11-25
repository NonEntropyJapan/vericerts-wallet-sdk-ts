/**
 * 自己ループ検出（同一 subject DN の再利用拒否）の回帰テスト。
 *
 * 同じ subject DN を 2 度使うチェーンは先に拒否されるため、`pathLenConstraint` の段数から
 * self-issued 中間証明書を除く例外はここでは適用されない。
 * 他の 8 検査には専用の回帰テストがあるが、subject DN の再利用を突くケースだけが無かった。
 *
 * ここで固定するのは「`usedSubjects` を外すと結果が変わる」ことそのものである。下のチェーンは
 * 検出が無ければ Trust Anchor まで到達して `trusted: true` になる。
 *
 * **配置**: 兄弟の `chain.*.test.ts` と同じ関心だが、`__tests__/` 直下はディレクトリ行数の
 * 上限（linterly `max_lines_per_directory`）に達しているため、`fail-open/` /
 * `proto-pollution/` と同じくサブディレクトリへ置く。
 */

import { describe, expect, test } from 'bun:test';
import { verifyCertificateChain } from '../../chain.js';
import { makeCertificate } from '../fixtures.js';

/**
 * self-issued な鍵ローテーション（同一 subject DN・別鍵）を含むチェーンを組む。
 *
 * ```
 *   leaf ─署名─ rolled(subject "Rollover CA", issuer "Rollover CA")
 *               └─署名─ original(subject "Rollover CA", issuer "Root CA")
 *                       └─署名─ root(anchor)
 * ```
 *
 * 辿る順は leaf → rolled → original で、2 段目と 3 段目の subject DN が同一になる。
 */
function rolloverChain(): {
  rootDer: Uint8Array;
  intermediatesDer: Uint8Array[];
  leafDer: Uint8Array;
} {
  const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true, keyUsage: ['keyCertSign'] });
  // Root が発行した中間 CA（旧鍵）。
  const original = makeCertificate({
    cn: 'Rollover CA',
    kind: 'ec',
    ca: true,
    keyUsage: ['keyCertSign'],
    issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
  });
  // 同じ subject DN を名乗り、旧鍵で署名された新鍵証明書（RFC 5280 の self-issued）。
  const rolled = makeCertificate({
    cn: 'Rollover CA',
    kind: 'ec',
    ca: true,
    keyUsage: ['keyCertSign'],
    issuer: { name: original.subjectName, privateKey: original.privateKey, kind: 'ec' },
  });
  const leaf = makeCertificate({
    cn: 'QTSP Issuer',
    kind: 'ec',
    issuer: { name: rolled.subjectName, privateKey: rolled.privateKey, kind: 'ec' },
  });
  return { rootDer: root.der, intermediatesDer: [rolled.der, original.der], leafDer: leaf.der };
}

describe('verifyCertificateChain（自己ループ検出）', () => {
  test('同一 subject DN を 2 度辿るチェーンは Anchor に届いても信頼しない', async () => {
    const { rootDer, intermediatesDer, leafDer } = rolloverChain();
    const result = await verifyCertificateChain(leafDer, intermediatesDer, {
      trustAnchorsDer: [rootDer],
    });
    // 検出を外すと 3 段目（`original`）で Anchor 署名が通り `trusted: true` になる。
    expect(result.trusted).toBe(false);
    expect(result.anchorSubjectDer).toBeUndefined();
  });

  test('maxDepth を広げても結果は変わらない（深さ不足ではなく DN 再利用で落ちている）', async () => {
    const { rootDer, intermediatesDer, leafDer } = rolloverChain();
    const result = await verifyCertificateChain(leafDer, intermediatesDer, {
      trustAnchorsDer: [rootDer],
      maxDepth: 16,
    });
    expect(result.trusted).toBe(false);
  });

  test('subject DN が段ごとに異なれば同じ形のチェーンは信頼する（対照）', async () => {
    const root = makeCertificate({
      cn: 'Root CA',
      kind: 'ec',
      ca: true,
      keyUsage: ['keyCertSign'],
    });
    const upper = makeCertificate({
      cn: 'Upper CA',
      kind: 'ec',
      ca: true,
      keyUsage: ['keyCertSign'],
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
    });
    const lower = makeCertificate({
      cn: 'Lower CA',
      kind: 'ec',
      ca: true,
      keyUsage: ['keyCertSign'],
      issuer: { name: upper.subjectName, privateKey: upper.privateKey, kind: 'ec' },
    });
    const leaf = makeCertificate({
      cn: 'QTSP Issuer',
      kind: 'ec',
      issuer: { name: lower.subjectName, privateKey: lower.privateKey, kind: 'ec' },
    });
    const result = await verifyCertificateChain(leaf.der, [lower.der, upper.der], {
      trustAnchorsDer: [root.der],
    });
    expect(result.trusted).toBe(true);
  });
});
