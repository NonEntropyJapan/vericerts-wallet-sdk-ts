/**
 * verifyCertificateChain の有効期間まわりの回帰テスト。
 *
 * 境界の包含（RFC 5280: notBefore ≤ now ≤ notAfter）、期限切れ Trust Anchor の拒否、
 * 結果 `notAfter` がチェーン内（leaf・中間・anchor）の最小 `notAfter` になること
 * （rp-access の `validUntil` / JAR 判定キャッシュ TTL の根拠）を pin する。
 */

import { describe, expect, test } from 'bun:test';
import { verifyCertificateChain } from '../../chain.js';
import { makeCertificate } from '../fixtures.js';

const DAY = 86_400;
const T0 = 1_800_000_000; // 固定の基準（Unix 秒、整数）。
const at = (unixSeconds: number): Date => new Date(unixSeconds * 1000);

describe('verifyCertificateChain: 有効期間', () => {
  function leafUnderRoot(nb: number, na: number, anchorNa = T0 + 100 * DAY) {
    const root = makeCertificate({
      cn: 'Root CA',
      kind: 'ec',
      notBefore: at(T0 - 100 * DAY),
      notAfter: at(anchorNa),
    });
    const leaf = makeCertificate({
      cn: 'Leaf',
      kind: 'ec',
      notBefore: at(nb),
      notAfter: at(na),
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
    });
    return { root, leaf };
  }

  test('now == notBefore / now == notAfter は有効（両端包含）、1 秒外は拒否', async () => {
    const { root, leaf } = leafUnderRoot(T0, T0 + DAY);
    const check = (now: number) =>
      verifyCertificateChain(leaf.der, [], { trustAnchorsDer: [root.der], now });
    expect((await check(T0)).trusted).toBe(true);
    expect((await check(T0 + DAY)).trusted).toBe(true);
    expect((await check(T0 - 1)).trusted).toBe(false);
    expect((await check(T0 + DAY + 1)).trusted).toBe(false);
  });

  test('期限切れの Trust Anchor は leaf が有効でも信頼しない（境界は包含）', async () => {
    const anchorNa = T0 + 10 * DAY;
    const { root, leaf } = leafUnderRoot(T0 - DAY, T0 + 100 * DAY, anchorNa);
    const check = (now: number) =>
      verifyCertificateChain(leaf.der, [], { trustAnchorsDer: [root.der], now });
    expect((await check(anchorNa)).trusted).toBe(true);
    expect((await check(anchorNa + 1)).trusted).toBe(false);
  });

  test('まだ有効でない Trust Anchor は信頼しない', async () => {
    const root = makeCertificate({
      cn: 'Future Root',
      kind: 'ec',
      notBefore: at(T0 + DAY),
      notAfter: at(T0 + 100 * DAY),
    });
    const leaf = makeCertificate({
      cn: 'Leaf',
      kind: 'ec',
      notBefore: at(T0 - DAY),
      notAfter: at(T0 + 50 * DAY),
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
    });
    const result = await verifyCertificateChain(leaf.der, [], {
      trustAnchorsDer: [root.der],
      now: T0,
    });
    expect(result.trusted).toBe(false);
  });
});

describe('verifyCertificateChain: 結果 notAfter は最小の notAfter', () => {
  function chain(leafNa: number, interNa: number, rootNa: number) {
    const root = makeCertificate({
      cn: 'Root CA',
      kind: 'ec',
      notBefore: at(T0 - 100 * DAY),
      notAfter: at(rootNa),
    });
    const inter = makeCertificate({
      cn: 'Intermediate CA',
      kind: 'ec',
      ca: true,
      keyUsage: ['keyCertSign'],
      notBefore: at(T0 - 100 * DAY),
      notAfter: at(interNa),
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
    });
    const leaf = makeCertificate({
      cn: 'Leaf',
      kind: 'ec',
      notBefore: at(T0 - DAY),
      notAfter: at(leafNa),
      issuer: { name: inter.subjectName, privateKey: inter.privateKey, kind: 'ec' },
    });
    return { root, inter, leaf };
  }

  async function notAfterOf(leafNa: number, interNa: number, rootNa: number) {
    const { root, inter, leaf } = chain(leafNa, interNa, rootNa);
    return verifyCertificateChain(leaf.der, [inter.der], {
      trustAnchorsDer: [root.der],
      now: T0,
    });
  }

  test('leaf より短命の中間 CA の notAfter になる', async () => {
    const result = await notAfterOf(T0 + 90 * DAY, T0 + 20 * DAY, T0 + 100 * DAY);
    expect(result.trusted).toBe(true);
    expect(result.notAfter).toBe(T0 + 20 * DAY);
  });

  test('中間・leaf より短命の Trust Anchor の notAfter になる', async () => {
    const result = await notAfterOf(T0 + 90 * DAY, T0 + 80 * DAY, T0 + 5 * DAY);
    expect(result.trusted).toBe(true);
    expect(result.notAfter).toBe(T0 + 5 * DAY);
  });

  test('leaf が最短ならその notAfter になる', async () => {
    const result = await notAfterOf(T0 + 3 * DAY, T0 + 80 * DAY, T0 + 100 * DAY);
    expect(result.trusted).toBe(true);
    expect(result.notAfter).toBe(T0 + 3 * DAY);
  });
});
