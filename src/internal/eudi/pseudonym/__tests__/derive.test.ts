/**
 * Pseudonym 派生のユニットテスト。
 *
 * 検証観点:
 * - 決定性: 同一 rpIdentifier + 同一 masterSeed で同一鍵・同一 subject。
 * - 継続性: canonicalize 揺れ（大文字/URL）を吸収し同一 RP を同一鍵に写像。
 * - 相関不能性: 異なる RP は相関不能な別鍵・別 subject。
 * - 不正入力: RP 識別子不正（10201）・masterSeed 不正（10202）。
 */

import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../../errors.js';
import { getP256PublicKey, signP256, verifyP256 } from '../../../keymanager/signer.js';
import { canonicalizeRpIdentifier, computePseudonymSubject, derivePseudonym } from '../derive.js';
import { PSEUDONYM_SUBJECT_PREFIX } from '../types.js';

/** テスト用の決定的な 32 バイトマスター種。 */
const MASTER_SEED = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);

describe('canonicalizeRpIdentifier', () => {
  test('FQDN を小文字化する', () => {
    expect(canonicalizeRpIdentifier('Service.Example')).toBe('service.example');
  });

  test('前後の空白を除去する', () => {
    expect(canonicalizeRpIdentifier('  rp-a.example  ')).toBe('rp-a.example');
  });

  test('URL は scheme + host の origin へ正規化する', () => {
    expect(canonicalizeRpIdentifier('https://RP-A.Example/login?x=1')).toBe('https://rp-a.example');
  });

  // prefixed client_id（`<prefix>:<URL>`）は URL 部のみ origin 化し prefix を保つ。
  test.each([
    ['origin:https://A.Example', 'origin:https://a.example'],
    ['origin:https://b.example', 'origin:https://b.example'],
    ['web-origin:https://a.example:8443/x?y=1', 'web-origin:https://a.example:8443'],
    ['redirect_uri:https://a.example/cb', 'redirect_uri:https://a.example'],
    ['Verifier_Attestation:https://a.example', 'verifier_attestation:https://a.example'],
    ['x509_san_dns:Rp.Example', 'x509_san_dns:rp.example'],
  ])('prefixed client_id %s は %s へ正規化する', (input, expected) => {
    expect(canonicalizeRpIdentifier(input)).toBe(expected);
  });

  test('異なる origin の prefixed client_id は別の正規形になる', () => {
    expect(canonicalizeRpIdentifier('origin:https://a.example')).not.toBe(
      canonicalizeRpIdentifier('origin:https://b.example'),
    );
  });

  test.each([
    'origin:https://',
    'bad prefix:https://a.example',
    'a.example/x?u=https://b.example',
  ])('不正な prefixed client_id %s は RP_IDENTIFIER_INVALID (10201)', (value) => {
    try {
      canonicalizeRpIdentifier(value);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10201');
    }
  });

  test.each(['', '   '])('空・空白のみは RP_IDENTIFIER_INVALID (10201)', (value) => {
    expect(() => canonicalizeRpIdentifier(value)).toThrow(VericertsError);
    try {
      canonicalizeRpIdentifier(value);
    } catch (e) {
      expect((e as VericertsError).code).toBe('10201');
    }
  });

  test('不正な URL は RP_IDENTIFIER_INVALID (10201)', () => {
    try {
      canonicalizeRpIdentifier('https://');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10201');
    }
  });
});

describe('derivePseudonym', () => {
  test('同一 RP + 同一 seed は決定的に同一鍵・同一 subject を返す', () => {
    const a = derivePseudonym('rp-a.example', MASTER_SEED);
    const b = derivePseudonym('rp-a.example', MASTER_SEED);
    expect(Array.from(a.privateKey)).toEqual(Array.from(b.privateKey));
    expect(Array.from(a.publicKey)).toEqual(Array.from(b.publicKey));
    expect(a.subject).toBe(b.subject);
  });

  test('canonicalize 揺れ（大文字/URL）を吸収し同一鍵を返す', () => {
    const base = derivePseudonym('rp-a.example', MASTER_SEED);
    const upper = derivePseudonym('RP-A.Example', MASTER_SEED);
    expect(upper.subject).toBe(base.subject);
    expect(Array.from(upper.privateKey)).toEqual(Array.from(base.privateKey));
  });

  test('異なる RP は相関不能な別鍵・別 subject を返す', () => {
    const a = derivePseudonym('rp-a.example', MASTER_SEED);
    const b = derivePseudonym('another.example', MASTER_SEED);
    expect(a.subject).not.toBe(b.subject);
    expect(Array.from(a.privateKey)).not.toEqual(Array.from(b.privateKey));
    expect(Array.from(a.publicKey)).not.toEqual(Array.from(b.publicKey));
  });

  test('origin: prefixed client_id でも RP ごとに別鍵を返す', () => {
    const a = derivePseudonym('origin:https://rp-a.example', MASTER_SEED);
    const b = derivePseudonym('origin:https://rp-b.example', MASTER_SEED);
    expect(Array.from(a.publicKey)).not.toEqual(Array.from(b.publicKey));
    expect(a.subject).not.toBe(b.subject);
    const again = derivePseudonym('origin:https://RP-A.example/cb', MASTER_SEED);
    expect(again.subject).toBe(a.subject);
  });

  test('異なる masterSeed は同一 RP でも別鍵を返す', () => {
    const otherSeed = new Uint8Array(32).map((_, i) => (i * 11 + 5) & 0xff);
    const a = derivePseudonym('rp-a.example', MASTER_SEED);
    const b = derivePseudonym('rp-a.example', otherSeed);
    expect(a.subject).not.toBe(b.subject);
  });

  test('派生鍵は有効な P-256 鍵ペアで、公開鍵は秘密鍵と対応する', () => {
    const key = derivePseudonym('rp-a.example', MASTER_SEED);
    expect(key.privateKey.length).toBe(32);
    expect(key.publicKey.length).toBe(33);
    expect(Array.from(getP256PublicKey(key.privateKey, true))).toEqual(Array.from(key.publicKey));
  });

  test('subject は urn:pseudonym: プレフィックスと公開鍵ハッシュから成る', () => {
    const key = derivePseudonym('rp-a.example', MASTER_SEED);
    expect(key.subject.startsWith(PSEUDONYM_SUBJECT_PREFIX)).toBe(true);
    expect(key.subject).toBe(computePseudonymSubject(key.publicKey));
  });

  test('派生鍵は署名・検証に使える（WSCD 署名の疎通確認）', () => {
    const key = derivePseudonym('rp-a.example', MASTER_SEED);
    const digest = new Uint8Array(32).fill(9);
    const sig = signP256(digest, key.privateKey);
    expect(verifyP256(digest, sig, getP256PublicKey(key.privateKey, false))).toBe(true);
  });

  test.each([
    new Uint8Array(0),
    new Uint8Array(32), // 全ゼロ = 消去済み配列の取り違え。公開値なので静かに導出しない。
    'not-bytes' as unknown as Uint8Array,
  ])('masterSeed が空・全ゼロ・非バイト列なら KEY_DERIVATION_FAILED (10202)', (seed) => {
    try {
      derivePseudonym('rp-a.example', seed);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10202');
    }
  });

  test('RP 識別子が空なら RP_IDENTIFIER_INVALID (10201)', () => {
    try {
      derivePseudonym('', MASTER_SEED);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10201');
    }
  });

  test('派生秘密鍵は例外の message / context に含まれない（RP 識別子不正時）', () => {
    try {
      derivePseudonym('', MASTER_SEED);
    } catch (e) {
      const err = e as VericertsError;
      expect(err.message).not.toContain('seed');
      expect(JSON.stringify(err.context ?? {})).not.toContain('privateKey');
    }
  });
});
