/**
 * Pseudonym Attestation 発行のテスト。
 *
 * 検証観点:
 * - vct=urn:eudi:pseudonym:1 / sub=urn:pseudonym:<hash(pub)> / rp_id / iat / exp / cnf。
 * - header は `{ alg: 'ES256', typ: 'pseudonym+jwt' }`。
 * - 署名が派生公開鍵で検証できる（cnf バインド）。
 * - 同一 RP は決定的に同一 subject を発行する。
 * - 派生秘密鍵は正常系・例外系のいずれでも使用後にゼロフィルされる。
 */

import { describe, expect, spyOn, test } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { VericertsError } from '../../../errors.js';
import { getP256PublicKey, verifyP256 } from '../../../keymanager/signer.js';
import { issuePseudonymAttestation, type PseudonymAttestationOptions } from '../attestation.js';
import * as deriveModule from '../derive.js';
import { derivePseudonym } from '../derive.js';
import { PSEUDONYM_VCT } from '../types.js';

/** テスト用マスター種。 */
const MASTER_SEED = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
const ISSUER = 'urn:wallet-instance:test';
const NOW = 1_700_000_000;

/** JWT を header / payload / signature に分解し、payload をデコードする。 */
function decodeJwt(jwt: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Uint8Array;
} {
  const parts = jwt.split('.');
  const [h, p, s] = parts;
  if (h === undefined || p === undefined || s === undefined) {
    throw new Error('malformed jwt');
  }
  const dec = (seg: string) =>
    JSON.parse(new TextDecoder().decode(base64urlnopad.decode(seg))) as Record<string, unknown>;
  return {
    header: dec(h),
    payload: dec(p),
    signingInput: `${h}.${p}`,
    signature: base64urlnopad.decode(s),
  };
}

describe('issuePseudonymAttestation', () => {
  test('vct / sub / rp_id / iat / exp / cnf を設定する', () => {
    const key = derivePseudonym('rp-a.example', MASTER_SEED);
    const att = issuePseudonymAttestation('rp-a.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
    });
    const { payload } = decodeJwt(att.jwt);
    expect(payload.vct).toBe(PSEUDONYM_VCT);
    expect(payload.sub).toBe(key.subject);
    expect(att.subject).toBe(key.subject);
    expect(payload.iss).toBe(ISSUER);
    expect(payload.rp_id).toBe('rp-a.example');
    expect(payload.iat).toBe(NOW);
    expect(payload.exp).toBe(NOW + 24 * 60 * 60);
    expect((payload.cnf as { jwk: { crv: string } }).jwk.crv).toBe('P-256');
  });

  test('header は ES256 / pseudonym+jwt', () => {
    const att = issuePseudonymAttestation('rp-a.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
    });
    const { header } = decodeJwt(att.jwt);
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('pseudonym+jwt');
  });

  test('署名は派生公開鍵で検証できる（cnf バインド）', () => {
    const key = derivePseudonym('rp-a.example', MASTER_SEED);
    const att = issuePseudonymAttestation('rp-a.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
    });
    const { signingInput, signature } = decodeJwt(att.jwt);
    const digest = sha256(new TextEncoder().encode(signingInput));
    const pub = getP256PublicKey(key.privateKey, false);
    expect(verifyP256(digest, signature, pub)).toBe(true);
  });

  test('lifetimeSeconds を尊重する', () => {
    const att = issuePseudonymAttestation('rp-a.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
      lifetimeSeconds: 3600,
    });
    const { payload } = decodeJwt(att.jwt);
    expect(payload.exp).toBe(NOW + 3600);
  });

  test('同一 RP は決定的に同一 subject を発行する', () => {
    const a = issuePseudonymAttestation('rp-a.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
    });
    const b = issuePseudonymAttestation('RP-A.Example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
    });
    expect(a.subject).toBe(b.subject);
  });

  test('異なる RP は別 subject を発行する（相関不能）', () => {
    const a = issuePseudonymAttestation('rp-a.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
    });
    const b = issuePseudonymAttestation('another.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
    });
    expect(a.subject).not.toBe(b.subject);
  });

  test('cnf.jwk の x 座標が派生公開鍵と一致する', () => {
    const key = derivePseudonym('rp-a.example', MASTER_SEED);
    const att = issuePseudonymAttestation('rp-a.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
    });
    const { payload } = decodeJwt(att.jwt);
    const jwkX = (payload.cnf as { jwk: { x: string } }).jwk.x;
    const expectedX = base64urlnopad.encode(key.publicKey.subarray(1, 33));
    expect(jwkX).toBe(expectedX);
  });

  test('発行した JWT は自身の cnf.jwk 公開鍵で検証できる（10010 が守る不変条件）', () => {
    // 発行時の自己検証（assertAttestationBoundToCnf）が通ることを RP 視点で再確認する。
    const att = issuePseudonymAttestation('rp-a.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
    });
    const { payload, signingInput, signature } = decodeJwt(att.jwt);
    const jwk = (payload.cnf as { jwk: { x: string; y: string } }).jwk;
    const uncompressed = new Uint8Array(65);
    uncompressed[0] = 0x04;
    uncompressed.set(base64urlnopad.decode(jwk.x), 1);
    uncompressed.set(base64urlnopad.decode(jwk.y), 33);
    const digest = sha256(new TextEncoder().encode(signingInput));
    expect(verifyP256(digest, signature, uncompressed)).toBe(true);
  });

  // PseudonymAttestation は rpIdentifier / vct / issuedAt / expiresAt を持つ
  // （実装が spec の永続化前提のフィールドを持っていなかった乖離のうち、
  // 新規の鍵管理暗号方式を伴わない部分の回帰テスト）。
  test('rpIdentifier・vct を返し、issuedAt・expiresAt は ISO 8601 で返す', () => {
    const att = issuePseudonymAttestation('rp-a.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
    });
    expect(att.rpIdentifier).toBe('rp-a.example');
    expect(att.vct).toBe(PSEUDONYM_VCT);
    expect(att.issuedAt).toBe(new Date(NOW * 1000).toISOString());
    expect(new Date(att.issuedAt).getTime()).toBe(NOW * 1000);
    expect(att.expiresAt).toBe(new Date((NOW + 24 * 60 * 60) * 1000).toISOString());
  });

  test('lifetimeSeconds 指定時も expiresAt が issuedAt + lifetime で ISO 8601 になる', () => {
    const att = issuePseudonymAttestation('rp-a.example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
      lifetimeSeconds: 3600,
    });
    expect(att.issuedAt).toBe(new Date(NOW * 1000).toISOString());
    expect(att.expiresAt).toBe(new Date((NOW + 3600) * 1000).toISOString());
    expect(new Date(att.expiresAt).getTime() - new Date(att.issuedAt).getTime()).toBe(3600 * 1000);
  });

  test('RP 識別子が正規化される（rpIdentifier は canonicalize 後の値）', () => {
    const att = issuePseudonymAttestation('RP-A.Example', MASTER_SEED, {
      issuer: ISSUER,
      nowSeconds: NOW,
    });
    expect(att.rpIdentifier).toBe('rp-a.example');
  });

  test('RP 識別子が空なら RP_IDENTIFIER_INVALID (10201)', () => {
    try {
      issuePseudonymAttestation('', MASTER_SEED, { issuer: ISSUER, nowSeconds: NOW });
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10201');
    }
  });

  // derivePseudonym が返す派生秘密鍵は attestation.ts / siop.ts が唯一の呼び出し元で
  // あり、署名後に消去する責務を負う。derivePseudonym を spy し、内部で使われた実オブジェクトの
  // privateKey 参照を捕捉して、関数を抜けた後にゼロフィルされているかを検証する。
  test('署名完了後に派生秘密鍵をゼロフィルする', () => {
    const spy = spyOn(deriveModule, 'derivePseudonym');
    issuePseudonymAttestation('rp-a.example', MASTER_SEED, { issuer: ISSUER, nowSeconds: NOW });
    const derivedKey = spy.mock.results[0]?.value as { privateKey: Uint8Array } | undefined;
    spy.mockRestore();
    expect(derivedKey).toBeDefined();
    expect(Array.from(derivedKey?.privateKey ?? []).every((b) => b === 0)).toBe(true);
  });

  test('例外発生時（issuer 欠落）でも派生秘密鍵をゼロフィルする', () => {
    const spy = spyOn(deriveModule, 'derivePseudonym');
    // issuer を意図的に欠落させ、鍵派生後・署名前の RP_IDENTIFIER_INVALID (10201) 経路を通す。
    const invalidOpts = { nowSeconds: NOW } as unknown as PseudonymAttestationOptions;
    expect(() => issuePseudonymAttestation('rp-a.example', MASTER_SEED, invalidOpts)).toThrow(
      VericertsError,
    );
    const derivedKey = spy.mock.results[0]?.value as { privateKey: Uint8Array } | undefined;
    spy.mockRestore();
    expect(derivedKey).toBeDefined();
    expect(Array.from(derivedKey?.privateKey ?? []).every((b) => b === 0)).toBe(true);
  });
});
