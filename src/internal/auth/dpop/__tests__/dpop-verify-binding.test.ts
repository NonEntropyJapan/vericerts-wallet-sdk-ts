/**
 * DPoP の sender-constraining 回帰テスト（実鍵・モック禁止）。
 *
 * 検証内容（RFC 9449 §4.3）:
 * - `accessToken` 指定時に `expectedJkt` を省略した呼び出しは 4085 で拒否される（型を迂回した
 *   JS 呼び出しを想定）。盗んだ DPoP-bound アクセストークンに攻撃者鍵の proof を添えても通らない。
 * - ES256 / ES256K の署名は厳密に 64 バイトでなければ 4081。末尾に 1 バイト付けた 65 バイト署名
 *   （recovery 付きとみなされ切り詰められる）と DER 再符号化署名を拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import { bindAccessTokenToDpopKey, createDpopProof } from '../dpop.js';
import { computeJwkThumbprint, type DpopAlg } from '../dpop-common.js';
import { verifyDpopProof } from '../dpop-verify.js';
import type { VerifyDpopProofOptions } from '../dpop-verify-options.js';

/** テスト用の固定秘密鍵（正規の Holder 鍵 / 攻撃者鍵を alg ごとに分ける）。 */
const HOLDER_KEYS: Record<DpopAlg, Uint8Array> = {
  ES256: new Uint8Array(32).fill(7),
  ES256K: new Uint8Array(32).fill(9),
};
const ATTACKER_KEYS: Record<DpopAlg, Uint8Array> = {
  ES256: new Uint8Array(32).fill(13),
  ES256K: new Uint8Array(32).fill(17),
};

/** 固定現在時刻（エポック秒）。 */
const NOW = 1_767_225_600;

const HTM = 'POST';
const HTU = 'https://api.example.com/mcp';
const ACCESS_TOKEN = 'stolen-access-token-abc123';

/** 検証条件の既定値（`htm` / `htu` / `nowSeconds` のみ）。 */
const BASE = { htm: HTM, htu: HTU, nowSeconds: NOW } as const;

/** `verifyDpopProof` が指定コードの VericertsError を投げることを表明し、その例外を返す。 */
function expectCode(
  proof: string,
  options: VerifyDpopProofOptions,
  code: ErrorCode,
): VericertsError {
  try {
    verifyDpopProof(proof, options);
    throw new Error('should have thrown');
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(code);
    return e as VericertsError;
  }
}

describe.each<DpopAlg>([
  'ES256',
  'ES256K',
])('accessToken 指定時の expectedJkt 必須化（%s、4085）', (alg) => {
  const holder = createPrivateKeySigner(HOLDER_KEYS[alg], alg);
  const attacker = createPrivateKeySigner(ATTACKER_KEYS[alg], alg);
  const holderJkt = computeJwkThumbprint(holder.publicKeyJwk, alg);
  // RS が受け取る DPoP-bound アクセストークン。cnf.jkt は正規 Holder 鍵に束縛されている。
  const boundToken = bindAccessTokenToDpopKey({ sub: 'user-1' }, holder.publicKeyJwk, alg);

  /** 攻撃者鍵で署名した proof。`ath` は盗んだトークンから計算できるため一致してしまう。 */
  const attackerProof = createDpopProof(
    {
      htm: HTM,
      htu: HTU,
      accessToken: ACCESS_TOKEN,
      jti: '1c9d5e2a-7b34-4c61-a0f8-2e6b9d4c7a31',
      nowSeconds: NOW,
    },
    attacker,
  );

  it('expectedJkt を省略した呼び出しは拒否される（型を迂回した JS 呼び出し相当）', () => {
    // 型では表現できない組み合わせを as で作り、ランタイムガードが働くことを確認する。
    const unsafe = { ...BASE, accessToken: ACCESS_TOKEN } as unknown as VerifyDpopProofOptions;
    expectCode(attackerProof, unsafe, ErrorCodes.DPOP_KEY_BINDING_MISMATCH);
  });

  it('expectedJkt 省略時のガードは proof のデコード前に働く', () => {
    const unsafe = { ...BASE, accessToken: ACCESS_TOKEN } as unknown as VerifyDpopProofOptions;
    // proof としては形式不正（4080）だが、鍵一致確認が不能である方を優先して報告する。
    expectCode('not-a-proof', unsafe, ErrorCodes.DPOP_KEY_BINDING_MISMATCH);
  });

  it('攻撃者鍵の proof は盗んだトークンの cnf.jkt と照合されて拒否される', () => {
    const options = {
      ...BASE,
      accessToken: ACCESS_TOKEN,
      expectedJkt: boundToken.cnf.jkt,
    } as const;
    expectCode(attackerProof, options, ErrorCodes.DPOP_KEY_BINDING_MISMATCH);
  });

  it('正規 Holder 鍵の proof は cnf.jkt と一致して受理される', () => {
    const proof = createDpopProof(
      {
        htm: HTM,
        htu: HTU,
        accessToken: ACCESS_TOKEN,
        jti: '5a7e8b19-3c42-4d90-b6e1-8f2a1c5d9e47',
        nowSeconds: NOW,
      },
      holder,
    );
    const verified = verifyDpopProof(proof, {
      ...BASE,
      accessToken: ACCESS_TOKEN,
      expectedJkt: boundToken.cnf.jkt,
    });
    expect(verified.jkt).toBe(holderJkt);
    expect(boundToken.cnf.jkt).toBe(holderJkt);
  });

  it('例外に proof / アクセストークン / 鍵素材が含まれない', () => {
    const options = {
      ...BASE,
      accessToken: ACCESS_TOKEN,
      expectedJkt: boundToken.cnf.jkt,
    } as const;
    const error = expectCode(attackerProof, options, ErrorCodes.DPOP_KEY_BINDING_MISMATCH);
    const jwk = attacker.publicKeyJwk as Record<string, string>;
    expect(error.message).not.toContain(ACCESS_TOKEN);
    expect(error.message).not.toContain(attackerProof);
    expect(error.message).not.toContain(jwk.x as string);
  });
});

/** 非負整数を DER INTEGER として符号化する（最上位ビットが立つ場合は `0x00` を前置）。 */
function derInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start += 1;
  }
  const body = bytes.subarray(start);
  const content = (body[0] as number) >= 0x80 ? Uint8Array.from([0, ...body]) : body;
  return Uint8Array.from([0x02, content.length, ...content]);
}

/** 64 バイトの `R || S` を DER の `ECDSA-Sig-Value`（RFC 3279 §2.2.3）へ再符号化する。 */
function toDerSignature(signature: Uint8Array): Uint8Array {
  const r = derInteger(signature.subarray(0, 32));
  const s = derInteger(signature.subarray(32));
  return Uint8Array.from([0x30, r.length + s.length, ...r, ...s]);
}

/** proof の署名セグメントだけを差し替えた proof 文字列を組み立てる。 */
function replaceSignature(proof: string, mutate: (signature: Uint8Array) => Uint8Array): string {
  const [header, payload, signature] = proof.split('.') as [string, string, string];
  const mutated = mutate(base64urlnopad.decode(signature));
  return `${header}.${payload}.${base64urlnopad.encode(mutated)}`;
}

describe.each<DpopAlg>(['ES256', 'ES256K'])('署名長の厳密検証（%s、4081）', (alg) => {
  const signer = createPrivateKeySigner(HOLDER_KEYS[alg], alg);
  const proof = createDpopProof(
    { htm: HTM, htu: HTU, jti: '8d2f6a40-1e73-4b58-9c0a-3b7e5f1d2a96', nowSeconds: NOW },
    signer,
  );

  it('正規の 64 バイト署名は受理される', () => {
    const signature = base64urlnopad.decode(proof.split('.')[2] as string);
    expect(signature.length).toBe(64);
    expect(verifyDpopProof(proof, BASE).jti).toBe('8d2f6a40-1e73-4b58-9c0a-3b7e5f1d2a96');
  });

  it.each([
    0x00, 0x01, 0xff,
  ])('末尾に 1 バイト（0x%s）を付けた 65 バイト署名は拒否される', (tail) => {
    const mutated = replaceSignature(proof, (sig) => Uint8Array.from([...sig, tail]));
    expectCode(mutated, BASE, ErrorCodes.DPOP_SIGNATURE_INVALID);
  });

  it('DER 再符号化した署名は拒否される', () => {
    const mutated = replaceSignature(proof, toDerSignature);
    expectCode(mutated, BASE, ErrorCodes.DPOP_SIGNATURE_INVALID);
  });

  it('署名を切り詰めた 63 バイト署名は拒否される', () => {
    const mutated = replaceSignature(proof, (sig) => sig.subarray(0, 63));
    expectCode(mutated, BASE, ErrorCodes.DPOP_SIGNATURE_INVALID);
  });
});
