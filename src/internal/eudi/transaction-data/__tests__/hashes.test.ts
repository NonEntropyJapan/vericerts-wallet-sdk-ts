/**
 * KB-JWT hashes 計算のテスト。
 *
 * 実鍵・実 SD-JWT を用い、モックは使わない。`transaction_data_hashes` が生 base64url に対する
 * SHA-256（base64url）であること、KB-JWT が `verifySdJwt`（cnf + sd_hash）で検証成功することを確認する。
 */

import { describe, expect, test } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { type ConfirmationClaim, createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { verifySdJwt } from '../../../credential/sdjwt/verify.js';
import type { CredentialAlg } from '../../../credential/vc/jws.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { extractTransactionData } from '../extract.js';
import { addKeyBindingWithTransactionData, computeTransactionDataHashes } from '../hashes.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const HOLDER_KEY = new Uint8Array(32).fill(11);

function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const HOLDER_JWK = toJwk(getSecp256k1PublicKey(HOLDER_KEY, false), 'secp256k1');
const CNF: ConfirmationClaim = { jwk: HOLDER_JWK };
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const HOLDER_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256K' as CredentialAlg);
const VCT = 'https://example.com/credentials/identity';

function encodeTd(obj: Record<string, unknown>): string {
  return base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(obj)));
}

function issuePresentation(): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    issuer: 'did:example:issuer',
    disclosureClaims: ['name'],
    claims: { name: 'Alice', sub: 'holder-1' },
    cnf: CNF,
  });
}

function kbHeaderSeg(sdJwt: string): string {
  const kb = sdJwt.split('~').at(-1) as string;
  return kb.split('.')[0] as string;
}

function decodeKbHeader(sdJwt: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(kbHeaderSeg(sdJwt))));
}

function decodeKbPayload(sdJwt: string): Record<string, unknown> {
  const kb = sdJwt.split('~').at(-1) as string;
  const payloadSeg = kb.split('.')[1] as string;
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(payloadSeg)));
}

describe('computeTransactionDataHashes', () => {
  test('生 base64url 文字列に対する SHA-256（base64url）を入力順で返す', () => {
    const raw = [encodeTd({ type: 'payment', credential_ids: ['pid'] })];
    const entries = extractTransactionData(raw);
    const hashes = computeTransactionDataHashes(entries);
    const expected = base64urlnopad.encode(sha256(new TextEncoder().encode(raw[0] as string)));
    expect(hashes).toEqual([expected]);
  });

  test('複数要素は入力順を保持する', () => {
    const raw = [
      encodeTd({ type: 'a', credential_ids: ['c1'] }),
      encodeTd({ type: 'b', credential_ids: ['c2'] }),
    ];
    const hashes = computeTransactionDataHashes(extractTransactionData(raw));
    expect(hashes).toEqual(
      raw.map((r) => base64urlnopad.encode(sha256(new TextEncoder().encode(r)))),
    );
  });

  test('空配列は空配列', () => {
    expect(computeTransactionDataHashes([])).toEqual([]);
  });
});

describe('addKeyBindingWithTransactionData', () => {
  const raw = [encodeTd({ type: 'payment', credential_ids: ['pid'], amount: '100' })];
  const entries = extractTransactionData(raw);

  test('KB-JWT に transaction_data_hashes / alg を格納し検証成功する', () => {
    const presentation = issuePresentation();
    const bound = addKeyBindingWithTransactionData(presentation, HOLDER_SIGNER, {
      nonce: 'n-1',
      audience: 'https://verifier.example',
      transactionData: entries,
      iatSeconds: 1_712_400_000,
    });

    // cnf + sd_hash の整合が取れて検証成功する。
    const verified = verifySdJwt(bound, {
      issuerKey: ISSUER_JWK,
      expectedVct: VCT,
      audience: 'https://verifier.example',
      nonce: 'n-1',
    });
    expect(verified.keyBindingVerified).toBe(true);

    const kb = decodeKbPayload(bound);
    expect(kb.transaction_data_hashes).toEqual(computeTransactionDataHashes(entries));
    expect(kb.transaction_data_hashes_alg).toBe('sha-256');
    expect(kb.nonce).toBe('n-1');
    expect(kb.aud).toBe('https://verifier.example');
  });

  test('既に KB-JWT が付与済みの提示部には再付与しない（3010）', () => {
    const bound = addKeyBindingWithTransactionData(issuePresentation(), HOLDER_SIGNER, {
      nonce: 'n-1',
      audience: 'https://verifier.example',
      transactionData: entries,
    });
    expect(() =>
      addKeyBindingWithTransactionData(bound, HOLDER_SIGNER, {
        nonce: 'n-1',
        audience: 'https://verifier.example',
        transactionData: entries,
      }),
    ).toThrow(VericertsError);
  });

  test('Transaction Data が空なら誤用として拒否（3010）', () => {
    expect(() =>
      addKeyBindingWithTransactionData(issuePresentation(), HOLDER_SIGNER, {
        nonce: 'n-1',
        audience: 'https://verifier.example',
        transactionData: [],
      }),
    ).toThrow(VericertsError);
  });

  test('expectedHashes が一致すれば KB-JWT を生成する', () => {
    const bound = addKeyBindingWithTransactionData(issuePresentation(), HOLDER_SIGNER, {
      nonce: 'n-1',
      audience: 'https://verifier.example',
      transactionData: entries,
      expectedHashes: computeTransactionDataHashes(entries),
    });
    expect(bound.split('~').at(-1)).not.toBe('');
  });

  test('expectedHashes が不一致なら同意改ざんとして拒否（10402）', () => {
    let code = '';
    try {
      addKeyBindingWithTransactionData(issuePresentation(), HOLDER_SIGNER, {
        nonce: 'n-1',
        audience: 'https://verifier.example',
        transactionData: entries,
        expectedHashes: ['tampered-hash'],
      });
    } catch (err) {
      code = (err as VericertsError).code;
    }
    expect(code).toBe('10402');
  });
});

describe('addKeyBindingWithTransactionData — nonce / audience の検証', () => {
  const TD = extractTransactionData([encodeTd({ type: 'payment', credential_ids: ['pid'] })]);
  const VALID = { nonce: 'n-1', audience: 'https://verifier.example', transactionData: TD };

  /** nonce / audience を上書きして呼び、投げられたコードを返す（投げなければ `ok`）。 */
  function codeFor(override: Record<string, unknown>): string {
    try {
      addKeyBindingWithTransactionData(issuePresentation(), HOLDER_SIGNER, {
        ...VALID,
        ...override,
      } as typeof VALID);
    } catch (err) {
      return (err as VericertsError).code;
    }
    return 'ok';
  }

  test.each([
    ['nonce が undefined', { nonce: undefined }],
    ['nonce が空文字', { nonce: '' }],
    ['nonce が非文字列', { nonce: 123 }],
    ['audience が undefined', { audience: undefined }],
    ['audience が空文字', { audience: '' }],
    ['audience が非文字列', { audience: {} }],
  ])('%s は 3012 で拒否し KB-JWT を署名しない', (_label, override) => {
    expect(codeFor(override)).toBe('3012');
  });

  test('nonce / audience キー自体の欠落も 3012（継承値は拾わない）', () => {
    const { nonce: _n, audience: _a, ...rest } = VALID;
    expect(() =>
      addKeyBindingWithTransactionData(issuePresentation(), HOLDER_SIGNER, rest as typeof VALID),
    ).toThrow(VericertsError);
  });

  test('正しい nonce / audience なら成功する', () => {
    expect(codeFor({})).toBe('ok');
  });
});

describe('addKeyBindingWithTransactionData — KB-JWT ヘッダの kid 伝播', () => {
  /** KMS / HSM 運用で verification method ID を伝える Holder 鍵。 */
  const KID = 'did:example:holder#key-1';
  const KEYED_HOLDER_SIGNER: CredentialSigner = { ...HOLDER_SIGNER, kid: KID };
  const TD = extractTransactionData([encodeTd({ type: 'payment', credential_ids: ['pid'] })]);

  test('signer.kid 設定時に KB-JWT ヘッダへ kid が載る（キー順 alg → kid → typ）', () => {
    const presented = addKeyBindingWithTransactionData(issuePresentation(), KEYED_HOLDER_SIGNER, {
      nonce: 'n-1',
      audience: 'https://verifier.example.com',
      transactionData: TD,
      iatSeconds: 1_700_000_000,
    });
    expect(decodeKbHeader(presented)).toEqual({ alg: 'ES256K', kid: KID, typ: 'kb+jwt' });
  });

  test('kid 未設定時のヘッダセグメントは従来どおりのバイト列と一致する（後方互換）', () => {
    const presented = addKeyBindingWithTransactionData(issuePresentation(), HOLDER_SIGNER, {
      nonce: 'n-1',
      audience: 'https://verifier.example.com',
      transactionData: TD,
      iatSeconds: 1_700_000_000,
    });
    // 修正前の手組みヘッダ `{"alg":"ES256K","typ":"kb+jwt"}` と同一バイト列であること。
    const legacy = base64urlnopad.encode(
      new TextEncoder().encode(JSON.stringify({ alg: 'ES256K', typ: 'kb+jwt' })),
    );
    expect(kbHeaderSeg(presented)).toBe(legacy);
  });

  test('kid 付き KB-JWT も verifySdJwt を通る（cnf.jwk 検証は kid に依存しない）', () => {
    const presented = addKeyBindingWithTransactionData(issuePresentation(), KEYED_HOLDER_SIGNER, {
      nonce: 'n-1',
      audience: 'https://verifier.example.com',
      transactionData: TD,
    });
    const result = verifySdJwt(presented, {
      issuerKey: ISSUER_JWK,
      expectedVct: VCT,
      audience: 'https://verifier.example.com',
      nonce: 'n-1',
      requireKeyBinding: true,
    });
    expect(result.keyBindingVerified).toBe(true);
  });
});
