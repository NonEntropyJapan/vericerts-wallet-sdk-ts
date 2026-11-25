/**
 * `KmsProvider` / `createKmsSigner` のユニットテスト（実鍵・モック禁止）。
 *
 * KMS / HSM は「秘密鍵を閉じ込めたクロージャ」で代替し、SDK へは `getKey` / `sign` の 2 メソッド
 * だけを渡す。検証は既存の `verifyCredential` / `verifySdJwt` 経路をそのまま用いる。
 *
 * 検証内容:
 * - PKCS#11 形（raw 署名）の adapter で JWT-VC を発行し既存検証経路で通る。
 * - KMIP 形（DER 署名）の adapter でも通る = 双方を同一インターフェースで実装できる。
 * - クラウド KMS 形（事前ハッシュ + DER）でも通り、外部へ渡るのが 32B digest である。
 * - `createSdJwtAsync` でも SD-JWT VC を発行できる。
 * - `kid` の header 反映と、未設定時に `kid` を出力しないこと。
 * - `keyId` が `sign` までそのまま伝わる（1 provider で複数鍵を扱える）。
 * - 秘密鍵 material が provider 境界を越えない = provider の `sign` が受け取るのは
 *   `(keyId, signing-input)` の 2 引数のみで、`message` は signing-input と正確に一致し、
 *   HSM 内秘密鍵のバイト列を部分列として含まない。
 *
 * エラー正規化（1004 / 1020 / 1030）は `kms-provider.errors.test.ts` で検証する。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { createSdJwtAsync } from '../../../credential/sdjwt/sdjwt.js';
import { verifySdJwt } from '../../../credential/sdjwt/verify.js';
import { issueCredentialAsync } from '../../../credential/vc/issue.js';
import type { VerifiableCredential } from '../../../credential/vc/vc.js';
import { verifyCredential } from '../../../credential/vc/verify.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, p1363ToDer, signP256 } from '../../signer.js';
import type { KmsKeyDescriptor, KmsProvider } from '../provider.js';
import { createKmsSigner } from '../provider.js';

/** HSM 内に閉じ込めた秘密鍵（SDK 側へは一切渡さない）。 */
const HSM_KEY = new Uint8Array(32).fill(41);
/** 同一 provider が扱う 2 本目の鍵（`keyId` ルーティングの検証用）。 */
const HSM_KEY_2 = new Uint8Array(32).fill(43);

/** テスト用の固定現在時刻・発行日時・有効期限。 */
const NOW = 1_767_225_600;
const ISSUANCE = '2025-12-01T00:00:00Z';
const EXPIRATION = '2027-01-01T00:00:00Z';

/** 非圧縮公開鍵（0x04 || x || y）から P-256 公開鍵 JWK を構築する。 */
function toJwk(privateKey: Uint8Array): PublicKeyJwk {
  const pub = getP256PublicKey(privateKey, false);
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const JWK = toJwk(HSM_KEY);
const JWK_2 = toJwk(HSM_KEY_2);

/** `keyId` → 秘密鍵の対応（HSM のトークン内スロットを模す）。 */
const SLOTS: Record<string, Uint8Array> = Object.assign(Object.create(null), {
  'slot-0': HSM_KEY,
  'slot-1': HSM_KEY_2,
});

/** provider の `sign` が 1 回の呼び出しで受け取った引数。 */
interface SignCall {
  readonly keyId: string;
  readonly message: Uint8Array;
  /** `keyId` / `message` 以外に渡された引数（SDK は渡さないので常に空のはず）。 */
  readonly extraArgs: readonly unknown[];
}

/** fake HSM の挙動設定（バックエンドごとの入出力表現を模す）。 */
interface FakeHsmOptions {
  /** 受け取る message が digest 済みか（`messageFormat: 'digest'` と対応）。 */
  readonly prehashed?: boolean;
  /** DER 署名を返すか（`signatureFormat: 'der'` と対応）。 */
  readonly der?: boolean;
  /** JWS ヘッダへ載せる `kid`。 */
  readonly kid?: string;
  /** `sign` が受け取った引数を記録する。 */
  readonly calls?: SignCall[];
}

/** `haystack` が `needle` のバイト列を連続部分列として含むか判定する。 */
function containsSubsequence(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || needle.length > haystack.length) {
    return false;
  }
  for (let offset = 0; offset <= haystack.length - needle.length; offset += 1) {
    if (needle.every((byte, index) => haystack[offset + index] === byte)) {
      return true;
    }
  }
  return false;
}

/**
 * 秘密鍵をクロージャに閉じ込めた fake HSM を `KmsProvider` として構築する。
 *
 * SDK へ渡るのは `getKey` / `sign` の 2 メソッドのみで、鍵 material は渡らない。
 */
function fakeHsm(opts: FakeHsmOptions = {}): KmsProvider {
  return {
    getKey: async (keyId: string): Promise<KmsKeyDescriptor> => {
      const privateKey = SLOTS[keyId];
      if (privateKey === undefined) {
        throw new Error('no such slot');
      }
      return {
        alg: 'ES256',
        publicKeyJwk: toJwk(privateKey),
        ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
        ...(opts.prehashed === true ? { messageFormat: 'digest' as const } : {}),
        ...(opts.der === true ? { signatureFormat: 'der' as const } : {}),
      };
    },
    sign: async (
      keyId: string,
      message: Uint8Array,
      ...extraArgs: readonly unknown[]
    ): Promise<Uint8Array> => {
      opts.calls?.push({ keyId, message, extraArgs });
      const privateKey = SLOTS[keyId];
      if (privateKey === undefined) {
        throw new Error('no such slot');
      }
      const digest = opts.prehashed === true ? message : sha256(message);
      const raw = signP256(digest, privateKey);
      return opts.der === true ? p1363ToDer(raw, 'p256') : raw;
    },
  };
}

/** サンプル VC を作る。 */
function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: ISSUANCE,
    expirationDate: EXPIRATION,
    id: 'urn:uuid:kms-383',
  };
}

/** JWT のヘッダセグメントをデコードする。 */
function decodeHeader(jwt: string): Record<string, unknown> {
  const headerSeg = jwt.split('.')[0] ?? '';
  return JSON.parse(Buffer.from(headerSeg, 'base64url').toString('utf-8'));
}

describe('createKmsSigner + issueCredentialAsync（バックエンド別 adapter）', () => {
  it('PKCS#11 形（signing-input + raw 署名）の provider で JWT-VC を発行し検証できる', async () => {
    const signer = await createKmsSigner(fakeHsm(), 'slot-0');
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    const result = verifyCredential(jwt, { key: { publicKeyJwk: JWK }, nowSeconds: NOW });
    expect(result.header.alg).toBe('ES256');
    expect(result.payload.iss).toBe('did:example:issuer');
    expect((result.payload.vc as VerifiableCredential).credentialSubject.name).toBe('Alice');
  });

  it('KMIP 形（DER 署名）の provider でも同一インターフェースで発行できる', async () => {
    const signer = await createKmsSigner(fakeHsm({ der: true }), 'slot-0');
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    const result = verifyCredential(jwt, { key: { publicKeyJwk: JWK }, nowSeconds: NOW });
    expect(result.header.alg).toBe('ES256');
  });

  it('クラウド KMS 形（事前ハッシュ + DER）では 32B digest が provider へ渡る', async () => {
    const calls: SignCall[] = [];
    const signer = await createKmsSigner(fakeHsm({ prehashed: true, der: true, calls }), 'slot-0');
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    expect(() =>
      verifyCredential(jwt, { key: { publicKeyJwk: JWK }, nowSeconds: NOW }),
    ).not.toThrow();
    expect(calls).toHaveLength(1);
    expect(calls[0]?.message).toHaveLength(32);
  });

  it('createSdJwtAsync でも SD-JWT VC を発行し検証できる', async () => {
    const signer = await createKmsSigner(fakeHsm(), 'slot-0');
    const vct = 'https://example.com/credentials/identity';
    const sdJwt = await createSdJwtAsync(signer, {
      vct,
      issuer: 'did:example:issuer',
      disclosureClaims: ['name'],
      claims: { name: 'Alice', sub: 'did:example:holder' },
      salts: { name: 'salt-name' },
    });
    const result = verifySdJwt(sdJwt, { issuerKey: JWK, expectedVct: vct });
    expect(result.vct).toBe(vct);
    expect(result.claims.name).toBe('Alice');
  });
});

describe('createKmsSigner の鍵メタデータ反映', () => {
  it('descriptor の kid が JWS ヘッダへ反映される', async () => {
    const signer = await createKmsSigner(fakeHsm({ kid: 'did:example:issuer#hsm-1' }), 'slot-0');
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    expect(decodeHeader(jwt).kid).toBe('did:example:issuer#hsm-1');
  });

  it('descriptor に kid が無ければ JWS ヘッダに kid を出力しない', async () => {
    const signer = await createKmsSigner(fakeHsm(), 'slot-0');
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    expect(decodeHeader(jwt)).not.toHaveProperty('kid');
  });

  it('keyId が sign までそのまま伝わり、1 provider で複数鍵を扱える', async () => {
    const calls: SignCall[] = [];
    const provider = fakeHsm({ calls });
    const signer = await createKmsSigner(provider, 'slot-1');
    expect(signer.publicKeyJwk).toEqual(JWK_2);

    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    expect(calls[0]?.keyId).toBe('slot-1');
    // slot-1 の鍵で検証が通り、slot-0 の鍵では通らない。
    expect(() =>
      verifyCredential(jwt, { key: { publicKeyJwk: JWK_2 }, nowSeconds: NOW }),
    ).not.toThrow();
    expect(() => verifyCredential(jwt, { key: { publicKeyJwk: JWK }, nowSeconds: NOW })).toThrow();
  });

  it('provider へ渡るのは signing-input のみで、秘密鍵 material は境界を越えない', async () => {
    const calls: SignCall[] = [];
    const signer = await createKmsSigner(fakeHsm({ kid: 'k1', calls }), 'slot-0');
    expect(Object.keys(signer).sort()).toEqual(['alg', 'kid', 'publicKeyJwk', 'sign']);

    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    const [header, payload] = jwt.split('.');
    const signingInput = new TextEncoder().encode(`${header}.${payload}`);

    expect(calls).toHaveLength(1);
    // 渡っているのは署名対象そのもの（signing-input）だけである。
    expect(calls[0]?.message).toEqual(signingInput);
    expect(calls[0]?.keyId).toBe('slot-0');
    expect(calls[0]?.extraArgs).toEqual([]);
    // 鍵 material はバイト列としても混入しない。
    expect(containsSubsequence(calls[0]?.message ?? new Uint8Array(), HSM_KEY)).toBe(false);
  });
});
