/**
 * Remote Signer の署名失敗時に秘密情報を漏らさないことのユニットテスト。
 *
 * 外部署名サービス（KMS / HSM）の例外メッセージには鍵 ID・鍵 material・署名対象が
 * 埋め込まれ得るため、SDK は `SIGN_FAILED`（1020）へ正規化し `cause` / `context` を付けない。
 * 本テストは以下の失敗経路すべてでその不変条件を検証する:
 *
 * - 外部署名関数が同期で throw する。
 * - 外部署名関数が Promise を reject する。
 * - 外部署名関数が長さ不正の署名を返す（署名バイト列も漏らさない）。
 * - 外部署名関数が Uint8Array 以外を返す。
 * - `signatureFormat: 'der'` で DER としてパースできない値を返す。
 *
 * あわせて、省略したオプションが `Object.prototype` 汚染で別の値へ化けないことも固定する
 * （`config.messageFormat ?? 既定値` はプロトタイプ鎖を辿るため、汚染下では署名対象が
 * signing-input から digest へ黙って変わっていた）。
 */

import { describe, expect, it } from 'bun:test';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { createRemoteSigner } from '../../../../keymanager/jws/remote-signer.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { issueCredentialAsync } from '../../issue.js';
import type { VerifiableCredential } from '../../vc.js';

/** 外部署名サービスの例外メッセージに紛れ込む想定の秘密文字列。 */
const SECRET = 'boom PRIVATE_KEY_ABCDEF secret';

/** fake KMS が保持する秘密鍵（公開鍵 JWK の導出にのみ使う）。 */
const KMS_KEY = new Uint8Array(32).fill(23);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const KMS_JWK = toJwk(getP256PublicKey(KMS_KEY, false), 'P-256');

/** サンプル VC を作る。 */
function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2025-12-01T00:00:00Z',
    id: 'urn:uuid:1234',
  };
}

/** VericertsError 相当の観測可能なフィールド。 */
interface ObservedError {
  readonly message: string;
  readonly code: unknown;
  readonly context: unknown;
  readonly cause: unknown;
}

/**
 * 失敗する外部署名関数で発行を試み、投げられたエラーと外部へ渡った signing-input を返す。
 *
 * @param sign 失敗する外部署名関数。
 * @param signatureFormat 署名表現（DER パース失敗経路の検証用）。
 * @returns 捕捉したエラーと、外部署名関数が受け取った署名対象の UTF-8 文字列。
 */
async function captureFailure(
  sign: (message: Uint8Array) => Promise<Uint8Array> | Uint8Array,
  signatureFormat?: 'raw' | 'der',
): Promise<{ readonly error: unknown; readonly signingInput: string }> {
  let signingInput = '';
  const signer = createRemoteSigner({
    alg: 'ES256',
    publicKeyJwk: KMS_JWK,
    kid: 'kms-key-1',
    ...(signatureFormat !== undefined ? { signatureFormat } : {}),
    sign: (message) => {
      signingInput = new TextDecoder().decode(message);
      return sign(message);
    },
  });
  try {
    await issueCredentialAsync(sampleVc(), signer);
  } catch (error) {
    return { error, signingInput };
  }
  throw new Error('署名は失敗するはずだが成功した');
}

/**
 * 捕捉したエラーが 1020 で、秘密・signing-input を一切露出していないことを検証する。
 *
 * @param error 捕捉したエラー。
 * @param signingInput 外部署名関数へ渡った signing-input（漏洩していないことを確認する対象）。
 */
function expectNoLeak(error: unknown, signingInput: string): void {
  expect(error).toBeInstanceOf(Error);
  const observed = error as ObservedError;
  expect(observed.code).toBe('1020');
  // 秘密を運び得る経路（cause / context）は一切設定しない。
  expect(observed.cause).toBeUndefined();
  expect(observed.context).toBeUndefined();

  const serialized = JSON.stringify({
    message: observed.message,
    code: observed.code,
    context: observed.context,
    cause: observed.cause,
  });
  expect(signingInput.length).toBeGreaterThan(0);
  for (const haystack of [observed.message, serialized]) {
    expect(haystack).not.toContain(SECRET);
    expect(haystack).not.toContain('PRIVATE_KEY_ABCDEF');
    expect(haystack).not.toContain(signingInput);
    // signing-input の先頭断片（base64url ヘッダ）も含まれないこと。
    expect(haystack).not.toContain(signingInput.slice(0, 16));
  }
}

describe('Remote Signer の署名失敗は秘密情報を漏らさない（1020）', () => {
  it('外部署名関数が同期 throw しても秘密・signing-input を含まない', async () => {
    const { error, signingInput } = await captureFailure(() => {
      throw new Error(SECRET);
    });
    expectNoLeak(error, signingInput);
  });

  it('外部署名関数が Promise を reject しても秘密・signing-input を含まない', async () => {
    const { error, signingInput } = await captureFailure(() => Promise.reject(new Error(SECRET)));
    expectNoLeak(error, signingInput);
  });

  it('署名長が不正でも署名バイト列・signing-input を含まない', async () => {
    // 32 バイト（64B raw ではない）を返す壊れた外部サービスを模す。
    const { error, signingInput } = await captureFailure(() => new Uint8Array(32).fill(0xab));
    expectNoLeak(error, signingInput);
  });

  it('Uint8Array 以外を返しても秘密・signing-input を含まない', async () => {
    const { error, signingInput } = await captureFailure(
      () => SECRET as unknown as Uint8Array<ArrayBuffer>,
    );
    expectNoLeak(error, signingInput);
  });

  it('DER としてパース不能な署名でも秘密・signing-input を含まない', async () => {
    const { error, signingInput } = await captureFailure(
      () => new Uint8Array([0x30, 0x00, 0xff]),
      'der',
    );
    expectNoLeak(error, signingInput);
  });
});

describe('createRemoteSigner: Object.prototype 汚染からの防御', () => {
  it('省略した messageFormat は汚染値ではなく既定の signing-input が使われる', async () => {
    const polluted = Object.prototype as unknown as Record<string, unknown>;
    polluted.messageFormat = 'digest';
    try {
      const seen: Uint8Array[] = [];
      const signer = createRemoteSigner({
        alg: 'ES256',
        publicKeyJwk: toJwk(getP256PublicKey(KMS_KEY, false), 'P-256'),
        sign: (message) => {
          seen.push(message);
          return new Uint8Array(64);
        },
      });
      const signingInput = new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhIn0');
      await signer.sign(signingInput).catch(() => undefined);
      // 汚染された 'digest' が効くと 32B の SHA-256 が渡ってしまう。
      expect(seen).toHaveLength(1);
      expect(Array.from(seen[0] as Uint8Array)).toEqual(Array.from(signingInput));
    } finally {
      delete polluted.messageFormat;
    }
  });

  it('省略した signatureFormat は汚染値ではなく既定の raw が使われる', async () => {
    const polluted = Object.prototype as unknown as Record<string, unknown>;
    polluted.signatureFormat = 'der';
    try {
      const signer = createRemoteSigner({
        alg: 'ES256',
        publicKeyJwk: toJwk(getP256PublicKey(KMS_KEY, false), 'P-256'),
        // 'der' が効くと raw 64B の DER パースに失敗し 1020 になる。
        sign: () => new Uint8Array(64).fill(1),
      });
      const signature = await signer.sign(new TextEncoder().encode('signing-input'));
      expect(signature).toHaveLength(64);
    } finally {
      delete polluted.signatureFormat;
    }
  });
});
