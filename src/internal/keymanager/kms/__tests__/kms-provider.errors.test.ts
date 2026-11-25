/**
 * `createKmsSigner` のエラー正規化と非漏洩のユニットテスト。
 *
 * PKCS#11 / KMIP バックエンド由来の例外メッセージには鍵ハンドル・PIN・接続情報が埋め込まれ得る
 * ため、SDK は `KEY_NOT_FOUND`（1004）へ正規化し `cause` / `context` を付けない。
 * 署名経路の失敗は `createRemoteSigner` が `SIGN_FAILED`（1020）へ
 * 正規化し、alg 不正は `UNSUPPORTED_ALGORITHM`（1030）で構築時に弾かれる。
 *
 * 検証内容:
 * - `getKey` が reject する → 1004、`cause` / `context` なし、秘密文字列を含まない。
 * - `getKey` が同期 throw する → 同上。
 * - `getKey` が publicKeyJwk 欠損 / 非オブジェクトを返す → 1004。
 * - descriptor 自体が配列、`publicKeyJwk` が配列 / `Uint8Array` / `kty` 欠損・空文字 → 1004。
 * - `kid` が非文字列、`messageFormat` / `signatureFormat` が列挙外（綴り誤り）→ 1004。
 * - 正当な descriptor（`digest` / `der` / `kid` 省略）は従来どおり signer を構築できる。
 * - `sign` が reject する → 1020（`createRemoteSigner` の正規化）、秘密文字列を含まない。
 * - descriptor の alg が未対応 → 1030（`createKmsSigner` の await 時点で弾かれる）。
 * - descriptor が `alg: 'EdDSA'` に digest / der を組み合わせる → 1030。
 */

import { describe, expect, it } from 'bun:test';
import { issueCredentialAsync } from '../../../credential/vc/issue.js';
import type { VerifiableCredential } from '../../../credential/vc/vc.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../signer.js';
import type { KmsKeyDescriptor, KmsProvider } from '../provider.js';
import { createKmsSigner } from '../provider.js';

/** バックエンドの例外メッセージに紛れ込む想定の秘密文字列（PIN / 鍵ハンドル）。 */
const SECRET = 'CKR_PIN_INCORRECT pin=1234 handle=0xdeadbeef';

/** HSM 内の秘密鍵（公開鍵 JWK の導出にのみ使う）。 */
const HSM_KEY = new Uint8Array(32).fill(41);

/** 非圧縮公開鍵から P-256 公開鍵 JWK を構築する。 */
function toJwk(privateKey: Uint8Array): PublicKeyJwk {
  const pub = getP256PublicKey(privateKey, false);
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const JWK = toJwk(HSM_KEY);

/** サンプル VC を作る。 */
function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2025-12-01T00:00:00Z',
    id: 'urn:uuid:kms-383-err',
  };
}

/** VericertsError 相当の観測可能なフィールド。 */
interface ObservedError {
  readonly message: string;
  readonly code: unknown;
  readonly context: unknown;
  readonly cause: unknown;
}

/** 投げられたエラーを観測用の形へ落とす。 */
function observe(error: unknown): ObservedError {
  const e = error as { message: string; code?: unknown; context?: unknown; cause?: unknown };
  return { message: e.message, code: e.code, context: e.context, cause: e.cause };
}

/** `createKmsSigner` が投げるエラーを捕捉する。 */
async function catchCreate(provider: KmsProvider): Promise<ObservedError> {
  try {
    await createKmsSigner(provider, 'slot-0');
  } catch (error) {
    return observe(error);
  }
  throw new Error('createKmsSigner が例外を投げませんでした');
}

/** `getKey` だけを差し替えた provider を作る（`sign` は到達しない）。 */
function providerWithGetKey(getKey: KmsProvider['getKey']): KmsProvider {
  return {
    getKey,
    sign: async (): Promise<Uint8Array> => {
      throw new Error('sign には到達しないはずです');
    },
  };
}

/** 任意の値を `getKey` の戻り値として返す provider を作る（実行時ガードの検証用）。 */
function providerReturning(value: unknown): KmsProvider {
  return providerWithGetKey(async () => value as KmsKeyDescriptor);
}

/** 実行時ガードで弾かれるべき descriptor（強化前は素通りしていたものを含む）。 */
const INVALID_DESCRIPTORS: readonly { readonly name: string; readonly value: unknown }[] = [
  { name: 'descriptor 自体が配列', value: [] },
  {
    name: '鍵メタデータを載せた配列（配列は descriptor として不可）',
    value: Object.assign([], { alg: 'ES256', publicKeyJwk: JWK }),
  },
  { name: 'publicKeyJwk が配列', value: { alg: 'ES256', publicKeyJwk: [] } },
  { name: 'publicKeyJwk が Uint8Array', value: { alg: 'ES256', publicKeyJwk: new Uint8Array() } },
  { name: 'publicKeyJwk が kty を持たない', value: { alg: 'ES256', publicKeyJwk: {} } },
  { name: 'publicKeyJwk の kty が空文字', value: { alg: 'ES256', publicKeyJwk: { kty: '' } } },
  { name: 'kid が非文字列', value: { alg: 'ES256', publicKeyJwk: JWK, kid: 123 } },
  {
    name: 'messageFormat が列挙外（綴り誤り）',
    value: { alg: 'ES256', publicKeyJwk: JWK, messageFormat: 'DIGEST' },
  },
  {
    name: 'signatureFormat が列挙外（綴り誤り）',
    value: { alg: 'ES256', publicKeyJwk: JWK, signatureFormat: 'DER' },
  },
];

describe('createKmsSigner: descriptor 形状ガードの 1004 拒否', () => {
  for (const { name, value } of INVALID_DESCRIPTORS) {
    it(`${name} の descriptor は 1004 で弾かれる`, async () => {
      const observed = await catchCreate(providerReturning(value));
      expect(observed.code).toBe('1004');
      expect(observed.cause).toBeUndefined();
      expect(observed.context).toBeUndefined();
    });
  }

  it('正当な descriptor（digest / der / kid 省略）はガードを通り signer を構築できる', async () => {
    const signer = await createKmsSigner(
      providerReturning({
        alg: 'ES256',
        publicKeyJwk: JWK,
        messageFormat: 'digest',
        signatureFormat: 'der',
      }),
      'slot-0',
    );
    expect(signer.alg).toBe('ES256');
    expect(signer.publicKeyJwk).toEqual(JWK);
    expect(signer).not.toHaveProperty('kid');
  });
});

describe('createKmsSigner: getKey 失敗の 1004 正規化', () => {
  it('getKey が reject すると 1004 になり cause / context を持たない', async () => {
    const observed = await catchCreate(
      providerWithGetKey(async () => {
        throw new Error(SECRET);
      }),
    );
    expect(observed.code).toBe('1004');
    expect(observed.cause).toBeUndefined();
    expect(observed.context).toBeUndefined();
    expect(observed.message).not.toContain(SECRET);
    expect(observed.message).not.toContain('1234');
  });

  it('getKey が同期 throw しても 1004 へ正規化される', async () => {
    const observed = await catchCreate(
      providerWithGetKey(((): never => {
        throw new Error(SECRET);
      }) as unknown as KmsProvider['getKey']),
    );
    expect(observed.code).toBe('1004');
    expect(observed.message).not.toContain(SECRET);
  });

  it('publicKeyJwk を欠く descriptor は 1004 で弾かれる', async () => {
    const observed = await catchCreate(
      providerWithGetKey(
        async () => ({ alg: 'ES256' }) as unknown as Awaited<ReturnType<KmsProvider['getKey']>>,
      ),
    );
    expect(observed.code).toBe('1004');
  });

  it('descriptor が非オブジェクトなら 1004 で弾かれる', async () => {
    const observed = await catchCreate(
      providerWithGetKey(async () => null as unknown as Awaited<ReturnType<KmsProvider['getKey']>>),
    );
    expect(observed.code).toBe('1004');
  });
});

describe('createKmsSigner: alg 不正の 1030 拒否', () => {
  it('未対応 alg の descriptor は 1030 で弾かれる', async () => {
    const observed = await catchCreate(
      providerWithGetKey(
        async () =>
          ({ alg: 'RS256', publicKeyJwk: JWK }) as unknown as Awaited<
            ReturnType<KmsProvider['getKey']>
          >,
      ),
    );
    expect(observed.code).toBe('1030');
  });

  it('alg: EdDSA に signatureFormat: der を組み合わせた descriptor は 1030 で弾かれる', async () => {
    const observed = await catchCreate(
      providerWithGetKey(async () => ({
        alg: 'EdDSA' as const,
        publicKeyJwk: JWK,
        signatureFormat: 'der' as const,
      })),
    );
    expect(observed.code).toBe('1030');
  });
});

describe('createKmsSigner: sign 失敗の 1020 正規化', () => {
  it('sign が reject すると 1020 になり秘密情報を漏らさない', async () => {
    const provider: KmsProvider = {
      getKey: async () => ({ alg: 'ES256', publicKeyJwk: JWK }),
      sign: async (): Promise<Uint8Array> => {
        throw new Error(SECRET);
      },
    };
    const signer = await createKmsSigner(provider, 'slot-0');
    let observed: ObservedError | undefined;
    try {
      await issueCredentialAsync(sampleVc(), signer, { nowSeconds: 1_767_225_600 });
    } catch (error) {
      observed = observe(error);
    }
    expect(observed?.code).toBe('1020');
    expect(observed?.cause).toBeUndefined();
    expect(observed?.context).toBeUndefined();
    expect(observed?.message).not.toContain(SECRET);
  });
});
