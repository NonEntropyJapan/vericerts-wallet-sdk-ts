/**
 * `createKmsSigner` の実行時ガードに対する TOCTOU 回帰テスト。
 *
 * `KmsProvider` は外部注入であり、`getKey` は任意の JS オブジェクトを返せる。ガードが検証した
 * プロパティを呼び出し側が**読み直す**実装だと、読むたびに違う値を返す getter を仕込むことで
 * 「検証は妥当な値で通し、実際に使われる値は不正なものへ差し替える」ガードバイパスが成立する。
 *
 * `createKmsSigner` は検証と同時に値を写し取り、以降 `getKey` の戻り値を読み直さない。したがって signer に
 * 採用されるのは常に**検証を通過した最初の読み取り値**でなければならない。
 *
 * 検証内容（いずれも写し取り導入前は失敗する）:
 * - `publicKeyJwk` が読み直しで `null` へ化けても、検証済み JWK が採用される。
 * - `kid` が読み直しで非文字列へ化けても、検証済みの `kid` が採用される。
 * - `messageFormat` が読み直しで `digest` へ化けても、`signing-input` のまま署名要求が出る。
 * - `signatureFormat` が読み直しで `der` へ化けても、`raw` として署名が解釈される。
 * - `publicKeyJwk` 内部の `kty` が読み直しで化けても、検証時点の値が固定される。
 * - descriptor の getter が throw しても 1004 へ正規化され、バックエンド由来の文言を漏らさない。
 * - `Object.prototype` を汚染しても descriptor の継承プロパティは採用されない。
 * - 文字列でない `alg` は 1030 で弾かれ、JWS ヘッダへ届かない。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, signP256 } from '../../signer.js';
import type { KmsKeyDescriptor, KmsProvider } from '../provider.js';
import { createKmsSigner } from '../provider.js';

/** HSM 内の秘密鍵（公開鍵 JWK の導出にのみ使う）。 */
const HSM_KEY = new Uint8Array(32).fill(41);

/** 非圧縮公開鍵から P-256 公開鍵 JWK を構築する。 */
function toJwk(privateKey: Uint8Array): PublicKeyJwk {
  const pub = getP256PublicKey(privateKey, false);
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const JWK = toJwk(HSM_KEY);

/** 任意の値を `getKey` の戻り値として返す provider を作る（`sign` は到達しない）。 */
function providerReturning(value: unknown): KmsProvider {
  return {
    getKey: async () => value as KmsKeyDescriptor,
    sign: async (): Promise<Uint8Array> => {
      throw new Error('sign には到達しないはずです');
    },
  };
}

/**
 * 指定プロパティが「読むたびに違う値を返す」descriptor を作る（TOCTOU の再現）。
 *
 * 1 回目の読み取りだけ `valid` を返し、2 回目以降は `hostile` を返す。ガードが値を検証したあとに
 * 呼び出し側が元オブジェクトを読み直す実装だと、検証を通っていない `hostile` が signer の
 * 構成値として採用されてしまう。`createKmsSigner` は検証と同時に値を写し取るため、
 * 採用されるのは常に検証を通った 1 回目の値でなければならない。
 */
function withAlternatingProperty(
  base: Record<string, unknown>,
  key: string,
  valid: unknown,
  hostile: unknown,
): unknown {
  let reads = 0;
  return Object.defineProperty({ ...base }, key, {
    enumerable: true,
    configurable: true,
    get: (): unknown => (reads++ === 0 ? valid : hostile),
  });
}

/** 署名対象を記録しつつ正当な 64B raw 署名を返す provider を作る。 */
function recordingProvider(descriptor: unknown, seen: Uint8Array[]): KmsProvider {
  return {
    getKey: async () => descriptor as KmsKeyDescriptor,
    sign: async (_keyId: string, message: Uint8Array): Promise<Uint8Array> => {
      seen.push(message);
      return signP256(sha256(message), HSM_KEY);
    },
  };
}

describe('createKmsSigner: descriptor の TOCTOU ガードバイパス', () => {
  it('publicKeyJwk が読み直しで null へ化けても、検証済みの JWK が採用される', async () => {
    const signer = await createKmsSigner(
      providerReturning(withAlternatingProperty({ alg: 'ES256' }, 'publicKeyJwk', JWK, null)),
      'slot-0',
    );
    expect(signer.publicKeyJwk).toEqual(JWK);
  });

  it('kid が読み直しで非文字列へ化けても、検証済みの kid が採用される', async () => {
    const signer = await createKmsSigner(
      providerReturning(
        withAlternatingProperty({ alg: 'ES256', publicKeyJwk: JWK }, 'kid', 'kid-1', {
          evil: true,
        }),
      ),
      'slot-0',
    );
    expect(signer.kid).toBe('kid-1');
  });

  it('messageFormat が読み直しで digest へ化けても、検証済みの signing-input が採用される', async () => {
    const seen: Uint8Array[] = [];
    const signer = await createKmsSigner(
      recordingProvider(
        withAlternatingProperty(
          { alg: 'ES256', publicKeyJwk: JWK },
          'messageFormat',
          'signing-input',
          'digest',
        ),
        seen,
      ),
      'slot-0',
    );
    const signingInput = new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9');
    await signer.sign(signingInput);
    // 'digest' が採用されていれば 32B の SHA-256 が渡る。
    expect(seen).toHaveLength(1);
    expect(Array.from(seen[0] as Uint8Array)).toEqual(Array.from(signingInput));
  });

  it('signatureFormat が読み直しで der へ化けても、検証済みの raw が採用される', async () => {
    const seen: Uint8Array[] = [];
    const signer = await createKmsSigner(
      recordingProvider(
        withAlternatingProperty(
          { alg: 'ES256', publicKeyJwk: JWK },
          'signatureFormat',
          'raw',
          'der',
        ),
        seen,
      ),
      'slot-0',
    );
    // 'der' が採用されていれば raw 64B の DER パースに失敗し 1020 になる。
    const signature = await signer.sign(new TextEncoder().encode('signing-input'));
    expect(signature).toHaveLength(64);
  });

  it('publicKeyJwk 内部の kty が読み直しで化けても、検証時点の値が固定される', async () => {
    let ktyReads = 0;
    const hostileJwk = Object.defineProperty({ crv: 'P-256', x: 'x', y: 'y' }, 'kty', {
      enumerable: true,
      configurable: true,
      get: (): string => (ktyReads++ === 0 ? 'EC' : 'oct'),
    });
    const signer = await createKmsSigner(
      providerReturning({ alg: 'ES256', publicKeyJwk: hostileJwk, kid: 'kid-1' }),
      'slot-0',
    );
    expect(signer.publicKeyJwk.kty).toBe('EC');
    expect(signer.kid).toBe('kid-1');
  });
});

describe('createKmsSigner: 写し取り時の例外とプロトタイプ汚染', () => {
  it('descriptor の getter が throw しても 1004 へ正規化し秘密文言を漏らさない', async () => {
    // 遅延解決する PKCS#11 adapter では現実に起こる。例外文言に PIN / 鍵ハンドルが載り得る。
    const secret = 'CKR_PIN_INCORRECT pin=1234 handle=0xdeadbeef';
    const descriptor = Object.defineProperty({ alg: 'ES256' }, 'publicKeyJwk', {
      enumerable: true,
      configurable: true,
      get: (): never => {
        throw new Error(secret);
      },
    });
    let observed: { code?: unknown; message: string; cause?: unknown; context?: unknown };
    try {
      await createKmsSigner(providerReturning(descriptor), 'slot-0');
      throw new Error('createKmsSigner が例外を投げませんでした');
    } catch (error) {
      observed = error as typeof observed;
    }
    expect(observed.code).toBe('1004');
    expect(observed.cause).toBeUndefined();
    expect(observed.context).toBeUndefined();
    expect(observed.message).not.toContain('CKR_PIN_INCORRECT');
    expect(observed.message).not.toContain('1234');
    expect(observed.message).not.toContain('0xdeadbeef');
  });

  it('Object.prototype 汚染由来の messageFormat は採用されない', async () => {
    const polluted = Object.prototype as unknown as Record<string, unknown>;
    polluted.messageFormat = 'digest';
    try {
      const seen: Uint8Array[] = [];
      const signer = await createKmsSigner(
        {
          getKey: async () => ({ alg: 'ES256', publicKeyJwk: JWK }) as KmsKeyDescriptor,
          sign: async (_keyId: string, message: Uint8Array): Promise<Uint8Array> => {
            seen.push(message);
            return signP256(sha256(message), HSM_KEY);
          },
        },
        'slot-0',
      );
      const signingInput = new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhIn0');
      await signer.sign(signingInput);
      // 継承した 'digest' が効くと 32B の SHA-256 が渡ってしまう。
      expect(Array.from(seen[0] as Uint8Array)).toEqual(Array.from(signingInput));
    } finally {
      delete polluted.messageFormat;
    }
  });

  it('文字列でない alg は 1030 で弾かれ JWS ヘッダへ届かない', async () => {
    const alg = { toString: (): string => 'ES256', toJSON: (): string => 'EdDSA' };
    let observed: { code?: unknown } | undefined;
    try {
      await createKmsSigner(providerReturning({ alg, publicKeyJwk: JWK }), 'slot-0');
    } catch (error) {
      observed = error as { code?: unknown };
    }
    expect(observed?.code).toBe('1030');
  });
});
