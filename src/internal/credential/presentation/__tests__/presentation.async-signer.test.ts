/**
 * JWT-VP の非同期署名（Remote Signer）経路の回帰テスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - `createRemoteSigner`（fake KMS）で署名した JWT-VP が既存の `verifyPresentation` で通る。
 * - 同期 signer では `issuePresentationAsync` の出力が `issuePresentation` とバイト単位で一致する
 *   （既存同期 API の出力不変）。
 * - 不正な VP は署名前に構造検証で拒否される（非同期版でも 3002）。
 * - `signer.kid` が JWS ヘッダへ `alg` → `kid` → `typ` の順で反映される
 *   （`buildJwsHeader` への一本化）。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { createRemoteSigner } from '../../../keymanager/jws/remote-signer.js';
import { getP256PublicKey, signP256 } from '../../../keymanager/signer.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import { issuePresentation, issuePresentationAsync } from '../issue.js';
import { verifyPresentation } from '../presentation.js';
import type { VerifiablePresentation } from '../vp.js';
import { sampleVp, signerFor } from './presentation.fixtures.js';

/** fake KMS が保持する秘密鍵（SDK 側へは一切渡さない）。 */
const KMS_KEY = new Uint8Array(32).fill(43);

/** 非圧縮公開鍵（0x04 || x || y）から P-256 公開鍵 JWK を構築する。 */
function kmsJwk(): PublicKeyJwk {
  const pub = getP256PublicKey(KMS_KEY, false);
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

/** 秘密鍵をクロージャに閉じ込めた fake KMS 署名関数（非同期 I/O を模す）。 */
function createKmsSigner(kid?: string): ReturnType<typeof createRemoteSigner> {
  return createRemoteSigner({
    alg: 'ES256',
    publicKeyJwk: kmsJwk(),
    ...(kid !== undefined ? { kid } : {}),
    sign: async (message: Uint8Array): Promise<Uint8Array> => {
      await Promise.resolve();
      return signP256(sha256(message), KMS_KEY);
    },
  });
}

describe('JWT-VP の非同期署名（Remote Signer）', () => {
  it('Remote Signer で署名した VP が既存の検証経路で通る', async () => {
    const jwt = await issuePresentationAsync(sampleVp(), createKmsSigner(), {
      audience: 'did:example:verifier',
      nonce: 'n-async-1',
    });
    const result = verifyPresentation(jwt, {
      key: { publicKeyJwk: kmsJwk() },
      expectedAudience: 'did:example:verifier',
      expectedNonce: 'n-async-1',
    });
    expect(result.payload.iss).toBe('did:example:holder');
    expect(result.header.alg).toBe('ES256');
  });

  it('同期 signer では同期版とバイト単位で一致する', async () => {
    const signer = signerFor('ES256');
    // `iat` を固定する。実時刻のままだと 2 回の発行の間に秒境界をまたいで不一致になる。
    const opts = {
      audience: 'did:example:verifier',
      nonce: 'n-1',
      nowSeconds: 1_700_000_000,
    } as const;
    const sync = issuePresentation(sampleVp(), signer, opts);
    const async = await issuePresentationAsync(sampleVp(), signer, opts);
    expect(async).toBe(sync);
  });

  it('構造不正な VP は非同期版でも署名前に 3002 で拒否される', async () => {
    // holder 欠落の VP は `assertVerifiablePresentation` が 3002 で弾く。
    const broken = { ...sampleVp(), holder: '' } as unknown as VerifiablePresentation;
    const promise = issuePresentationAsync(broken, createKmsSigner());
    await expect(promise).rejects.toThrow(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.VC_SCHEMA_INVALID });
  });

  it('kid 設定時は alg → kid → typ の順でヘッダに反映される', async () => {
    const kid = 'did:example:holder#key-1';
    const jwt = await issuePresentationAsync(sampleVp(), createKmsSigner(kid));
    const headerSeg = jwt.split('.')[0] ?? '';
    expect(Buffer.from(headerSeg, 'base64url').toString('utf8')).toBe(
      `{"alg":"ES256","kid":"${kid}","typ":"JWT"}`,
    );
  });

  it('kid 未設定のヘッダは従来どおり alg / typ のみ（後方互換）', () => {
    const jwt = issuePresentation(sampleVp(), createPrivateKeySigner(KMS_KEY, 'ES256'));
    const headerSeg = jwt.split('.')[0] ?? '';
    expect(Buffer.from(headerSeg, 'base64url').toString('utf8')).toBe(
      '{"alg":"ES256","typ":"JWT"}',
    );
  });
});
