/**
 * Status List Token の非同期署名（Remote Signer）経路の回帰テスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - `createRemoteSigner`（fake KMS）で `StatusListManager.issueToken` / `signStatusListTokenAsync`
 *   が Status List Token を署名でき、`verifyStatusListToken` で検証できる。
 * - 同期 signer を渡した場合の出力が従来の `signStatusListToken` とバイト単位で一致する
 *   （既存同期 API の出力不変）。
 * - `signer.kid` が JWS ヘッダへ `alg` → `kid` → `typ` の順で反映される
 *   （`buildJwsHeader` への一本化）。
 * - `kid` 未設定時のヘッダが従来どおり `{"alg":...,"typ":"statuslist+jwt"}` である（後方互換）。
 * - `IssuerModule`も Remote Signer で Status List Token を発行できる。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { createPrivateKeySigner } from '../../credential/vc/signer.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { createRemoteSigner } from '../../keymanager/jws/remote-signer.js';
import { getP256PublicKey, signP256 } from '../../keymanager/signer.js';
import { IssuerModule } from '../module/issuer-module.js';
import { signStatusListToken, signStatusListTokenAsync } from '../status-list-token.js';
import { readStatusBit, verifyStatusListToken } from '../status-list-token-verify.js';
import { createStatusList } from '../token-status-list.js';

/** fake KMS が保持する秘密鍵（SDK 側へは一切渡さない）。 */
const KMS_KEY = new Uint8Array(32).fill(37);
/** 同期 local signer 用の秘密鍵。 */
const LOCAL_KEY = new Uint8Array(32).fill(41);

const ISSUER = 'did:key:z6MkIssuerForStatusList';
const URI = 'https://issuer.example/status/1';
const IAT = 1_767_225_600;

/** 非圧縮公開鍵（0x04 || x || y）から P-256 公開鍵 JWK を構築する。 */
function toJwk(privateKey: Uint8Array): PublicKeyJwk {
  const pub = getP256PublicKey(privateKey, false);
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

/** 秘密鍵をクロージャに閉じ込めた fake KMS 署名関数（非同期 I/O を模す）。 */
function createKmsSigner(kid?: string): ReturnType<typeof createRemoteSigner> {
  return createRemoteSigner({
    alg: 'ES256',
    publicKeyJwk: toJwk(KMS_KEY),
    ...(kid !== undefined ? { kid } : {}),
    sign: async (message: Uint8Array): Promise<Uint8Array> => {
      await Promise.resolve();
      return signP256(sha256(message), KMS_KEY);
    },
  });
}

/** コンパクト JWS のヘッダ部を JSON へデコードする。 */
function decodeHeader(jwt: string): Record<string, unknown> {
  const seg = jwt.split('.')[0] ?? '';
  return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8')) as Record<string, unknown>;
}

describe('Status List Token の非同期署名（Remote Signer）', () => {
  it('createRemoteSigner で署名した Status List Token を検証できる（受入条件 1）', async () => {
    const manager = createStatusList({ uri: URI, issuer: ISSUER, size: 128 });
    const idx = manager.allocate();
    manager.revoke(idx);

    const token = await manager.issueToken(createKmsSigner(), { iatSeconds: IAT });

    const verified = verifyStatusListToken(token, URI, toJwk(KMS_KEY));
    expect(verified.payload.iss).toBe(ISSUER);
    expect(await readStatusBit(verified, idx)).toBe(1);
    expect(await readStatusBit(verified, idx + 1)).toBe(0);
  });

  it('signStatusListTokenAsync が Remote Signer で署名できる', async () => {
    const token = await signStatusListTokenAsync(
      { issuer: ISSUER, uri: URI, bits: 1, lst: 'eNrbuRgAAhcBXQ' },
      createKmsSigner(),
      { iatSeconds: IAT },
    );
    expect(() => verifyStatusListToken(token, URI, toJwk(KMS_KEY))).not.toThrow();
  });

  it('同期 signer では非同期版と同期版の出力がバイト単位で一致する（受入条件 2）', async () => {
    const signer = createPrivateKeySigner(LOCAL_KEY, 'ES256');
    const input = { issuer: ISSUER, uri: URI, bits: 1, lst: 'eNrbuRgAAhcBXQ' } as const;
    const sync = signStatusListToken(input, signer, { iatSeconds: IAT });
    const async = await signStatusListTokenAsync(input, signer, { iatSeconds: IAT });
    expect(async).toBe(sync);
  });

  it('kid 未設定のヘッダは従来どおり alg / typ のみ（後方互換）', () => {
    const signer = createPrivateKeySigner(LOCAL_KEY, 'ES256');
    const token = signStatusListToken(
      { issuer: ISSUER, uri: URI, bits: 1, lst: 'eNrbuRgAAhcBXQ' },
      signer,
      { iatSeconds: IAT },
    );
    expect(decodeHeader(token)).toEqual({ alg: 'ES256', typ: 'statuslist+jwt' });
  });

  it('kid 設定時は alg → kid → typ の順でヘッダに反映される（受入条件 3）', async () => {
    const kid = 'arn:aws:kms:ap-northeast-1:000000000000:key/status-list';
    const token = await signStatusListTokenAsync(
      { issuer: ISSUER, uri: URI, bits: 1, lst: 'eNrbuRgAAhcBXQ' },
      createKmsSigner(kid),
      { iatSeconds: IAT },
    );
    const headerSeg = token.split('.')[0] ?? '';
    expect(Buffer.from(headerSeg, 'base64url').toString('utf8')).toBe(
      `{"alg":"ES256","kid":"${kid}","typ":"statuslist+jwt"}`,
    );
  });

  it('IssuerModule facade も Remote Signer で Token を発行できる', async () => {
    const list = createStatusList({ uri: URI, issuer: ISSUER, size: 32, purpose: 'revocation' });
    const issuer = new IssuerModule({
      issuer: ISSUER,
      signer: createKmsSigner(),
      statusLists: { revocation: list },
    });
    const vc = await issuer.issueVC('did:key:z6MkHolderRemote', {});
    await issuer.setTokenStatus(vc.id ?? '', 'revocation', 1);

    const token = await issuer.generateTokenStatusList('revocation', { iatSeconds: IAT });
    const verified = verifyStatusListToken(token, URI, toJwk(KMS_KEY));
    expect(await readStatusBit(verified, 0)).toBe(1);
  });
});
