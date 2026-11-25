/**
 * SD-JWT VC の `typ`（`dc+sd-jwt` 既定 / `vc+sd-jwt` 後方互換）の回帰テスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - 発行の既定 `typ` が `dc+sd-jwt`（同期版 / 非同期版とも）。
 * - 旧 `vc+sd-jwt` での発行は明示指定した場合のみ（opt-in）。
 * - 受理対象外の `typ` を発行時に指定すると 3002 で拒否する。
 * - 検証は `dc+sd-jwt` / `vc+sd-jwt` の双方を受理する（移行期間の後方互換）。
 * - 別 `typ`（`kb+jwt` 等）は 3002 で拒否する（typ 混同の防止）。
 * - `typ` 欠落は受理する（後方互換。`typ` は署名対象なので剥奪は署名破壊を伴う）。
 * - 検証順は「Issuer JWT 署名検証 → `typ` 検証」（署名不正が先に 3010 で落ちる）。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import { type CreateSdJwtOptions, createSdJwt, createSdJwtAsync } from '../sdjwt.js';
import type { SdJwtVcTyp } from '../typ.js';
import { verifySdJwt } from '../verify.js';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const VCT = 'https://example.com/credentials/identity';

/** 開示クレームを 1 つ含む発行オプションを作る（`typ` は任意で上書き）。 */
function input(typ?: SdJwtVcTyp): CreateSdJwtOptions {
  const base = {
    vct: VCT,
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
  };
  return typ === undefined ? base : { ...base, typ };
}

/** Issuer-signed JWT のヘッダを JSON として取り出す。 */
function decodeHeader(sdJwt: string): Record<string, unknown> {
  const headerSeg = (sdJwt.split('~')[0] as string).split('.')[0] as string;
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(headerSeg)));
}

/** 任意のヘッダを手組みし、指定鍵（既定は実 issuer 鍵）で署名した SD-JWT（Disclosure なし）を作る。 */
function issueWithRawHeader(header: Record<string, unknown>, signer = ISSUER_SIGNER): string {
  const b64uText = (t: string): string => Buffer.from(t).toString('base64url');
  const payload = { vct: VCT, _sd: [], _sd_alg: 'sha-256' };
  const signingInput = `${b64uText(JSON.stringify(header))}.${b64uText(JSON.stringify(payload))}`;
  const sig = signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(sig).toString('base64url')}~`;
}

describe('SD-JWT VC の typ 発行', () => {
  it('createSdJwt の既定 typ は dc+sd-jwt', () => {
    expect(decodeHeader(createSdJwt(ISSUER_SIGNER, input())).typ).toBe('dc+sd-jwt');
  });

  it('createSdJwtAsync の既定 typ も dc+sd-jwt', async () => {
    const sdJwt = await createSdJwtAsync(ISSUER_SIGNER, input());
    expect(decodeHeader(sdJwt).typ).toBe('dc+sd-jwt');
  });

  it('旧 typ（vc+sd-jwt）での発行は明示指定した場合のみ', () => {
    expect(decodeHeader(createSdJwt(ISSUER_SIGNER, input('vc+sd-jwt'))).typ).toBe('vc+sd-jwt');
  });

  it('受理対象外の typ を指定すると VC_SCHEMA_INVALID（3002）', () => {
    const opts = input('JWT' as SdJwtVcTyp);
    expect(() => createSdJwt(ISSUER_SIGNER, opts)).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });
});

describe('SD-JWT VC の typ 検証', () => {
  it('dc+sd-jwt で発行された SD-JWT を受理する', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, input());
    expect(verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK }).claims.name).toBe('Alice');
  });

  it('vc+sd-jwt で発行された SD-JWT も受理する（後方互換）', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, input('vc+sd-jwt'));
    expect(verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK }).claims.name).toBe('Alice');
  });

  it('typ 欠落のヘッダも受理する（後方互換。typ は署名対象なので剥奪は署名破壊を伴う）', () => {
    const sdJwt = issueWithRawHeader({ alg: 'ES256' });
    expect(verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK }).vct).toBe(VCT);
  });

  it('別 typ（kb+jwt）のヘッダは VC_SCHEMA_INVALID（3002、typ 混同の防止）', () => {
    const sdJwt = issueWithRawHeader({ alg: 'ES256', typ: 'kb+jwt' });
    expect(() => verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK })).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('署名不正かつ typ も不正なら SIG_INVALID（3010）が先に出る', () => {
    // Issuer JWT の署名を確認した後で typ を調べる。typ を先に見ると、真正性が未確定の
    // JWT に対して 3002 を返してしまい仕様と失敗面が食い違う。
    const otherSigner = createPrivateKeySigner(new Uint8Array(32).fill(9), 'ES256');
    const sdJwt = issueWithRawHeader({ alg: 'ES256', typ: 'kb+jwt' }, otherSigner);
    expect(() => verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });
});
