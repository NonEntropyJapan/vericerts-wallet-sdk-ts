/**
 * Status List Token の JOSE ヘッダ `typ` 検証（RFC 8725 §3.11 / draft-ietf-oauth-status-list §5.1）。
 *
 * 同じ Issuer 鍵が署名した別種の JWT（`vc+jwt` 等）が、`sub` と `status_list` を含むだけで
 * Status List Token として受理されないこと（欠落・`JWT` も同様に fail-closed）。
 *
 * エラーコードは構造不正の 3002（`VC_SCHEMA_INVALID`）。署名は検証済みで改ざんではなく「別種の JWT を
 * 渡された」ことを表すため、署名不一致の 3010 は使わない（SD-JWT VC の `typ` 混同・Go 実装と
 * 同じ規約）。署名自体が不正な Token は typ に依らず従来どおり 3010。
 */

import { describe, expect, it } from 'bun:test';
import { signCompactJws } from '../../../credential/vc/compact-jws.js';
import { decodeCompactJws } from '../../../credential/vc/jws.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getEd25519PublicKey } from '../../../keymanager/ed25519.js';
import { createStatusListResolver } from '../../status-list-resolver.js';
import { STATUS_LIST_TOKEN_TYP } from '../../status-list-token.js';
import { StatusListManager } from '../../token-status-list.js';

const SEED = new Uint8Array(32).fill(31);
const SIGNER = createPrivateKeySigner(SEED, 'EdDSA');
const ISSUER_JWK: PublicKeyJwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: Buffer.from(getEd25519PublicKey(SEED)).toString('base64url'),
};
const URI = 'https://issuer.example/status/typ';

const MANAGER = new StatusListManager({
  uri: URI,
  issuer: 'did:web:issuer.example',
  size: 16,
  bits: 1,
});
const REF = MANAGER.reference(MANAGER.allocate());

/** 正規の Token と同じ payload を、指定ヘッダ（同じ鍵で署名）で組み直す。 */
async function reissueWithHeader(header: Record<string, unknown>): Promise<string> {
  const genuine = await MANAGER.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
  return signCompactJws({ alg: 'EdDSA', ...header }, decodeCompactJws(genuine).payload, SIGNER);
}

async function resolveWith(token: string): Promise<unknown> {
  const resolver = createStatusListResolver({
    fetchToken: async () => token,
    issuerPublicKey: ISSUER_JWK,
    purpose: 'revocation',
    nowSeconds: () => 1_700_000_100,
  });
  return resolver.resolve(REF);
}

describe('Status List Token の typ 検証', () => {
  it('typ=statuslist+jwt の Token は受理される（対照）', async () => {
    const token = await reissueWithHeader({ typ: STATUS_LIST_TOKEN_TYP });

    expect(await resolveWith(token)).toMatchObject({ valid: true, value: 0 });
  });

  const rejected: readonly [string, Record<string, unknown>][] = [
    ['vc+jwt', { typ: 'vc+jwt' }],
    ['JWT', { typ: 'JWT' }],
    ['欠落', {}],
    ['文字列でない', { typ: 1 }],
  ];

  for (const [label, header] of rejected) {
    it(`typ が${label}の Token は VC_SCHEMA_INVALID（3002）で拒否される`, async () => {
      const token = await reissueWithHeader(header);

      const error = await resolveWith(token).catch((e: unknown) => e);

      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
    });
  }

  it('typ が不正でも署名が不正な Token は SIG_INVALID（3010）で拒否される（署名検証が先）', async () => {
    const token = await reissueWithHeader({ typ: 'vc+jwt' });
    const [h, p, s] = token.split('.');
    const flipped = `${s?.slice(0, -2)}${s?.endsWith('AA') ? 'BB' : 'AA'}`;

    const error = await resolveWith(`${h}.${p}.${flipped}`).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.SIG_INVALID);
  });

  it('別の鍵で署名された Token は typ が正しくても SIG_INVALID（3010）のまま（署名不一致は 3010）', async () => {
    const token = await reissueWithHeader({ typ: STATUS_LIST_TOKEN_TYP });
    const other = createStatusListResolver({
      fetchToken: async () => token,
      issuerPublicKey: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(getEd25519PublicKey(new Uint8Array(32).fill(32))).toString('base64url'),
      },
      purpose: 'revocation',
      nowSeconds: () => 1_700_000_100,
    });

    const error = await other.resolve(REF).catch((e: unknown) => e);

    expect((error as VericertsError).code).toBe(ErrorCodes.SIG_INVALID);
  });
});
