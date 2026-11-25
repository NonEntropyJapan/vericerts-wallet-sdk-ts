/**
 * Token Status List を EdDSA（Ed25519）で発行 → 参照解決する統合テスト（実鍵・実圧縮・モック禁止）。
 *
 * ES256 経路は `status-list.integration.test.ts` が担当し、本ファイルは
 * `status-list-resolver.ts` が EdDSA を受理するようになったことの正常系を固定する。
 *
 * 検証内容:
 * - EdDSA 署名の Status List Token を解決でき、失効前後でビットが反映される。
 * - Status List Token のヘッダ alg が `EdDSA` になっている。
 * - 別の Ed25519 鍵で検証すると 3010（fail-closed の維持）。
 */

import { describe, expect, it } from 'bun:test';
import type { StatusReference } from '../../../credential/sdjwt/sdjwt.js';
import { resolveStatus } from '../../../credential/sdjwt/status.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getEd25519PublicKey } from '../../../keymanager/ed25519.js';
import { createStatusListResolver } from '../../status-list-resolver.js';
import { StatusListManager } from '../../token-status-list.js';

const ISSUER_SEED = new Uint8Array(32).fill(23);
const OTHER_SEED = new Uint8Array(32).fill(29);
const SIGNER = createPrivateKeySigner(ISSUER_SEED, 'EdDSA');

/** Ed25519 シードから OKP 公開鍵 JWK を構築する（`y` を持たない。RFC 8037）。 */
function toOkpJwk(seed: Uint8Array): PublicKeyJwk {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(getEd25519PublicKey(seed)).toString('base64url'),
  };
}

const ISSUER_JWK = toOkpJwk(ISSUER_SEED);
const OTHER_JWK = toOkpJwk(OTHER_SEED);

const URI = 'https://issuer.example/status/1';
const ISSUER = 'did:web:issuer.example';

/** 発行済み token を URI に紐付けて返す fetchToken を作る。 */
function fetcherOf(map: Record<string, string>): (uri: string) => Promise<string> {
  return async (uri: string) => {
    const token = map[uri];
    if (token === undefined) {
      throw new Error('status list token not found for uri');
    }
    return token;
  };
}

/** 指定 token / 検証鍵で resolver を作る。 */
function resolverFor(token: string, jwk: PublicKeyJwk) {
  return createStatusListResolver({
    fetchToken: fetcherOf({ [URI]: token }),
    issuerPublicKey: jwk,
    purpose: 'revocation',
    nowSeconds: () => 1_700_000_100,
  });
}

describe('Token Status List（EdDSA / Ed25519）', () => {
  it('EdDSA で署名した Status List Token を解決でき、失効が反映される', async () => {
    const manager = new StatusListManager({ uri: URI, issuer: ISSUER, size: 100, bits: 1 });
    const idx = manager.allocate();
    const ref: StatusReference = manager.reference(idx);

    const tokenBefore = await manager.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    expect(await resolveStatus(ref, resolverFor(tokenBefore, ISSUER_JWK))).toEqual({
      valid: true,
      purpose: 'revocation',
      value: 0,
    });

    manager.revoke(idx);
    const tokenAfter = await manager.issueToken(SIGNER, { iatSeconds: 1_700_000_100 });
    expect(await resolveStatus(ref, resolverFor(tokenAfter, ISSUER_JWK))).toEqual({
      valid: false,
      purpose: 'revocation',
      value: 1,
    });
  });

  it('Status List Token のヘッダ alg が EdDSA になる', async () => {
    const manager = new StatusListManager({ uri: URI, issuer: ISSUER, size: 100, bits: 1 });
    manager.allocate();
    const token = await manager.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    const headerSeg = token.split('.')[0] ?? '';
    const header = JSON.parse(Buffer.from(headerSeg, 'base64url').toString('utf-8'));
    expect(header.alg).toBe('EdDSA');
    expect(header.typ).toBe('statuslist+jwt');
  });

  it('別の Ed25519 鍵で検証すると 3010', async () => {
    const manager = new StatusListManager({ uri: URI, issuer: ISSUER, size: 100, bits: 1 });
    const ref: StatusReference = manager.reference(manager.allocate());
    const token = await manager.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });

    try {
      await resolveStatus(ref, resolverFor(token, OTHER_JWK));
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.SIG_INVALID);
    }
  });
});
