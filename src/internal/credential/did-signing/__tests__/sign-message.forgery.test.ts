/**
 * 回帰テスト（RFC 7797 + `crit` 方式）: `did_signMessage` の署名は、DID 署名鍵で署名する他の JWT
 * （VC-JWT / VP-JWT / SD-JWT VC / did:jwt / Status List Token / id_token / proof JWT）としては受理されない。
 *
 * 攻撃: dApp が JWT の claims set を base64url にした文字列をメッセージとして渡し、返った JWS の署名を
 * `header.<message>.signature` に付け替えて、ユーザーの DID 名義の JWT を作る。署名の中身（`b64:false` /
 * `crit:["b64"]` のヘッダ付き signing-input）は付け替え後の signing-input と一致するので、署名そのものは有効に
 * 検証できてしまう（= `crit` を無視する非準拠の検証器なら受理しうる）。RFC 7515 §4.1.11 により `crit` を理解
 * しない検証器は JWS を拒否しなければならず、本 SDK の全検証経路はこれに従って拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes } from '../../../errors.js';
import { NOW } from '../../../identity/jwt/__tests__/jwt-fixtures.js';
import { resolveDidJwt } from '../../../identity/jwt/method-jwt.js';
import { verifyStatusListToken } from '../../../issuer/status-list-token-verify.js';
import { sampleVp } from '../../presentation/__tests__/presentation.fixtures.js';
import { issuePresentation } from '../../presentation/issue.js';
import { verifyPresentation } from '../../presentation/presentation.js';
import { verifySdJwt } from '../../sdjwt/verify.js';
import { issueCredential } from '../../vc/issue.js';
import { decodeCompactJws, verifyWithJwk } from '../../vc/jws.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../vc/signer.js';
import { verifyCredential } from '../../vc/verify.js';
import { signMessageJws } from '../sign-message.js';

const encoder = new TextEncoder();

const ALGS = ['ES256', 'ES256K', 'EdDSA'] as const;
const DID = 'did:example:victim';

function victimSigner(alg: (typeof ALGS)[number]): CredentialSigner {
  const signer = createPrivateKeySigner(new Uint8Array(32).fill(9), alg);
  return { ...signer, kid: `${DID}#key-1` };
}

/** dApp が攻撃として渡す claims（正当な署名なら受理される JWT の payload）を作り、wallet の返す JWS から偽 JWT を組み立てる。 */
async function forge(signer: CredentialSigner, claims: unknown) {
  const message = base64urlnopad.encode(encoder.encode(JSON.stringify(claims)));
  const jws = await signMessageJws(message, signer);
  const [header, , signature] = jws.split('.') as [string, string, string];
  return { forged: `${header}.${message}.${signature}`, header, message, signature };
}

describe.each([...ALGS])('did_signMessage の署名は JWT として受理されない [%s]', (alg) => {
  const signer = victimSigner(alg);
  const key = { publicKeyJwk: signer.publicKeyJwk as Record<string, unknown> };

  it('前提: 付け替え後の signing-input に対して署名自体は有効（crit だけが防いでいる）', async () => {
    const { forged, header, message, signature } = await forge(signer, { iss: DID });
    expect(forged.split('.')).toHaveLength(3);
    expect(
      verifyWithJwk(
        alg,
        {
          signingInput: encoder.encode(`${header}.${message}`),
          signature: base64urlnopad.decode(signature),
        },
        signer.publicKeyJwk,
      ),
    ).toBe(true);
    // 付け替え後のヘッダは crit を持ち、b64:false を宣言している。
    expect(() => decodeCompactJws(forged)).toThrow(
      expect.objectContaining({ code: ErrorCodes.INVALID_DID }),
    );
  });

  it('VC-JWT: 同じ claims を通常署名した JWT は受理され、wallet の署名の付け替えは 3010 で拒否される', async () => {
    const vc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: DID,
      credentialSubject: { id: DID, role: 'admin' },
      issuanceDate: '2025-12-01T00:00:00Z',
      expirationDate: '2027-01-01T00:00:00Z',
      id: 'urn:uuid:forged-vc',
    };
    const honest = issueCredential(vc, signer, { nowSeconds: NOW });
    expect(verifyCredential(honest, { key, nowSeconds: NOW }).payload.jti).toBe(
      'urn:uuid:forged-vc',
    );
    const { forged } = await forge(signer, decodeCompactJws(honest).payload);
    expect(() => verifyCredential(forged, { key, nowSeconds: NOW })).toThrow(
      expect.objectContaining({ code: ErrorCodes.SIG_INVALID }),
    );
  });

  it('VP-JWT: 通常署名は受理され、付け替えは 3010 で拒否される', async () => {
    const honest = issuePresentation(sampleVp({ holder: DID }), signer, {
      audience: 'https://verifier.example',
      nonce: 'n-1',
      nowSeconds: NOW,
    });
    const opts = {
      key,
      expectedAudience: 'https://verifier.example',
      expectedNonce: 'n-1',
      nowSeconds: NOW,
    };
    expect(verifyPresentation(honest, opts).presentation.holder).toBe(DID);
    const { forged } = await forge(signer, decodeCompactJws(honest).payload);
    expect(() => verifyPresentation(forged, opts)).toThrow(
      expect.objectContaining({ code: ErrorCodes.SIG_INVALID }),
    );
  });

  it('SD-JWT VC の Issuer-signed JWT: 付け替えは 3010 で拒否される', async () => {
    const { forged } = await forge(signer, { iss: DID, vct: 'urn:example:vct', iat: NOW });
    expect(() =>
      verifySdJwt(`${forged}~`, { issuerKey: signer.publicKeyJwk as never, nowSeconds: NOW }),
    ).toThrow(expect.objectContaining({ code: ErrorCodes.SIG_INVALID }));
  });

  it('id_token / proof JWT / DLC 等の共通デコード（decodeCompactJws）は crit 付きヘッダを拒否する', async () => {
    const { forged } = await forge(signer, {
      iss: DID,
      sub: DID,
      aud: 'https://rp.example',
      nonce: 'n-1',
      iat: NOW,
      exp: NOW + 600,
    });
    expect(() => decodeCompactJws(forged)).toThrow(
      expect.objectContaining({ code: ErrorCodes.INVALID_DID }),
    );
  });

  it('did:jwt: 付け替えた JWT を DID として解決できない（INVALID_DID）', async () => {
    const { forged } = await forge(signer, { iss: DID, iat: NOW });
    expect(() => resolveDidJwt(`did:jwt:${forged}`, NOW)).toThrow(
      expect.objectContaining({ code: ErrorCodes.INVALID_DID }),
    );
  });

  it('Status List Token: 付け替えを拒否する', async () => {
    const { forged } = await forge(signer, {
      sub: 'https://i.example/s/1',
      status_list: { bits: 1, lst: '' },
    });
    expect(() =>
      verifyStatusListToken(forged, 'https://i.example/s/1', signer.publicKeyJwk as never),
    ).toThrow();
  });

  it('header を crit なしに書き換えれば署名が合わなくなる（crit を剥がして通すことはできない）', async () => {
    const { message, signature } = await forge(signer, { iss: DID });
    const stripped = base64urlnopad.encode(
      encoder.encode(JSON.stringify({ alg, kid: `${DID}#key-1` })),
    );
    expect(
      verifyWithJwk(
        alg,
        {
          signingInput: encoder.encode(`${stripped}.${message}`),
          signature: base64urlnopad.decode(signature),
        },
        signer.publicKeyJwk,
      ),
    ).toBe(false);
  });
});
