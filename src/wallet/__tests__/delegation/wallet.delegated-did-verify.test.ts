/**
 * 委任 DIDの検証側: VP / message JWS / SIOPv2 id_token を、`iss` = 委任先 DID `D`・`kid` = `V` で受理する。
 *
 * 署名はペルソナの鍵（P-256 / secp256k1）で `resolveDelegatedSigner` の署名鍵を使う。検証側は `D` の DID Document の
 * `authentication` だけを読む（`V` が `D` に埋め込まれていても、委任元ペルソナの検証メソッドへの DID URL 参照でもよい）。
 * `D` が `V` を載せなくなった・鍵が違う・失効したときは fail-closed で拒否する。did:web の `did.json` は可変で、
 * 検証のたびに解決し直す（キャッシュなし）。
 */

import { describe, expect, it } from 'bun:test';
import { generateIDToken } from '../../../internal/auth/siop/id-token.js';
import type { SIOPv2Request } from '../../../internal/auth/siop/types.js';
import { verifyIDToken } from '../../../internal/auth/siop/verify-id-token.js';
import {
  DELEGATED_DID,
  type Delegation,
  EMBEDDED_KID,
  failureOf,
  newDelegation,
} from '../../../internal/credential/did-signing/__tests__/delegation/delegation.fixtures.js';
import { NOW } from '../../../internal/credential/did-signing/__tests__/fixtures.js';
import { resolveDelegatedSigner } from '../../../internal/credential/did-signing/delegation.js';
import {
  signMessageJws,
  verifyMessageJws,
} from '../../../internal/credential/did-signing/sign-message.js';
import { sampleVp } from '../../../internal/credential/presentation/__tests__/presentation.fixtures.js';
import { issuePresentation } from '../../../internal/credential/presentation/issue.js';
import { signCompactJwsAsync } from '../../../internal/credential/vc/compact-jws.js';
import { createPrivateKeySigner } from '../../../internal/credential/vc/signer.js';
import { ErrorCodes } from '../../../internal/errors.js';
import { resolvePresentationEnvelope } from '../../credential/presentation-envelope.js';

const KEY_TYPES = ['P-256', 'secp256k1'] as const;
/** 検証メソッドの置き方: `D` に埋め込み / 委任元ペルソナの検証メソッドへの DID URL 参照。 */
const PLACEMENTS = ['embedded', 'reference'] as const;
type Placement = (typeof PLACEMENTS)[number];

const metrics = new Proxy({}, { get: () => () => undefined }) as never;
const REQUEST: SIOPv2Request = {
  scope: 'openid',
  responseType: 'id_token',
  clientId: 'https://rp.example',
  redirectUri: 'https://rp.example/cb',
  nonce: 'siop-nonce-1',
};

async function setup(keyType: (typeof KEY_TYPES)[number], placement: Placement) {
  const d = await newDelegation(keyType);
  if (placement === 'reference') {
    d.publish({ verificationMethod: [], authentication: [d.own.kid] });
  }
  const delegated = await resolveDelegatedSigner(d.world.km, d.persona, {
    delegatedDid: DELEGATED_DID,
    resolver: d.world.resolver,
  });
  return { d, delegated };
}

function vpOptions() {
  return {
    expectedAudience: 'https://verifier.example',
    expectedNonce: 'vp-nonce-1',
    nowSeconds: NOW,
  };
}

function signVp(delegated: Awaited<ReturnType<typeof setup>>['delegated']): string {
  return issuePresentation(sampleVp({ holder: DELEGATED_DID }), delegated.signer, {
    audience: 'https://verifier.example',
    nonce: 'vp-nonce-1',
    nowSeconds: NOW,
  });
}

describe.each([...KEY_TYPES])('委任 DID の検証側（%s）', (keyType) => {
  describe.each([...PLACEMENTS])('検証メソッドの置き方: %s', (placement) => {
    it('VP: holder = D、kid = V の JWT-VP を verifyPresentation の経路（authentication）で受理する', async () => {
      const { d, delegated } = await setup(keyType, placement);
      const verified = await resolvePresentationEnvelope(
        d.world.resolver,
        signVp(delegated),
        metrics,
        vpOptions(),
      );
      expect(verified.claims.asserted.holder).toBe(DELEGATED_DID);
      expect(verified.claims.header.kid).toBe(placement === 'embedded' ? EMBEDDED_KID : d.own.kid);
    });

    it('VP: D が V を authentication から外した後は拒否する（検証のたびに解決し直す）', async () => {
      const { d, delegated } = await setup(keyType, placement);
      const jwt = signVp(delegated);
      await resolvePresentationEnvelope(d.world.resolver, jwt, metrics, vpOptions());
      d.publish({ authentication: [] });
      const failure = await failureOf(
        resolvePresentationEnvelope(d.world.resolver, jwt, metrics, vpOptions()),
      );
      expect(failure?.code).toBe(ErrorCodes.DID_DOC_INVALID);
    });

    it('VP: D が失効（deactivated）したら拒否する', async () => {
      const { d, delegated } = await setup(keyType, placement);
      const jwt = signVp(delegated);
      d.publish({ deactivated: true });
      expect(
        (await failureOf(resolvePresentationEnvelope(d.world.resolver, jwt, metrics, vpOptions())))
          ?.code,
      ).toBe(ErrorCodes.DID_DOC_INVALID);
    });

    it('message JWS: expectedDid = D で受理し、署名主体は D になる', async () => {
      const { d, delegated } = await setup(keyType, placement);
      const jws = await signMessageJws('Sign in to Example', delegated.signer);
      const verified = await verifyMessageJws(jws, {
        message: 'Sign in to Example',
        resolver: d.world.resolver,
        expectedDid: DELEGATED_DID,
      });
      expect(verified.did).toBe(DELEGATED_DID);
      expect(verified.kid).toBe(placement === 'embedded' ? EMBEDDED_KID : d.own.kid);
    });

    it('message JWS: D が V を載せなくなったら拒否する', async () => {
      const { d, delegated } = await setup(keyType, placement);
      const jws = await signMessageJws('m', delegated.signer);
      d.publish({ authentication: [] });
      const failure = await failureOf(
        verifyMessageJws(jws, {
          message: 'm',
          resolver: d.world.resolver,
          expectedDid: DELEGATED_DID,
        }),
      );
      expect(failure?.code).toBe(
        placement === 'embedded' ? ErrorCodes.DID_KEY_MISMATCH : ErrorCodes.SIG_INVALID,
      );
    });

    it('SIOPv2 id_token: iss = sub = D、kid = V を受理する（sub_jwk は鍵の根拠にしない）', async () => {
      const { d, delegated } = await setup(keyType, placement);
      const token = await generateIDToken(REQUEST, DELEGATED_DID, delegated.signer, {
        nowSeconds: NOW,
      });
      const verified = await verifyIDToken(token, {
        resolver: d.world.resolver,
        expectedAudience: REQUEST.clientId,
        expectedNonce: REQUEST.nonce,
        nowSeconds: NOW,
      });
      expect(verified.did).toBe(DELEGATED_DID);
      expect(verified.kid).toBe(placement === 'embedded' ? EMBEDDED_KID : d.own.kid);
      expect(verified.claims.sub).toBe(DELEGATED_DID);
    });

    it('SIOPv2 id_token: D が V を載せなくなったら拒否する（2017）', async () => {
      const { d, delegated } = await setup(keyType, placement);
      const token = await generateIDToken(REQUEST, DELEGATED_DID, delegated.signer, {
        nowSeconds: NOW,
      });
      d.publish({ authentication: [] });
      expect(await failureOf(verifyToken(d, token))).toEqual({
        code: ErrorCodes.DID_KEY_MISMATCH,
        reason: 'relationship_not_granted',
      });
    });
  });

  it('message JWS（参照）: expectedDid を渡さなければ署名主体は kid の DID（ペルソナ）。D としては受理しない', async () => {
    const { d, delegated } = await setup(keyType, 'reference');
    const jws = await signMessageJws('m', delegated.signer);
    const verified = await verifyMessageJws(jws, { message: 'm', resolver: d.world.resolver });
    expect(verified.did).toBe(d.persona.did);
    // D を期待しても、D が V を載せていない（別ペルソナの鍵）なら拒否する。
    const stranger = await newDelegation(keyType);
    const other = createPrivateKeySigner(new Uint8Array(32).fill(9), 'ES256');
    const strangerJws = await signMessageJws('m', { ...other, kid: stranger.own.kid });
    expect(
      (
        await failureOf(
          verifyMessageJws(strangerJws, {
            message: 'm',
            resolver: d.world.resolver,
            expectedDid: DELEGATED_DID,
          }),
        )
      )?.code,
    ).toBe(ErrorCodes.SIG_INVALID);
  });

  it('鍵不一致: kid = V だが別の鍵で署名した VP / id_token / message は 3010', async () => {
    const { d, delegated } = await setup(keyType, 'embedded');
    const forger = {
      ...createPrivateKeySigner(new Uint8Array(32).fill(88), 'ES256'),
      kid: delegated.kid,
    };
    const vp = issuePresentation(sampleVp({ holder: DELEGATED_DID }), forger, {
      audience: 'https://verifier.example',
      nonce: 'vp-nonce-1',
      nowSeconds: NOW,
    });
    // ES256 以外の鍵（secp256k1 のペルソナ）では alg が合わず同様に失敗する。
    expect(
      (await failureOf(resolvePresentationEnvelope(d.world.resolver, vp, metrics, vpOptions())))
        ?.code,
    ).toBe(ErrorCodes.SIG_INVALID);
    const token = await generateIDToken(REQUEST, DELEGATED_DID, forger, { nowSeconds: NOW });
    expect((await failureOf(verifyToken(d, token)))?.code).toBe(ErrorCodes.SIG_INVALID);
    const jws = await signMessageJws('m', forger);
    expect(
      (
        await failureOf(
          verifyMessageJws(jws, {
            message: 'm',
            resolver: d.world.resolver,
            expectedDid: DELEGATED_DID,
          }),
        )
      )?.code,
    ).toBe(ErrorCodes.SIG_INVALID);
  });
});

function verifyToken(
  d: Delegation,
  token: string,
  overrides: Partial<Parameters<typeof verifyIDToken>[1]> = {},
) {
  return verifyIDToken(token, {
    resolver: d.world.resolver,
    expectedAudience: REQUEST.clientId,
    expectedNonce: REQUEST.nonce,
    nowSeconds: NOW,
    ...overrides,
  });
}

describe('verifyIDToken の ID Token 検証規則', () => {
  async function token() {
    const { d, delegated } = await setup('P-256', 'embedded');
    return {
      d,
      id: await generateIDToken(REQUEST, DELEGATED_DID, delegated.signer, { nowSeconds: NOW }),
    };
  }

  it('aud 不一致は 3010、nonce 不一致は 4012', async () => {
    const { d, id } = await token();
    expect(
      await failureOf(verifyToken(d, id, { expectedAudience: 'https://other.example' })),
    ).toEqual({
      code: ErrorCodes.SIG_INVALID,
      reason: 'aud_mismatch',
    });
    expect((await failureOf(verifyToken(d, id, { expectedNonce: 'other' })))?.code).toBe(
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
  });

  it('expectedAudience / expectedNonce が無い・空だと（JS 呼び出しでも）検証せず RangeError（aud / nonce 無しのトークンを通さない）', async () => {
    const { d, delegated } = await setup('P-256', 'embedded');
    // aud / nonce を持たないトークン（署名は正しい）。期待値の欠落と `undefined === undefined` で通ってはならない。
    const bare = await signCompactJwsAsync(
      { alg: delegated.alg, kid: delegated.kid, typ: 'JWT' },
      { iss: DELEGATED_DID, sub: DELEGATED_DID, iat: NOW, exp: NOW + 300 },
      delegated.signer,
    );
    for (const missing of ['expectedAudience', 'expectedNonce'] as const) {
      const opts = { resolver: d.world.resolver, nowSeconds: NOW, [missing]: undefined };
      const withOther = {
        expectedAudience: REQUEST.clientId,
        expectedNonce: REQUEST.nonce,
        ...opts,
      };
      await expect(
        verifyIDToken(bare, withOther as unknown as Parameters<typeof verifyIDToken>[1]),
      ).rejects.toBeInstanceOf(RangeError);
      await expect(verifyToken(d, bare, { [missing]: '' })).rejects.toBeInstanceOf(RangeError);
    }
    // 期待値を渡しても、aud / nonce を持たないトークンは拒否する。
    expect((await failureOf(verifyToken(d, bare)))?.reason).toBe('aud_mismatch');
  });

  it('期限切れ・未来の iat は 4014', async () => {
    const { d, id } = await token();
    expect((await failureOf(verifyToken(d, id, { nowSeconds: NOW + 24 * 3600 })))?.code).toBe(
      ErrorCodes.CLOCK_SKEW_EXCEEDED,
    );
    expect((await failureOf(verifyToken(d, id, { nowSeconds: NOW - 24 * 3600 })))?.code).toBe(
      ErrorCodes.CLOCK_SKEW_EXCEEDED,
    );
  });

  it('iss ≠ sub、DID でない sub、kid 無し、構造不正は 3010', async () => {
    const { d, delegated } = await setup('P-256', 'embedded');
    const forged = async (claims: Record<string, unknown>) => {
      // generateIDToken は iss = sub を強制するため、同じ署名鍵で任意クレームを署名する。
      return signCompactJwsAsync(
        { alg: delegated.alg, kid: delegated.kid, typ: 'JWT' },
        claims,
        delegated.signer,
      );
    };
    const base = { aud: REQUEST.clientId, nonce: REQUEST.nonce, iat: NOW, exp: NOW + 300 };
    const issMismatch = await forged({ ...base, iss: DELEGATED_DID, sub: 'did:web:other.example' });
    expect((await failureOf(verifyToken(d, issMismatch)))?.reason).toBe('subject_invalid');
    const notDid = await forged({ ...base, iss: 'https://self-issued.me/v2', sub: 'abc' });
    expect((await failureOf(verifyToken(d, notDid)))?.reason).toBe('subject_invalid');
    expect((await failureOf(verifyToken(d, 'not-a-jwt')))?.reason).toBe('malformed');
  });
});
