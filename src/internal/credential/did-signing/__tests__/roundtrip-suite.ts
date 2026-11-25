/**
 * 署名ラウンドトリップの共有スイート。
 *
 * 各 DID メソッドのケース（`Case`）を受け取り、ペルソナの署名鍵（`resolvePersonaSigner`）で VP / VC / SIOPv2 id_token /
 * signMessage を署名し、SDK の検証経路で検証する。ケースの組み立ては `roundtrip.test.ts`（ローカルで解決できるメソッド）と
 * `roundtrip.network.test.ts`（ネットワーク取得を伴うメソッド）にある。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { generateIDToken } from '../../../auth/siop/id-token.js';
import type { SIOPv2Request } from '../../../auth/siop/types.js';
import type { PersonaMetadata } from '../../../persona/types.js';
import { sampleVp } from '../../presentation/__tests__/presentation.fixtures.js';
import { issuePresentation } from '../../presentation/issue.js';
import { verifyPresentation } from '../../presentation/presentation.js';
import { issueCredential } from '../../vc/issue.js';
import { decodeCompactJws, verifyWithKey } from '../../vc/jws.js';
import { didDocumentToVerifierKey } from '../../vc/verifier-key.js';
import { verifyCredential } from '../../vc/verify.js';
import { importPersonaFromDid } from '../import-persona.js';
import { resolvePersonaSigner } from '../persona-signer.js';
import { signMessageJws, verifyMessageJws } from '../sign-message.js';
import { NOW, type World } from './fixtures.js';

export interface Setup {
  readonly world: World;
  readonly persona: PersonaMetadata;
  /** 署名時に渡す外部秘密鍵（取り込んだ外部鍵のペルソナ）。 */
  readonly externalKey?: Record<string, unknown>;
}

export interface Case {
  readonly name: string;
  readonly alg: 'ES256' | 'ES256K' | 'EdDSA' | 'ES256K-R';
  setup(): Promise<Setup>;
}

export async function imported(
  world: World,
  did: string,
  key: Record<string, unknown>,
  relationship?: 'authentication' | 'assertionMethod',
): Promise<Setup> {
  const persona = await importPersonaFromDid(
    { personas: world.personas, keymanager: world.km, resolver: world.resolver },
    { did, key: { external: key }, ...(relationship !== undefined ? { relationship } : {}) },
  );
  return { world, persona, externalKey: key };
}

const REQUEST: SIOPv2Request = {
  scope: 'openid',
  responseType: 'id_token',
  clientId: 'https://rp.example',
  redirectUri: 'https://rp.example/cb',
  nonce: 'siop-nonce-1',
};

export function defineRoundtripSuite(cases: readonly Case[]): void {
  describe.each([...cases])('署名ラウンドトリップ: $name', (testCase) => {
    async function prepare(relationship: 'authentication' | 'assertionMethod' = 'authentication') {
      const { world, persona, externalKey: key } = await testCase.setup();
      const resolved = await resolvePersonaSigner(world.km, persona, {
        relationship,
        resolver: world.resolver,
        ...(key !== undefined ? { externalKey: key } : {}),
      });
      const document = await world.resolver.resolve(persona.did);
      const verifierKey = didDocumentToVerifierKey(document, {
        verificationMethodId: resolved.kid,
        relationship,
      });
      return { world, persona, resolved, verifierKey };
    }

    it('署名鍵は alg に合い、kid は DID Document の検証メソッド', async () => {
      const { persona, resolved, verifierKey } = await prepare();
      expect(resolved.alg).toBe(testCase.alg);
      expect(resolved.signer.alg).toBe(testCase.alg);
      expect(resolved.kid.startsWith(`${persona.did}#`)).toBe(true);
      expect(resolved.signer.kid).toBe(resolved.kid);
      // 公開鍵を持たない検証メソッド（did:pkh / did:ethr の controller）はアドレス鍵（ES256K-R）で検証する。
      expect('ethereumAddress' in verifierKey).toBe(testCase.alg === 'ES256K-R');
    });

    it('VP（JWT-VP）: kid 付きで署名し verifyPresentation で検証できる', async () => {
      const { persona, resolved, verifierKey } = await prepare();
      const jwt = issuePresentation(sampleVp({ holder: persona.did }), resolved.signer, {
        audience: 'https://verifier.example',
        nonce: 'vp-nonce-1',
        nowSeconds: NOW,
      });
      expect(decodeCompactJws(jwt).header).toMatchObject({ alg: testCase.alg, kid: resolved.kid });
      const verified = verifyPresentation(jwt, {
        key: verifierKey,
        expectedAudience: 'https://verifier.example',
        expectedNonce: 'vp-nonce-1',
        nowSeconds: NOW,
      });
      expect(verified.presentation.holder).toBe(persona.did);
      expect(verified.header.alg).toBe(testCase.alg);
    });

    it('VC（JWT-VC）: assertionMethod の検証メソッドで署名し verifyCredential で検証できる', async () => {
      const { persona, resolved, verifierKey } = await prepare('assertionMethod');
      const jwt = issueCredential(
        {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          type: ['VerifiableCredential'],
          issuer: persona.did,
          credentialSubject: { id: 'did:example:subject', name: 'Alice' },
          issuanceDate: '2025-12-01T00:00:00Z',
          expirationDate: '2027-01-01T00:00:00Z',
          id: 'urn:uuid:roundtrip-vc',
        },
        resolved.signer,
        { nowSeconds: NOW },
      );
      expect(decodeCompactJws(jwt).header).toMatchObject({ alg: testCase.alg, kid: resolved.kid });
      const verified = verifyCredential(jwt, { key: verifierKey, nowSeconds: NOW });
      expect(verified.header.alg).toBe(testCase.alg);
    });

    it('SIOPv2 id_token: iss = sub = DID、kid 付きで署名し DID Document の鍵で検証できる', async () => {
      const { persona, resolved, verifierKey } = await prepare();
      const token = await generateIDToken(REQUEST, persona.did, resolved.signer, {
        nowSeconds: NOW,
      });
      const decoded = decodeCompactJws(token);
      expect(decoded.header).toMatchObject({ alg: testCase.alg, kid: resolved.kid });
      expect(decoded.payload).toMatchObject({
        iss: persona.did,
        sub: persona.did,
        aud: REQUEST.clientId,
        nonce: REQUEST.nonce,
      });
      expect(verifyWithKey(testCase.alg, decoded, verifierKey)).toBe(true);
    });

    it('signMessage: kid 付き detached JWS（b64:false / crit）を署名し verifyMessageJws で検証できる', async () => {
      const { world, persona, resolved } = await prepare();
      const message = 'Sign in to Example\n日本語も可';
      const jws = await signMessageJws(message, resolved.signer);
      const verified = await verifyMessageJws(jws, {
        message,
        resolver: world.resolver,
        expectedDid: persona.did,
      });
      expect(verified).toEqual({ did: persona.did, kid: resolved.kid, alg: testCase.alg });
      // JWS の header は alg / kid と RFC 7797 の b64 / crit のみ（独自ヘッダを足さない）。payload セグメントは空。
      expect(JSON.parse(Buffer.from(jws.split('.')[0] as string, 'base64url').toString())).toEqual({
        alg: testCase.alg,
        kid: resolved.kid,
        b64: false,
        crit: ['b64'],
      });
      expect(jws.split('.')[1]).toBe('');
      // ES256K-R（標準外の例外）は recoverable 署名の 65 バイト、ほかは `r ‖ s` の 64 バイト。
      const signature = base64urlnopad.decode(jws.split('.')[2] as string);
      expect(signature).toHaveLength(testCase.alg === 'ES256K-R' ? 65 : 64);
    });
  });
}
