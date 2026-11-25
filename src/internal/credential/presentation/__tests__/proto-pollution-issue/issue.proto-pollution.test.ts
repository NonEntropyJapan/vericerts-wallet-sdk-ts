/**
 * JWT-VP 発行の `Object.prototype` 汚染耐性テスト。
 *
 * `opts.audience` / `nonce` / `nowSeconds` / `expiresInSeconds` をプロトタイプ鎖で読むと、
 * これらを**省略した**正当な発行でも汚染値が **署名済み JWT-VP の payload** に載る:
 *
 * - `aud`: 意図しない Verifier 向けの VP になり、その Verifier で受理される。
 * - `nonce`: リプレイ対策のバインドが攻撃者の選んだ値になる。
 * - `iat` / `exp`: 攻撃者の選んだ有効期間（実質無期限の VP）になる。
 *
 * 署名済み payload は改竄できないため、ここで汚染値が入ると検証側では検知できない。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { issuePresentation } from '../../issue.js';
import type { VerifiablePresentation } from '../../vp.js';

const HOLDER_KEY = new Uint8Array(32).fill(11);
const SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256');
const HOLDER_DID = 'did:example:holder';

const VP: VerifiablePresentation = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiablePresentation'],
  holder: HOLDER_DID,
  verifiableCredential: [],
};

/** JWT-VP の payload をデコードする（署名検証はしない）。 */
function payloadOf(jwt: string): Record<string, unknown> {
  const segment = jwt.split('.')[1] ?? '';
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

describe('issuePresentation の Object.prototype 汚染耐性', () => {
  it('継承した audience は署名済み VP の aud に載らない', () => {
    const jwt = withPollutedPrototype({ audience: 'https://attacker.example' }, () =>
      issuePresentation(VP, SIGNER, {}),
    );
    expect(payloadOf(jwt).aud).toBeUndefined();
  });

  it('継承した nonce は署名済み VP の nonce に載らない', () => {
    const jwt = withPollutedPrototype({ nonce: 'attacker-nonce' }, () =>
      issuePresentation(VP, SIGNER, {}),
    );
    expect(payloadOf(jwt).nonce).toBeUndefined();
  });

  it('継承した expiresInSeconds は署名済み VP の exp に載らない', () => {
    const jwt = withPollutedPrototype({ expiresInSeconds: 100 * 365 * 24 * 3600 }, () =>
      issuePresentation(VP, SIGNER, {}),
    );
    expect(payloadOf(jwt).exp).toBeUndefined();
  });

  it('継承した nowSeconds は署名済み VP の iat に載らない', () => {
    const attackerIat = 1_000_000;
    const jwt = withPollutedPrototype({ nowSeconds: attackerIat }, () =>
      issuePresentation(VP, SIGNER, {}),
    );
    expect(payloadOf(jwt).iat).not.toBe(attackerIat);
  });

  it('継承した id は署名済み VP の jti に載らない', () => {
    const jwt = withPollutedPrototype({ id: 'urn:uuid:attacker' }, () =>
      issuePresentation(VP, SIGNER, {}),
    );
    expect(payloadOf(jwt).jti).toBeUndefined();
  });

  it('明示的に渡したオプションは従来どおり payload に載る（正常系）', () => {
    const jwt = issuePresentation({ ...VP, id: 'urn:uuid:vp-1' }, SIGNER, {
      audience: 'https://verifier.example',
      nonce: 'nonce-1',
      nowSeconds: 1_767_225_600,
      expiresInSeconds: 300,
    });
    const payload = payloadOf(jwt);
    expect(payload.aud).toBe('https://verifier.example');
    expect(payload.nonce).toBe('nonce-1');
    expect(payload.iat).toBe(1_767_225_600);
    expect(payload.exp).toBe(1_767_225_900);
    expect(payload.jti).toBe('urn:uuid:vp-1');
    expect(payload.iss).toBe(HOLDER_DID);
  });
});
