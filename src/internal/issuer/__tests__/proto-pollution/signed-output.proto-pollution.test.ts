/**
 * 発行系の署名済み出力への汚染混入テスト。
 *
 * `buildCredential`（VC 本体）と `issueStatusListToken`（Status List Token）は、組み立てた
 * オブジェクトをそのまま Issuer が署名する。任意プロパティをプロトタイプ鎖で読むと、
 * それらを**省略した**正当な発行でも汚染値が **署名済みの成果物** に載る:
 *
 * - `expirationDate`: 攻撃者の有効期限が VC に焼き付く。
 * - `refreshService`: 更新エンドポイントが攻撃者の URL になる。
 * - `evidence` / `termsOfUse`: 偽の発行根拠・利用条件が Issuer 署名付きで配布される。
 * - `revocationPropagation`: 失効伝搬ポリシーが緩和された VC が署名される。
 * - Status List Token の `expSeconds` / `ttlSeconds` / `iatSeconds`: 失効リストの有効期限が
 *   攻撃者の値になる（実質無期限の失効リスト）。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { buildCredential } from '../../module/build-vc.js';
import { normalizeClaims, normalizeIssueOptions } from '../../module/normalized-issue-input.js';
import { signStatusListToken } from '../../status-list-token.js';

const ISSUER = 'did:key:z6MkIssuerSignedOutput';
const HOLDER = 'did:key:z6MkHolderSignedOutput';
const SIGNER_KEY = new Uint8Array(32).fill(59);
const SIGNER = createPrivateKeySigner(SIGNER_KEY, 'ES256');
const IAT = 1_767_225_600;

const BASE_INPUT = {
  issuer: ISSUER,
  holderDID: HOLDER,
  claims: normalizeClaims({ degree: 'BSc' }),
  id: 'urn:uuid:vc-1',
  issuanceDate: '2026-01-01T00:00:00Z',
};

/** JWT の payload をデコードする（署名検証はしない）。 */
function payloadOf(jwt: string): Record<string, unknown> {
  const segment = jwt.split('.')[1] ?? '';
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

describe('buildCredential の Object.prototype 汚染耐性', () => {
  it('継承した expirationDate は VC に載らない', () => {
    const vc = withPollutedPrototype({ expirationDate: '2099-01-01T00:00:00Z' }, () =>
      buildCredential(BASE_INPUT, normalizeIssueOptions({})),
    );
    expect(vc.expirationDate).toBeUndefined();
  });

  it('継承した refreshService / evidence / termsOfUse は VC に載らない', () => {
    const vc = withPollutedPrototype(
      {
        refreshService: { id: 'attacker', type: 'X', url: 'https://attacker.example/refresh' },
        evidence: [{ type: ['PhysicalDocumentVerification'] }],
        termsOfUse: [{ type: 'X' }],
      },
      () => buildCredential(BASE_INPUT, normalizeIssueOptions({})),
    );
    expect(vc.refreshService).toBeUndefined();
    expect(vc.evidence).toBeUndefined();
    expect(vc.termsOfUse).toBeUndefined();
  });

  it('継承した revocationPropagation は VC に載らない', () => {
    const vc = withPollutedPrototype({ revocationPropagation: 'permissive' }, () =>
      buildCredential(BASE_INPUT, normalizeIssueOptions({})),
    );
    expect(vc.revocationPropagation).toBeUndefined();
  });

  it('継承した types / credentialSchema は VC に載らない', () => {
    const vc = withPollutedPrototype(
      { types: ['AttackerCredential'], credentialSchema: 'https://attacker.example/schema' },
      () => buildCredential(BASE_INPUT, normalizeIssueOptions({})),
    );
    expect(vc.type).toEqual(['VerifiableCredential']);
    expect(vc.credentialSchema).toBeUndefined();
  });

  it('明示的に渡したオプションは従来どおり VC に載る（正常系）', () => {
    const vc = buildCredential(
      BASE_INPUT,
      normalizeIssueOptions({
        types: ['UniversityDegreeCredential'],
        expirationDate: '2027-01-01T00:00:00Z',
        revocationPropagation: 'permissive',
      }),
    );
    expect(vc.type).toEqual(['VerifiableCredential', 'UniversityDegreeCredential']);
    expect(vc.expirationDate).toBe('2027-01-01T00:00:00Z');
    expect(vc.revocationPropagation).toBe('permissive');
  });
});

describe('issueStatusListToken の Object.prototype 汚染耐性', () => {
  const input = {
    issuer: ISSUER,
    uri: 'https://issuer.example/status/revocation',
    bits: 1 as const,
    lst: 'eNrbuRgAAhcBXQ',
  };

  it('継承した expSeconds は署名済み Token の exp に載らない', () => {
    const token = withPollutedPrototype({ expSeconds: 4_102_444_800 }, () =>
      signStatusListToken(input, SIGNER, { iatSeconds: IAT }),
    );
    expect(payloadOf(token).exp).toBeUndefined();
  });

  it('継承した ttlSeconds は署名済み Token の exp に載らない', () => {
    const token = withPollutedPrototype({ ttlSeconds: 100_000_000 }, () =>
      signStatusListToken(input, SIGNER, { iatSeconds: IAT }),
    );
    expect(payloadOf(token).exp).toBeUndefined();
  });

  it('継承した iatSeconds は署名済み Token の iat に載らない', () => {
    const token = withPollutedPrototype({ iatSeconds: 1_000_000 }, () =>
      signStatusListToken(input, SIGNER, {}),
    );
    expect(payloadOf(token).iat).not.toBe(1_000_000);
  });

  it('明示的に渡した ttlSeconds / iatSeconds は従来どおり反映される（正常系）', () => {
    const token = signStatusListToken(input, SIGNER, {
      iatSeconds: IAT,
      ttlSeconds: 3600,
    });
    const payload = payloadOf(token);
    expect(payload.iat).toBe(IAT);
    expect(payload.exp).toBe(IAT + 3600);
  });
});
