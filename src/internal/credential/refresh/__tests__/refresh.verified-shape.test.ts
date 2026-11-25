/**
 * `verifyRefreshed` の戻り値の実行時検査。
 *
 * 注入された `verifyRefreshed` が VC でない値（文字列 / 数値 / `{}` / null / undefined）を返しても
 * 「リフレッシュ成功」として旧 VC を破損 VC へ入れ替えてはならない。`REFRESHED_VC_VERIFICATION_FAILED`
 * （3022）へ正規化して拒否する（生の TypeError も漏らさない）。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../auth/oid4vci/oid4vci.js';
import { ErrorCodes } from '../../../errors.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../../vc/vc.js';
import { type RefreshDependencies, refreshCredential } from '../refresh.js';

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-07-01T00:00:00Z');

const SERVICE: RefreshServiceConfig = {
  id: 'refresh-1',
  type: 'OID4VCIRefreshService2025',
  url: 'https://issuer.example/refresh',
};

const OLD_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'IdentityCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:holder' },
  issuanceDate: '2026-01-01T00:00:00Z',
  expirationDate: new Date(NOW + 5 * MS_PER_DAY).toISOString(),
  id: 'urn:vc:1',
  refreshService: SERVICE,
};

const NEW_VC: VerifiableCredential = {
  ...OLD_VC,
  id: 'urn:vc:2',
  issuanceDate: '2026-07-01T00:00:00Z',
  expirationDate: new Date(NOW + 365 * MS_PER_DAY).toISOString(),
};

const okFetch: FetchLike = async () =>
  new Response(JSON.stringify({ credential: JSON.stringify(NEW_VC) }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });

describe('refreshCredential: verifyRefreshed の戻り値検査', () => {
  it.each([
    ['undefined', undefined],
    ['null', null],
    ['文字列', 'str'],
    ['数値', 42],
    ['空オブジェクト', {}],
    ['配列', [NEW_VC]],
    ['必須メンバ欠落（credentialSubject なし）', { ...NEW_VC, credentialSubject: undefined }],
  ])('%s を返す verifyRefreshed は 3022 で拒否する（破損 VC に入れ替えない）', async (_name, returned) => {
    const deps: RefreshDependencies = {
      verifyRefreshed: async () => returned as unknown as VerifiableCredential,
      fetchImpl: okFetch,
    };
    await expect(refreshCredential(OLD_VC, { now: NOW }, deps)).rejects.toMatchObject({
      code: ErrorCodes.REFRESHED_VC_VERIFICATION_FAILED,
    });
  });

  it('構造が正しい VC は従来どおり derivedFrom 付きで採用する（非退行）', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: async (raw) => JSON.parse(raw) as VerifiableCredential,
      fetchImpl: okFetch,
    };
    const result = await refreshCredential(OLD_VC, { now: NOW }, deps);
    expect(result.refreshed).toBe(true);
    expect(result.credential).toEqual({ ...NEW_VC, derivedFrom: 'urn:vc:1' });
  });
});
