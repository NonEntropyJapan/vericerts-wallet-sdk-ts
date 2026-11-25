/**
 * `vct#integrity`（draft-ietf-oauth-sd-jwt-vc-22 §2.2.2.3 / §6）の扱い。
 *
 * SDK は SRI を検証できない。`extends#integrity` / `schema_uri#integrity` と同じ方針で、宣言を黙って
 * 捨てず **取得より前に** 3061 で拒否する。ピン留めされた文書がすり替えられても valid:true にしない。
 */

import { describe, expect, it } from 'bun:test';
import { createHash } from 'node:crypto';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import { TypeMetadataCache } from '../cache.js';
import { validateClaimsAgainstTypeMetadata } from '../resolve.js';
import type { SdJwtTypeMetadata } from '../types.js';
import { BASE_METADATA, BASE_VCT, createFetchStub } from './fixtures.js';

function freshCaches() {
  return {
    metadataCache: new TypeMetadataCache<SdJwtTypeMetadata>(),
    schemaCache: new TypeMetadataCache<Record<string, unknown>>(),
  };
}

async function expectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(code);
    expect((err as VericertsError).context).toMatchObject({ reason: 'integrity_unverifiable' });
  }
}

const GENUINE = JSON.stringify(BASE_METADATA);
const TAMPERED = { vct: BASE_VCT, name: 'base', schema: {} };

describe('vct#integrity のピン留め', () => {
  it.each([
    ['正しい SRI（本物の文書）', GENUINE],
    ['SRI（すり替えられた文書は不一致のはず）', JSON.stringify(TAMPERED)],
  ])('%s が宣言されたクレームは取得せず 3061 で拒否する', async (_label, body) => {
    const sri = `sha256-${createHash('sha256').update(body).digest('base64')}`;
    // ホスト乗っ取り後の「制約なし」文書。修正前は valid:true / schemaAvailable:true で通った。
    const stub = createFetchStub({ [BASE_VCT]: { json: TAMPERED } });
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { vct: BASE_VCT, 'vct#integrity': sri, other: 1 },
        { fetchImpl: stub.fetchImpl, ...freshCaches() },
      ),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
    expect(stub.requested).toEqual([]);
  });

  it.each([
    ['文字列でない値', 123],
    ['null', null],
    ['空文字列', ''],
    ['undefined', undefined],
    ['配列', ['sha256-x']],
    ['空配列', []],
  ])('宣言が %s でも黙って捨てず 3061 で拒否する', async (_label, value) => {
    const stub = createFetchStub({ [BASE_VCT]: { json: TAMPERED } });
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { vct: BASE_VCT, 'vct#integrity': value },
        { fetchImpl: stub.fetchImpl, ...freshCaches() },
      ),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });

  it.each([
    'VCT#INTEGRITY',
    'Vct#Integrity',
    'vct#integrity',
  ])('大文字小文字違いのキー %s でも宣言として拒否する（W3C の digestSRI と共通のヘルパ）', async (key) => {
    const stub = createFetchStub({ [BASE_VCT]: { json: TAMPERED } });
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { vct: BASE_VCT, [key]: 'sha256-abc' },
        { fetchImpl: stub.fetchImpl, ...freshCaches() },
      ),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
    expect(stub.requested).toEqual([]);
  });

  it('FO-3 の fail-open override でも 3061 は通過させない', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: TAMPERED } });
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { vct: BASE_VCT, 'vct#integrity': 'sha256-abc' },
        {
          fetchImpl: stub.fetchImpl,
          ...freshCaches(),
          failSafePolicy: { onConsent: () => true, onAudit: () => {} },
        } as never,
      ),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });

  it('プロトタイプ由来の vct#integrity は宣言として扱わない（従来どおり検証される）', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const claims = Object.create({ 'vct#integrity': 'sha256-abc' }) as Record<string, unknown>;
    claims.given_name = 'Alice';
    const result = await validateClaimsAgainstTypeMetadata(BASE_VCT, claims, {
      fetchImpl: stub.fetchImpl,
      ...freshCaches(),
    });
    expect(result.valid).toBe(true);
    expect(result.schemaAvailable).toBe(true);
  });

  it('ピンが無ければ従来どおり取得して検証する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { vct: BASE_VCT, given_name: 'Alice' },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(result.valid).toBe(true);
    expect(stub.requested).toEqual([BASE_VCT]);
  });

  it('vct が URL でなければ Type Metadata は無く、ピンがあっても検証をスキップする', async () => {
    const result = await validateClaimsAgainstTypeMetadata('urn:example:plain', {
      'vct#integrity': 'sha256-abc',
    });
    expect(result).toEqual({ valid: true, schemaAvailable: false, warnings: [] });
  });
});
