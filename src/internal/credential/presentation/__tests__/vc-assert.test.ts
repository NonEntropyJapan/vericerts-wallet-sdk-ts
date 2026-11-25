/**
 * VC データモデルの構造検証・シリアライズ / パースのユニットテスト。
 *
 * `vp.ts` から VC 側 API（`assertVerifiableCredential` 等）を `vc-assert.ts` へ切り出したのに合わせて
 * `vp.test.ts` から分割した。VP 側の同種テストは `vp.test.ts` にある。
 *
 * 検証内容:
 * - VC の serialize → parse ラウンドトリップ。
 * - 不正 @context / 必須プロパティ欠落の拒否（VC_SCHEMA_INVALID 3002）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import {
  assertVerifiableCredential,
  parseVerifiableCredential,
  serializeVerifiableCredential,
} from '../vc-assert.js';
import { VC_V2_CONTEXT } from '../vp.js';

const SCHEMA_INVALID = new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);

/** サンプル VC を作る。 */
function sampleVc(overrides: Partial<VerifiableCredential> = {}): VerifiableCredential {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2025-12-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    id: 'urn:uuid:1234',
    ...overrides,
  };
}

describe('VC 構造検証・ラウンドトリップ', () => {
  it('正常 VC は serialize → parse でラウンドトリップする', () => {
    const vc = sampleVc();
    const parsed = parseVerifiableCredential(serializeVerifiableCredential(vc));
    expect(parsed).toEqual(vc);
  });

  it('expirationDate 省略の VC もラウンドトリップする', () => {
    const vc = sampleVc({ expirationDate: undefined });
    const parsed = parseVerifiableCredential(serializeVerifiableCredential(vc));
    expect(parsed.expirationDate).toBeUndefined();
    expect(parsed.issuer).toBe('did:example:issuer');
  });

  it('type 先頭が VerifiableCredential でないと 3002', () => {
    const bad = { ...sampleVc(), type: ['SomethingElse'] };
    expect(() => assertVerifiableCredential(bad)).toThrow(SCHEMA_INVALID);
  });

  it('issuer 欠落は 3002', () => {
    const { issuer: _omit, ...bad } = sampleVc();
    expect(() => assertVerifiableCredential(bad)).toThrow(SCHEMA_INVALID);
  });

  it('credentialSubject が配列だと 3002', () => {
    const bad = { ...sampleVc(), credentialSubject: [] };
    expect(() => assertVerifiableCredential(bad)).toThrow(SCHEMA_INVALID);
  });

  it('issuanceDate 欠落は 3002', () => {
    const { issuanceDate: _omit, ...bad } = sampleVc();
    expect(() => assertVerifiableCredential(bad)).toThrow(SCHEMA_INVALID);
  });

  it('object でない値は 3002', () => {
    expect(() => assertVerifiableCredential('not-an-object')).toThrow(SCHEMA_INVALID);
    expect(() => assertVerifiableCredential(null)).toThrow(SCHEMA_INVALID);
  });

  it('不正 JSON のパースは 3002', () => {
    expect(() => parseVerifiableCredential('{ broken')).toThrow(SCHEMA_INVALID);
  });
});
