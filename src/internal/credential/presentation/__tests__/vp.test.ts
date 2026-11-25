/**
 * VP データモデルの構造検証・シリアライズ / パースのユニットテスト。
 *
 * VC 側（`assertVerifiableCredential` 等）の同種テストは `vc-assert.test.ts` にある
 * （`vp.ts` / `vc-assert.ts` の分割に合わせたテストの分割）。
 *
 * 検証内容:
 * - `@context` 検証（先頭が W3C VC v2 base context）の正常 / 異常。
 * - VP の serialize → parse ラウンドトリップ。
 * - 不正 @context / 必須プロパティ欠落の拒否（VC_SCHEMA_INVALID 3002）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  assertVcV2Context,
  assertVerifiablePresentation,
  parseVerifiablePresentation,
  serializeVerifiablePresentation,
  VC_V2_CONTEXT,
  type VerifiablePresentation,
} from '../vp.js';

const SCHEMA_INVALID = new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);

/** サンプル VP を作る。 */
function sampleVp(overrides: Partial<VerifiablePresentation> = {}): VerifiablePresentation {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiablePresentation'],
    holder: 'did:example:holder',
    verifiableCredential: ['eyJhbGciOiJFUzI1NiJ9.payload.sig'],
    id: 'urn:uuid:vp-1',
    ...overrides,
  };
}

describe('@context 検証', () => {
  it('先頭が VC v2 base context なら通る（追加 context 許容）', () => {
    expect(() => assertVcV2Context([VC_V2_CONTEXT, 'https://example.com/ns/v1'])).not.toThrow();
  });

  it('配列でない @context は 3002', () => {
    expect(() => assertVcV2Context(VC_V2_CONTEXT)).toThrow(SCHEMA_INVALID);
  });

  it('空配列は 3002', () => {
    expect(() => assertVcV2Context([])).toThrow(SCHEMA_INVALID);
  });

  it('先頭が base context でないと 3002', () => {
    expect(() => assertVcV2Context(['https://www.w3.org/2018/credentials/v1'])).toThrow(
      SCHEMA_INVALID,
    );
  });
});

describe('VP 構造検証・ラウンドトリップ', () => {
  it('正常 VP は serialize → parse でラウンドトリップする', () => {
    const vp = sampleVp();
    const parsed = parseVerifiablePresentation(serializeVerifiablePresentation(vp));
    expect(parsed).toEqual(vp);
  });

  it('JSON-LD VC（object）を含む VP もラウンドトリップする', () => {
    const vp = sampleVp({ verifiableCredential: [{ '@context': [VC_V2_CONTEXT] }] });
    const parsed = parseVerifiablePresentation(serializeVerifiablePresentation(vp));
    expect(parsed.verifiableCredential).toHaveLength(1);
  });

  it('空の verifiableCredential 配列は許容する', () => {
    const vp = sampleVp({ verifiableCredential: [] });
    expect(() => assertVerifiablePresentation(vp)).not.toThrow();
  });

  it('type 先頭が VerifiablePresentation でないと 3002', () => {
    const bad = { ...sampleVp(), type: ['VerifiableCredential'] };
    expect(() => assertVerifiablePresentation(bad)).toThrow(SCHEMA_INVALID);
  });

  it('holder 欠落は 3002', () => {
    const { holder: _omit, ...bad } = sampleVp();
    expect(() => assertVerifiablePresentation(bad)).toThrow(SCHEMA_INVALID);
  });

  it('@context 先頭不一致は 3002', () => {
    const bad = { ...sampleVp(), '@context': ['https://example.com/wrong'] };
    expect(() => assertVerifiablePresentation(bad)).toThrow(SCHEMA_INVALID);
  });

  it('verifiableCredential が配列でないと 3002', () => {
    const bad = { ...sampleVp(), verifiableCredential: 'not-an-array' };
    expect(() => assertVerifiablePresentation(bad)).toThrow(SCHEMA_INVALID);
  });

  it('verifiableCredential に null 要素があると 3002', () => {
    const bad = { ...sampleVp(), verifiableCredential: [null] };
    expect(() => assertVerifiablePresentation(bad)).toThrow(SCHEMA_INVALID);
  });

  it('verifiableCredential に配列要素（ネスト配列）があると 3002', () => {
    // 配列も typeof === 'object' だが JSON-LD VC object ではないため拒否する。
    const bad = { ...sampleVp(), verifiableCredential: [['eyJ.payload.sig']] };
    expect(() => assertVerifiablePresentation(bad)).toThrow(SCHEMA_INVALID);
  });
});
