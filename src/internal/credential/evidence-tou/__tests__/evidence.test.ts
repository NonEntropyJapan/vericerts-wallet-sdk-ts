/**
 * VC `evidence` の構造検証・解釈と Verifier 側 LoA 充足判定のユニットテスト。
 *
 * 検証内容:
 * - interpretEvidence: object 単体 / 配列の正規化、type 正規化、checks 正規化、trustLevel 決定。
 * - type 明示 trustLevel / type 既定値 / 未知 type の保守的 low フォールバック。
 * - type 欠落エントリで VC_SCHEMA_INVALID（3002）。
 * - verifyEvidence: 要求 LoA と最大 trustLevel の比較（low/substantial/high）。
 * - failed 確認を含む evidence は保証レベルを無効化（fail-safe）。
 * - evidence 無しは low 要求のみ充足。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import { interpretEvidence, verifyEvidence } from '../evidence.js';
import type { EvidenceEntry } from '../types.js';

/** evidence を指定した最小 VC を作る。 */
function vcWithEvidence(evidence: VerifiableCredential['evidence']): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject' },
    issuanceDate: '2026-01-01T00:00:00Z',
    ...(evidence !== undefined ? { evidence } : {}),
  };
}

describe('interpretEvidence', () => {
  it('object 単体の evidence を 1 件の解釈に正規化する', async () => {
    const entry: EvidenceEntry = {
      id: 'urn:evidence:1',
      type: 'DocumentVerification',
      verifier: 'did:example:kyc',
      evidenceDocument: 'DriversLicense',
      subjectPresence: 'Physical',
      documentPresence: 'Physical',
      hashValue: 'abc123',
    };
    const result = await interpretEvidence(vcWithEvidence(entry));
    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe('urn:evidence:1');
    expect(result[0]?.type).toEqual(['DocumentVerification']);
    expect(result[0]?.verifier).toBe('did:example:kyc');
    expect(result[0]?.trustLevel).toBe('substantial');
  });

  it('配列の evidence を全件解釈する', async () => {
    const result = await interpretEvidence(
      vcWithEvidence([
        { type: ['DocumentVerification'] },
        { type: 'PhysicalDocumentVerification' },
      ]),
    );
    expect(result).toHaveLength(2);
    expect(result[1]?.trustLevel).toBe('high');
  });

  it('明示 trustLevel を type 既定値より優先する', async () => {
    const result = await interpretEvidence(
      vcWithEvidence({ type: 'DocumentVerification', trustLevel: 'high' } as EvidenceEntry),
    );
    expect(result[0]?.trustLevel).toBe('high');
  });

  it('未知 type は保守的に low へ倒す', async () => {
    const result = await interpretEvidence(vcWithEvidence({ type: 'SomethingUnknown' }));
    expect(result[0]?.trustLevel).toBe('low');
  });

  it('checks を passed/failed/unknown に正規化し不正値は unknown にする', async () => {
    const result = await interpretEvidence(
      vcWithEvidence({
        type: 'DocumentVerification',
        checks: [
          { type: 'document_authenticity', result: 'passed' },
          { type: 'liveness', result: 'bogus' },
          { type: 'nope' },
          'invalid',
        ],
      } as EvidenceEntry),
    );
    expect(result[0]?.checks).toEqual([
      { type: 'document_authenticity', result: 'passed' },
      { type: 'liveness', result: 'unknown' },
      { type: 'nope', result: 'unknown' },
    ]);
  });

  it('evidence 無しは空配列を返す', async () => {
    expect(await interpretEvidence(vcWithEvidence(undefined))).toEqual([]);
  });

  it('type 欠落エントリで VC_SCHEMA_INVALID（3002）を送出する', async () => {
    let thrown: unknown;
    try {
      await interpretEvidence(vcWithEvidence({ verifier: 'x' } as unknown as EvidenceEntry));
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VericertsError);
    expect((thrown as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });
});

describe('verifyEvidence', () => {
  it('substantial evidence は substantial 要求を満たす', async () => {
    const result = await verifyEvidence(
      vcWithEvidence({ type: 'DocumentVerification' }),
      'substantial',
    );
    expect(result.sufficient).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('substantial evidence は high 要求を満たさない', async () => {
    const result = await verifyEvidence(vcWithEvidence({ type: 'DocumentVerification' }), 'high');
    expect(result.sufficient).toBe(false);
    expect(result.reason).toContain('high');
  });

  it('複数 evidence の最大 trustLevel で判定する', async () => {
    const result = await verifyEvidence(
      vcWithEvidence([{ type: 'KYCProof' }, { type: 'PhysicalDocumentVerification' }]),
      'high',
    );
    expect(result.sufficient).toBe(true);
  });

  it('failed 確認を含む evidence は保証レベルを無効化する', async () => {
    const result = await verifyEvidence(
      vcWithEvidence({
        type: 'PhysicalDocumentVerification',
        checks: [{ type: 'document_authenticity', result: 'failed' }],
      } as EvidenceEntry),
      'substantial',
    );
    expect(result.sufficient).toBe(false);
  });

  it('evidence 無しは low 要求のみ満たす', async () => {
    expect((await verifyEvidence(vcWithEvidence(undefined), 'low')).sufficient).toBe(true);
    expect((await verifyEvidence(vcWithEvidence(undefined), 'substantial')).sufficient).toBe(false);
  });
});
