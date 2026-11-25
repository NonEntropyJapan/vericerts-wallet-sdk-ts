/**
 * evidence 解釈・LoA 判定の `Object.prototype` 汚染耐性テスト。
 *
 * evidence は VC 本文由来のデータであり、`entry.trustLevel` / `entry.assuranceLevel` を
 * プロトタイプ鎖で読むと、LoA を**明示していない** evidence が汚染値で `high` に昇格し、
 * 「未知 / 欠落は保守的に `low`」という fail-safe フォールバックを飛び越える。
 * その結果 `verifyEvidence(vc, 'high')` が本来満たさない VC を `sufficient: true` と判定する。
 *
 * `entry.type` も同様で、`type` を持たない構造不正な evidence が汚染値で「type あり」に化け、
 * `VC_SCHEMA_INVALID`（3002）のガードを素通りする。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import { interpretEvidence, verifyEvidence } from '../../evidence.js';

const V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

function vcWithEvidence(evidence: unknown): VerifiableCredential {
  return {
    '@context': [V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2026-01-01T00:00:00Z',
    evidence,
  } as VerifiableCredential;
}

describe('evidence 解釈の Object.prototype 汚染耐性', () => {
  it('継承した trustLevel は LoA の明示指定として採用しない', async () => {
    // type 既定値を持たない未知 type ＝ 本来は `low` フォールバック。
    const vc = vcWithEvidence({ type: ['UnknownEvidenceType'] });
    const interpretations = await withPollutedPrototypeAsync({ trustLevel: 'high' }, () =>
      interpretEvidence(vc),
    );
    expect(interpretations[0]?.trustLevel).toBe('low');
  });

  it('継承した assuranceLevel も LoA の明示指定として採用しない', async () => {
    const vc = vcWithEvidence({ type: ['UnknownEvidenceType'] });
    const interpretations = await withPollutedPrototypeAsync({ assuranceLevel: 'high' }, () =>
      interpretEvidence(vc),
    );
    expect(interpretations[0]?.trustLevel).toBe('low');
  });

  it('継承した trustLevel で requiredLoA: high の判定を通過させられない', async () => {
    const vc = vcWithEvidence({ type: ['UnknownEvidenceType'] });
    const result = await withPollutedPrototypeAsync({ trustLevel: 'high' }, () =>
      verifyEvidence(vc, 'high'),
    );
    expect(result.sufficient).toBe(false);
  });

  it('継承した type は「type あり」として扱わず 3002 で拒否する', async () => {
    // `type` を持たない構造不正な evidence。
    const vc = vcWithEvidence({ verifier: 'did:example:verifier' });
    await expect(
      withPollutedPrototypeAsync({ type: ['DocumentVerification'] }, () => interpretEvidence(vc)),
    ).rejects.toThrow(new VericertsError(ErrorCodes.VC_SCHEMA_INVALID));
  });

  it('明示的な trustLevel / type は従来どおり尊重される（正常系）', async () => {
    const vc = vcWithEvidence({ type: ['UnknownEvidenceType'], trustLevel: 'high' });
    const interpretations = await interpretEvidence(vc);
    expect(interpretations[0]?.trustLevel).toBe('high');
    expect(interpretations[0]?.type).toEqual(['UnknownEvidenceType']);
    expect((await verifyEvidence(vc, 'high')).sufficient).toBe(true);
  });

  it('type 既定の LoA 推定は従来どおり効く（正常系）', async () => {
    const vc = vcWithEvidence({ type: ['PhysicalDocumentVerification'] });
    const interpretations = await interpretEvidence(vc);
    expect(interpretations[0]?.trustLevel).toBe('high');
  });
});
