/**
 * `CredentialRecord`（`src/internal/gdpr/types.ts`）の全フィールドを含む encode/decode
 * ラウンドトリップの回帰テスト。
 *
 * `CredentialRecord` は `Credential`/`CredentialMeta` とは別目的の GDPR ローカル
 * コピーであり、`disputed` 系 / `processingRestricted` 系 / `legalHold` / `presentedTo` という
 * GDPR 操作専用フィールドを持つ。これらのフィールドが将来
 * リネーム・削除された際に `codec.ts` が黙って field を落とさないことを検知する。
 *
 * `../codec.test.ts` に置かず本ディレクトリに分けているのは、`gdpr/__tests__/` 直下の合計行数が
 * linterly の `max_lines_per_directory` 上限（.linterly.yml、2000 行 + 10% 警告閾値）に迫って
 * いたため（sub-barrel 化）。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../credential/index.js';
import { decodeCredentialRecord, encodeCredentialRecord } from '../../codec.js';
import type { CredentialRecord } from '../../types.js';

const vc: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:subject', name: 'Alice' },
  issuanceDate: '2026-01-01T00:00:00Z',
  id: 'urn:uuid:round-trip',
};

describe('CredentialRecord の encode/decode ラウンドトリップ', () => {
  it('必須フィールドのみのレコードはそのまま往復する', () => {
    const record: CredentialRecord = {
      id: vc.id as string,
      credential: vc,
      receivedAt: '2026-01-01T00:00:00Z',
    };

    const decoded = decodeCredentialRecord(encodeCredentialRecord(record));

    expect(decoded).toEqual(record);
  });

  it('GDPR 操作専用フィールド（disputed系/processingRestricted系/legalHold/presentedTo）を含めても欠落しない', () => {
    const record: CredentialRecord = {
      id: vc.id as string,
      credential: vc,
      receivedAt: '2026-01-01T00:00:00Z',
      disputed: true,
      disputeReason: '記載内容に誤りがある',
      disputedAt: '2026-01-02T00:00:00Z',
      processingRestricted: true,
      restrictionUpdatedAt: '2026-01-03T00:00:00Z',
      legalHold: true,
      presentedTo: [
        { rpIdentifier: 'rp-1', purpose: 'age-check', presentedAt: '2026-01-04T00:00:00Z' },
      ],
    };

    const decoded = decodeCredentialRecord(encodeCredentialRecord(record));

    // `CredentialMeta`（issuerDID/types/format 等の検索用メタデータ）に相当する
    // フィールドは意図的に持たない（GDPR 操作は VC ID 単位のため不要）。往復後も生えていないことを見る。
    expect(decoded).toEqual(record);
    expect(decoded).not.toHaveProperty('issuerDID');
    expect(decoded).not.toHaveProperty('format');
  });
});
