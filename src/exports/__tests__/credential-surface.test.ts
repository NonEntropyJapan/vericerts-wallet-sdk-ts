/**
 * Credential ドメインの公開エクスポート面の回帰テスト。
 *
 * `src/exports/credential.ts` は内部バレルより狭い明示的な allowlist であり、
 * `evidence` / `termsOfUse` / Credential Chain の型と関数は公開されていなかった。
 * `VerifiableCredential` 型がこれらのフィールドを公開しているのに解釈する API が無い、という
 * 非対称を解消したことを固定する。これらは `@experimental` のため サブパスバレル
 * `src/exports/experimental.ts`（`@vericerts/vericerts-wallet-sdk/experimental`）へ移した。メインバレル
 * （`src/index.ts`）に載っていないことも併せて固定する。
 */

import { describe, expect, test } from 'bun:test';
import * as sdk from '../../index.js';
import * as experimental from '../experimental.js';

/** Evidence / Terms of Use / Credential Chain を扱う公開関数（すべて `@experimental`）。 */
const PUBLIC_FUNCTIONS = [
  'interpretEvidence',
  'verifyEvidence',
  'checkTermsOfUse',
  'validateTermsOfUseOnPresentation',
  'verifyCredentialChain',
  'verifyCredentialChainOnPresentation',
  'buildDerivedCredential',
] as const;

describe('公開エクスポート: evidence / termsOfUse / Credential Chain', () => {
  for (const name of PUBLIC_FUNCTIONS) {
    test(`${name} が experimental サブパスから import でき、メインバレルには載らない`, () => {
      expect(typeof (experimental as unknown as Record<string, unknown>)[name]).toBe('function');
      expect((sdk as unknown as Record<string, unknown>)[name]).toBeUndefined();
    });
  }

  test('ChainVerificationCache が experimental サブパスで公開されている（ChainVerifyOptions.cache に渡せる）', () => {
    expect(typeof experimental.ChainVerificationCache).toBe('function');
    expect(new experimental.ChainVerificationCache()).toBeInstanceOf(
      experimental.ChainVerificationCache,
    );
    expect((sdk as unknown as Record<string, unknown>).ChainVerificationCache).toBeUndefined();
  });

  test('公開された関数が実際に動作する（型だけの再エクスポートではない）', async () => {
    const vc: sdk.VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:subject' },
      issuanceDate: '2026-01-01T00:00:00Z',
      id: 'urn:vc:public-surface',
      evidence: {
        type: ['DocumentVerification'],
        verifier: 'did:example:verifier',
      },
      termsOfUse: {
        id: 'urn:tou:public-surface',
        prohibition: [
          {
            uid: 'urn:rule:no-marketing',
            action: 'use',
            constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'marketing' }],
          },
        ],
      },
    };

    const interpretations = await experimental.interpretEvidence(vc);
    expect(interpretations).toHaveLength(1);
    expect(interpretations[0]?.trustLevel).toBe('substantial');

    const context: sdk.UsageContext = {
      verifierId: 'did:example:verifier',
      purpose: 'marketing',
      at: '2026-06-01T00:00:00Z',
    };
    const tou = await experimental.checkTermsOfUse(vc, context);
    expect(tou.compliant).toBe(false);
    expect(tou.violations[0]?.ruleId).toBe('urn:rule:no-marketing');
  });

  test('fail-closed オプション型が公開され checkTermsOfUse に渡せる', async () => {
    const vc: sdk.VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: {},
      issuanceDate: '2026-01-01T00:00:00Z',
      termsOfUse: {
        permission: [
          {
            action: 'use',
            constraint: [{ leftOperand: 'toolName', operator: 'eq', rightOperand: 'search' }],
          },
        ],
      },
    };
    const options: sdk.ToUCheckOptions = { unknownConstraint: 'fail-closed' };
    const context: sdk.UsageContext = { verifierId: 'did:example:verifier' };
    expect((await experimental.checkTermsOfUse(vc, context)).compliant).toBe(true);
    expect((await experimental.checkTermsOfUse(vc, context, options)).compliant).toBe(false);
  });

  test('Credential Chain の型と関数で N:1 来歴を検証できる', async () => {
    const parent: sdk.VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: {},
      issuanceDate: '2026-01-01T00:00:00Z',
      id: 'urn:vc:parent',
    };
    const ref: sdk.VerifiableCredential = { ...parent, id: 'urn:vc:ref' };
    const child = experimental.buildDerivedCredential(parent, {
      ...parent,
      id: 'urn:vc:child',
    });
    const leaf: sdk.VerifiableCredential = { ...child, basedOn: ['urn:vc:ref'] };

    const store = new Map<string, sdk.VerifiableCredential>([
      ['urn:vc:parent', parent],
      ['urn:vc:ref', ref],
      ['urn:vc:child', leaf],
    ]);
    const options: sdk.ChainVerifyOptions = {
      resolveCredential: async (id) => store.get(id),
      verifyLink: () => true,
      resolveStatus: async () => undefined,
    };
    const result: sdk.ChainVerificationResult = await experimental.verifyCredentialChain(
      'urn:vc:child',
      options,
    );
    expect(result.valid).toBe(true);
    expect(result.chain.map((n) => n.vcId)).toEqual([
      'urn:vc:child',
      'urn:vc:parent',
      'urn:vc:ref',
    ]);
    const relations: sdk.ChainRelation[] = result.chain.map((n) => n.relation);
    expect(relations).toEqual(['derivedFrom', 'derivedFrom', 'basedOn']);
  });
});
