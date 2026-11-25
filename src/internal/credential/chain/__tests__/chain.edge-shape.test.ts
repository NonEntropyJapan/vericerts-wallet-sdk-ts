/**
 * 親エッジ宣言が想定外の型のときの fail-closed。
 *
 * 4 つの親エッジフィールド（`derivedFrom` / `basedOn` / `supersedes` / `amends`）が
 * `string` / `string[]` に正規化できないと、親が一切走査されず失効した親を持つチェーンが
 * `valid: true` になっていた。`CHAIN_PARENT_UNRESOLVABLE`（4052）で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { StatusCheckResult } from '../../sdjwt/status.js';
import type { CredentialStatus, VerifiableCredential } from '../../vc/vc.js';
import { type ChainVerifyOptions, verifyCredentialChain } from '../index.js';

const STATUS_REF: CredentialStatus = {
  id: 'https://issuer.example/status/1#0',
  type: 'BitstringStatusListEntry',
};

function makeVc(id: string, extra: Record<string, unknown> = {}): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id,
    ...extra,
  } as unknown as VerifiableCredential;
}

function depsFor(...vcs: VerifiableCredential[]): ChainVerifyOptions {
  const store = new Map(vcs.map((vc) => [vc.id as string, vc]));
  return {
    resolveCredential: async (id) => store.get(id),
    verifyLink: () => true,
    resolveStatus: async (vc): Promise<StatusCheckResult> =>
      vc.id === 'parent'
        ? { valid: false, purpose: 'revocation', value: 1 }
        : { valid: true, purpose: 'revocation', value: 0 },
  };
}

const PARENT = makeVc('parent', { credentialStatus: STATUS_REF });

const MALFORMED: ReadonlyArray<readonly [string, unknown]> = [
  ['{ id } オブジェクト', { id: 'parent' }],
  ['{ id } オブジェクトの配列', [{ id: 'parent' }]],
  ['空文字', ''],
  ['数値', 5],
  ['null', null],
  ['真偽値', true],
  ['非文字列要素を含む配列', ['parent', 5]],
  ['空文字要素を含む配列', ['parent', '']],
];

describe('親エッジ宣言が string / string[] でないと 4052', () => {
  for (const field of ['derivedFrom', 'basedOn', 'supersedes', 'amends'] as const) {
    it.each(MALFORMED)(`${field}: %s`, async (_name, value) => {
      const child = makeVc('child', { [field]: value });
      let caught: unknown;
      try {
        await verifyCredentialChain('child', depsFor(PARENT, child));
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(VericertsError);
      expect((caught as VericertsError).code).toBe(ErrorCodes.CHAIN_PARENT_UNRESOLVABLE);
    });
  }

  it('正常形（文字列・文字列配列・空配列・未指定）は従来どおり', async () => {
    const byString = makeVc('child', { derivedFrom: 'parent' });
    const result = await verifyCredentialChain('child', depsFor(PARENT, byString));
    expect(result.valid).toBe(false);
    expect(result.chain).toHaveLength(2);

    const byArray = makeVc('child', { derivedFrom: ['parent'] });
    expect((await verifyCredentialChain('child', depsFor(PARENT, byArray))).chain).toHaveLength(2);

    const empty = makeVc('child', { derivedFrom: [] });
    const emptyResult = await verifyCredentialChain('child', depsFor(PARENT, empty));
    expect(emptyResult.valid).toBe(true);
    expect(emptyResult.chain).toHaveLength(1);

    const none = makeVc('child');
    expect((await verifyCredentialChain('child', depsFor(none))).chain).toHaveLength(1);
  });
});
