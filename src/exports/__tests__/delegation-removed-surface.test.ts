/**
 * 独自の委任機能（signAsDelegate / DelegationGrant / SubjectBinding）の公開 API を削除したことの回帰テスト
 *
 * 委任は W3C DID Core の `controller` / `capabilityDelegation` だけで表す。独自の代理署名・委任証書・
 * 保持者管理（`relationship` × `scope`）と、それらに由来する委任提示の突合材料、エラーコード
 * 2011〜2015 は、互換 export なしで削除した。誤って export を戻すことを防ぐ。
 */

import { describe, expect, it } from 'bun:test';
import * as sdk from '../../index.js';
import { ErrorCodes } from '../../internal/errors.js';

describe('公開エクスポート: 独自の委任機能は公開されない', () => {
  it.each([
    'signAsDelegate',
    'issueSubjectBinding',
    'verifySubjectBinding',
    'SubjectBindingManager',
    'issueDelegationGrant',
    'verifyDelegationGrant',
    'DELEGATION_GRANT_VCT',
    'DELEGATE_SIGNATURE_PREFIX',
    'delegateSignaturePayload',
    'evaluateScope',
    'evaluateScopeChain',
    'assertIsController',
    'delegatedPresentationFromDelegationGrant',
    'delegatedPresentationFromSubjectBinding',
    'delegatedPresentationFromSubjectBindingRecord',
    'isDelegatedPresentationAuthorized',
    'lendToCustodianBindingInput',
  ])('%s はメインバレルに存在しない', (name) => {
    expect(name in sdk).toBe(false);
  });

  it('残る委任の公開 API は did:ethr の controller 操作だけである', () => {
    for (const name of [
      'buildSetControllerTx',
      'buildRemoveControllerTx',
      'detectController',
      'createErc1056AbiEncoder',
      'createEthersEventSource',
      'parseEthrDid',
      'formatEthrDid',
    ]) {
      expect(name in sdk).toBe(true);
    }
  });

  it.each([
    'SUBJECT_BINDING_AGE_LIMIT',
    'SUBJECT_BINDING_SCOPE_DENIED',
    'DELEGATION_BASIS_MISMATCH',
    'DELEGATION_SCOPE_EXCEEDED',
    'SUBJECT_BINDING_NOT_FOUND',
  ])('ErrorCodes.%s は存在しない（2011〜2015 の削除）', (name) => {
    expect(name in ErrorCodes).toBe(false);
  });
});
