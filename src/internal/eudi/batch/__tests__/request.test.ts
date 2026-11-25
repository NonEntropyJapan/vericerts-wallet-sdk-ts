/**
 * Batch Credential Request 組み立てテスト。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { buildBatchCredentialRequest } from '../request.js';
import type { BatchProof } from '../types.js';

function jwtProof(jwt: string): BatchProof {
  return { proofType: 'jwt', jwt };
}

/**
 * 入力検証の失敗が SDK 共通の `VericertsError` かつ code `8020` で投げられることを検証する。
 * `toThrow(VericertsError)` だけでは他コードの `VericertsError` でも通り、
 * レジストリ外の独自例外へ戻る回帰を検知できないため code まで確認する。
 */
function expectCredentialRequestFailed(fn: () => unknown, reason: string): VericertsError {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  const error = caught as VericertsError;
  expect(error.code).toBe(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  expect(error.context?.reason).toBe(reason);
  return error;
}

describe('buildBatchCredentialRequest', () => {
  test('N 個の proof を { proofs: { jwt: [...] } } 形式にまとめる', () => {
    const proofs = [jwtProof('p1'), jwtProof('p2'), jwtProof('p3')];
    const req = buildBatchCredentialRequest('urn:eudi:pid:1', proofs);
    expect(req.vct).toBe('urn:eudi:pid:1');
    expect(req.proofs.jwt).toEqual(['p1', 'p2', 'p3']);
  });

  test('proof の入力順を保持する（Issuer は同順で credentials を返す）', () => {
    const proofs = [jwtProof('a'), jwtProof('b'), jwtProof('c'), jwtProof('d')];
    const req = buildBatchCredentialRequest('urn:eudi:pid:1', proofs);
    expect(req.proofs.jwt).toEqual(['a', 'b', 'c', 'd']);
  });

  test('単一 proof でもバッチ形式（配列）で返す', () => {
    const req = buildBatchCredentialRequest('urn:eudi:pid:1', [jwtProof('only')]);
    expect(req.proofs.jwt).toEqual(['only']);
  });

  test('vct が空文字なら VericertsError(8020)', () => {
    expectCredentialRequestFailed(
      () => buildBatchCredentialRequest('', [jwtProof('p1')]),
      'missing_vct',
    );
  });

  test('proofs が空配列なら VericertsError(8020)', () => {
    expectCredentialRequestFailed(
      () => buildBatchCredentialRequest('urn:eudi:pid:1', []),
      'empty_proofs',
    );
  });

  test('proofType が jwt 以外なら VericertsError(8020)', () => {
    const bad = [{ proofType: 'cwt', jwt: 'x' } as unknown as BatchProof];
    expectCredentialRequestFailed(
      () => buildBatchCredentialRequest('urn:eudi:pid:1', bad),
      'invalid_proof_type',
    );
  });

  test('jwt が空文字なら VericertsError(8020)（該当 index を context に含む）', () => {
    const proofs = [jwtProof('p1'), jwtProof('')];
    const error = expectCredentialRequestFailed(
      () => buildBatchCredentialRequest('urn:eudi:pid:1', proofs),
      'empty_jwt',
    );
    expect(error.context?.index).toBe(1);
  });
});
