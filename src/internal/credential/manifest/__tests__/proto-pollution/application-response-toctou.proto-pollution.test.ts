/**
 * `processCredentialResponse` が応答メンバを**同じキーで 2 度読まない**こと。
 *
 * 是正前は検査と採用が別々の読み取りだった（`isNonBlankString(raw.credential) ? raw.credential : …`
 * の形）。プロパティがアクセサなら getter は呼ばれるたびに別の値を返せるため、
 * **`isNonBlankString` を通した値と実際に採用される値が食い違う**（TOCTOU）。
 *
 * `Object.prototype` 汚染そのものは `application-response.proto-pollution.test.ts` の own 限定読みで
 * 塞がるが、2 度読みはそれとは独立した欠陥として残る。`processCredentialResponse` は
 * `credential/index.ts` から公開されており、`JSON.parse` 由来とは限らない任意のオブジェクトを
 * 呼び出し側から受け取りうるため、**own のアクセサ**で成立する。ここではその形で固定する。
 *
 * 各テストは getter の呼び出し回数も確認する（1 回だけ読むことの直接の固定）。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../vc/vc.js';
import { processCredentialResponse } from '../../application-response.js';

const HONEST_VC = 'eyJhbGciOiJFUzI1NiJ9.honest-vc';
const ATTACKER_VC = 'eyJhbGciOiJFUzI1NiJ9.attacker-vc';
const HONEST_REASON = 'insufficient evidence';
const ATTACKER_REASON = 'attacker-controlled rejection';
const HONEST_TX = 'tx-issuer-1';
const ATTACKER_TX = 'tx-attacker';

const VERIFIED_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'IdentityCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:holder' },
  issuanceDate: '2026-01-01T00:00:00Z',
  id: 'urn:vc:issued',
};

/** 受け取った生 VC を記録する `verify` DI。 */
function recordingVerify(): { fn: (raw: string) => Promise<VerifiableCredential>; seen: string[] } {
  const seen: string[] = [];
  return {
    seen,
    fn: async (raw: string) => {
      seen.push(raw);
      return VERIFIED_VC;
    },
  };
}

/**
 * `key` を **own のアクセサ**として持つオブジェクトを作る。
 *
 * getter は 1 回目に `first`、2 回目以降は `rest` を返す。2 度読みする実装では検査に `first` を
 * 使いながら `rest` を採用してしまう。読み取り回数を `reads()` で観測する。
 */
function withTogglingAccessor(
  key: string,
  first: unknown,
  rest: unknown,
  base: Record<string, unknown> = {},
): { raw: Record<string, unknown>; reads: () => number } {
  let reads = 0;
  const raw: Record<string, unknown> = { ...base };
  Object.defineProperty(raw, key, {
    get: () => {
      reads += 1;
      return reads === 1 ? first : rest;
    },
    enumerable: true,
    configurable: true,
  });
  return { raw, reads: () => reads };
}

describe('processCredentialResponse: 同一キーを 2 度読まない（アクセサ TOCTOU）', () => {
  it('verifiableCredential は 1 回だけ読み、検査した値をそのまま検証へ渡す', async () => {
    const verify = recordingVerify();
    const { raw, reads } = withTogglingAccessor('verifiableCredential', HONEST_VC, ATTACKER_VC);

    const result = await processCredentialResponse(raw, verify.fn);

    expect(reads()).toBe(1);
    expect(verify.seen).toEqual([HONEST_VC]);
    expect(result).toMatchObject({ accepted: true, credential: VERIFIED_VC });
  });

  it('credential は 1 回だけ読み、検査した値をそのまま検証へ渡す', async () => {
    const verify = recordingVerify();
    const { raw, reads } = withTogglingAccessor('credential', HONEST_VC, ATTACKER_VC);

    const result = await processCredentialResponse(raw, verify.fn);

    expect(reads()).toBe(1);
    expect(verify.seen).toEqual([HONEST_VC]);
    expect(result).toMatchObject({ accepted: true, credential: VERIFIED_VC });
  });

  it('transaction_id は 1 回だけ読み、検査した取引 ID をそのまま返す', async () => {
    const verify = recordingVerify();
    const { raw, reads } = withTogglingAccessor('transaction_id', HONEST_TX, ATTACKER_TX);

    const result = await processCredentialResponse(raw, verify.fn);

    expect(reads()).toBe(1);
    expect(result).toMatchObject({ accepted: true, transactionId: HONEST_TX });
  });

  it('transactionId は 1 回だけ読み、検査した取引 ID をそのまま返す', async () => {
    const verify = recordingVerify();
    const { raw, reads } = withTogglingAccessor('transactionId', HONEST_TX, ATTACKER_TX);

    const result = await processCredentialResponse(raw, verify.fn);

    expect(reads()).toBe(1);
    expect(result).toMatchObject({ accepted: true, transactionId: HONEST_TX });
  });

  it('rejectionReason は 1 回だけ読み、検査した理由をそのまま返す', async () => {
    const verify = recordingVerify();
    const { raw, reads } = withTogglingAccessor('rejectionReason', HONEST_REASON, ATTACKER_REASON);

    const result = await processCredentialResponse(raw, verify.fn);

    expect(reads()).toBe(1);
    expect(result).toMatchObject({ accepted: false, rejectionReason: HONEST_REASON });
  });

  it('denial は 1 回だけ読み、その 1 回で得たオブジェクトの reason を使う', async () => {
    const verify = recordingVerify();
    // 是正前は `isPlainObject(raw.denial)` と `raw.denial.reason`（検査・採用）で最大 3 回読んでいた。
    const { raw, reads } = withTogglingAccessor(
      'denial',
      { reason: HONEST_REASON },
      { reason: ATTACKER_REASON },
    );

    const result = await processCredentialResponse(raw, verify.fn);

    expect(reads()).toBe(1);
    expect(result).toMatchObject({ accepted: false, rejectionReason: HONEST_REASON });
  });

  it('denial.reason（内側）も 1 回だけ読み、検査した理由をそのまま返す', async () => {
    const verify = recordingVerify();
    const inner = withTogglingAccessor('reason', HONEST_REASON, ATTACKER_REASON);

    const result = await processCredentialResponse({ denial: inner.raw }, verify.fn);

    expect(inner.reads()).toBe(1);
    expect(result).toMatchObject({ accepted: false, rejectionReason: HONEST_REASON });
  });
});
