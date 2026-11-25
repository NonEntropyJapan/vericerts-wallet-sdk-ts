/**
 * `presentPIDCredential` / `presentEAACredential` の `transaction_data` 束縛のテスト。
 *
 * 修正前は、要求に `transaction_data` があっても KB-JWT に `transaction_data_hashes` が載らなかった
 * （同意画面で承認した取引内容と署名対象が結び付かない）。実鍵で署名し、送信された `vp_token` の
 * KB-JWT payload を実際にデコードして検証する。
 */

import { describe, expect, test } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { parseSdJwt } from '../../../../credential/sdjwt/sdjwt.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import { extractTransactionData } from '../../../../eudi/transaction-data/extract.js';
import { computeTransactionDataHashes } from '../../../../eudi/transaction-data/hashes.js';
import { presentEAACredential, presentPIDCredential } from '../present.js';
import {
  buildSdJwtVc,
  createSubmitStub,
  EAA_VCT,
  eaaCredential,
  pidCredential,
  presentDeps,
  RESPONSE_URI,
  submittedVpToken,
  VERIFIER_CLIENT_ID,
} from './presentation-fixtures.js';

function encodeTx(value: Record<string, unknown>): string {
  return base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(value)));
}

const PAYMENT = encodeTx({
  type: 'payment',
  credential_ids: ['pid'],
  amount: '9999.00',
  payee: 'attacker',
});
const APPROVAL = encodeTx({ type: 'approval', credential_ids: ['pid'], note: 'ok' });
const OTHER_CREDENTIAL = encodeTx({ type: 'payment', credential_ids: ['other'], amount: '1' });

function requestURI(opts: {
  transactionData?: readonly string[];
  dcqlIds?: readonly string[];
}): string {
  const params = new URLSearchParams({
    response_type: 'vp_token',
    client_id: VERIFIER_CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: 'n-0S6_WzA2Mj-0123456789',
    state: 'state-123',
  });
  const ids = opts.dcqlIds ?? ['pid'];
  params.set(
    'dcql_query',
    JSON.stringify({ credentials: ids.map((id) => ({ id, format: 'dc+sd-jwt' })) }),
  );
  if (opts.transactionData !== undefined) {
    params.set('transaction_data', JSON.stringify(opts.transactionData));
  }
  return `openid4vp://?${params.toString()}`;
}

/** 送信された vp_token の KB-JWT payload。 */
function kbPayload(vpToken: string): Record<string, unknown> {
  const kb = parseSdJwt(vpToken).keyBinding as string;
  const payload = kb.split('.')[1] as string;
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(payload))) as Record<
    string,
    unknown
  >;
}

function expectCode(error: unknown, code: ErrorCode): void {
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(code);
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (e) {
    return e;
  }
  throw new Error('should reject');
}

describe('transaction_data を KB-JWT へ束縛する', () => {
  test('presentPID: 要求順の transaction_data_hashes（+ _alg）が署名済み KB-JWT に入る', async () => {
    const stub = createSubmitStub();
    await presentPIDCredential(
      requestURI({ transactionData: [PAYMENT, APPROVAL] }),
      ['family_name'],
      pidCredential(),
      presentDeps(stub.fetchImpl, [PAYMENT, APPROVAL]),
    );
    const payload = kbPayload(submittedVpToken(stub.calls[0]));
    // 期待値は生の base64url 文字列に対する SHA-256（base64url）を独立に計算して照合する。
    const expected = [PAYMENT, APPROVAL].map((tx) =>
      base64urlnopad.encode(sha256(new TextEncoder().encode(tx))),
    );
    expect(payload.transaction_data_hashes).toEqual(expected);
    expect(payload.transaction_data_hashes).toEqual(
      computeTransactionDataHashes(extractTransactionData([PAYMENT, APPROVAL])),
    );
    expect(payload.transaction_data_hashes_alg).toBe('sha-256');
    expect(payload.nonce).toBe('n-0S6_WzA2Mj-0123456789');
    expect(payload.aud).toBe(VERIFIER_CLIENT_ID);
  });

  test('transaction_data が無い要求の KB-JWT には hashes が入らない（従来どおり）', async () => {
    const stub = createSubmitStub();
    await presentPIDCredential(
      requestURI({}),
      ['family_name'],
      pidCredential(),
      presentDeps(stub.fetchImpl),
    );
    const payload = kbPayload(submittedVpToken(stub.calls[0]));
    expect(payload).not.toHaveProperty('transaction_data_hashes');
    expect(payload).not.toHaveProperty('transaction_data_hashes_alg');
  });

  test('presentEAA: 一致する各 (Q)EAA の KB-JWT が同じ hashes を持つ', async () => {
    const stub = createSubmitStub();
    const second = {
      vct: EAA_VCT,
      claims: { degree: 'PhD' },
      raw: buildSdJwtVc(EAA_VCT, { degree: 'PhD' }),
    };
    await presentEAACredential(
      requestURI({ transactionData: [PAYMENT] }),
      EAA_VCT,
      [eaaCredential(), second],
      presentDeps(stub.fetchImpl, [PAYMENT]),
    );
    const tokens = JSON.parse(
      new URLSearchParams(stub.calls[0]?.body ?? '').get('vp_token') ?? '[]',
    );
    expect(tokens).toHaveLength(2);
    const expected = computeTransactionDataHashes(extractTransactionData([PAYMENT]));
    for (const token of tokens as string[]) {
      expect(kbPayload(token).transaction_data_hashes).toEqual(expected);
    }
  });

  test('consentedTransactionData が署名対象の要求と同一なら通り、1 件でも違えば 10402 で署名・送信しない', async () => {
    const ok = createSubmitStub();
    await presentPIDCredential(requestURI({ transactionData: [PAYMENT] }), [], pidCredential(), {
      ...presentDeps(ok.fetchImpl),
      consentedTransactionData: [PAYMENT],
    });
    expect(ok.calls).toHaveLength(1);

    // 同意した取引と要求が違う / 件数が違う / 順序が違う / 同意なしなのに要求にある。
    const cases: [readonly string[], readonly string[]][] = [
      [[PAYMENT], [APPROVAL]],
      [[PAYMENT, APPROVAL], [PAYMENT]],
      [[PAYMENT], [PAYMENT, APPROVAL]],
      [
        [PAYMENT, APPROVAL],
        [APPROVAL, PAYMENT],
      ],
      [[PAYMENT], []],
    ];
    for (const [requested, consented] of cases) {
      const stub = createSubmitStub();
      const error = await rejection(
        presentPIDCredential(requestURI({ transactionData: requested }), [], pidCredential(), {
          ...presentDeps(stub.fetchImpl),
          consentedTransactionData: consented,
        }),
      );
      expectCode(error, ErrorCodes.TRANSACTION_DATA_HASH_MISMATCH);
      expect(stub.calls).toHaveLength(0);
    }
  });

  test('同意が空配列で要求にも transaction_data が無ければ通る', async () => {
    const stub = createSubmitStub();
    await presentPIDCredential(requestURI({}), [], pidCredential(), {
      ...presentDeps(stub.fetchImpl),
      consentedTransactionData: [],
    });
    expect(stub.calls).toHaveLength(1);
  });

  // 照合指定が無いまま署名すると、Verifier は `request_uri` の 2 回目の GET で取引内容を
  // 差し替えられる（同意画面に出した取引と KB-JWT に束縛される取引が別物になる）。
  test('transaction_data を持つ要求で consentedTransactionData 未指定なら署名せず 10402', async () => {
    const stub = createSubmitStub();
    const error = await rejection(
      presentPIDCredential(
        requestURI({ transactionData: [PAYMENT] }),
        [],
        pidCredential(),
        presentDeps(stub.fetchImpl),
      ),
    );
    expectCode(error, ErrorCodes.TRANSACTION_DATA_HASH_MISMATCH);
    expect((error as VericertsError).context).toMatchObject({
      reason: 'transaction_data_consent_required',
    });
    expect(stub.calls).toHaveLength(0);
  });

  test('transaction_data を持たない要求は未指定でも従来どおり通る', async () => {
    const stub = createSubmitStub();
    await presentPIDCredential(requestURI({}), [], pidCredential(), presentDeps(stub.fetchImpl));
    expect(stub.calls).toHaveLength(1);
  });
});

describe('束縛できない transaction_data は署名せず fail-closed', () => {
  test('どの提示にも紐付かない credential_ids の取引が混ざる要求は 8035', async () => {
    const stub = createSubmitStub();
    const error = await rejection(
      presentPIDCredential(
        requestURI({ transactionData: [PAYMENT, OTHER_CREDENTIAL] }),
        [],
        pidCredential(),
        presentDeps(stub.fetchImpl, [PAYMENT, OTHER_CREDENTIAL]),
      ),
    );
    expectCode(error, ErrorCodes.PRESENTATION_SUBMIT_FAILED);
    expect(stub.calls).toHaveLength(0);
  });

  test('DCQL が複数要件で提示と要件 id を決められない要求は 8035', async () => {
    const stub = createSubmitStub();
    const error = await rejection(
      presentPIDCredential(
        requestURI({ transactionData: [PAYMENT], dcqlIds: ['pid', 'other'] }),
        [],
        pidCredential(),
        presentDeps(stub.fetchImpl, [PAYMENT]),
      ),
    );
    expectCode(error, ErrorCodes.PRESENTATION_SUBMIT_FAILED);
    expect(stub.calls).toHaveLength(0);
  });

  test('type / credential_ids が不正な transaction_data は 8030', async () => {
    const stub = createSubmitStub();
    const noType = encodeTx({ credential_ids: ['pid'] });
    const error = await rejection(
      presentPIDCredential(
        requestURI({ transactionData: [noType] }),
        [],
        pidCredential(),
        presentDeps(stub.fetchImpl, [noType]),
      ),
    );
    expectCode(error, ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(stub.calls).toHaveLength(0);
  });

  test('未対応のハッシュアルゴリズムだけを指定する取引は 8030', async () => {
    const stub = createSubmitStub();
    const sha512 = encodeTx({
      type: 'payment',
      credential_ids: ['pid'],
      transaction_data_hashes_alg: ['sha-512'],
    });
    const error = await rejection(
      presentPIDCredential(
        requestURI({ transactionData: [sha512] }),
        [],
        pidCredential(),
        presentDeps(stub.fetchImpl, [sha512]),
      ),
    );
    expectCode(error, ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(stub.calls).toHaveLength(0);
  });
});
