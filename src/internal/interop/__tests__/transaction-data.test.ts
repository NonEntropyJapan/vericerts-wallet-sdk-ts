/**
 * HAIP SD-JWT VC + Transaction Data 提示の相互運用テスト。
 *
 * HAIP の OID4VP 提示で Transaction Data（payment 等）への同意を要求する場合、Holder は
 * `transaction_data_hashes` を KB-JWT に格納して署名する。本テストは
 * 実装済みの transaction-data モジュールと SD-JWT VC 提示の結合が相互運用境界で一貫することを
 * 実鍵で検証する（抽出 → ハッシュ → KB-JWT 格納 → 検証）。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  credentialInput,
  foreignHolderSigner,
  holderSigner,
  ISSUER_JWK,
  issuerSigner,
} from '../fixtures.js';
import { runInteropTxPair } from '../tx-harness.js';

const NONCE = 'tx-nonce-77c1';
const AUD = 'https://rp.example/pay';
const IAT = 1_767_225_600;

/** payment 種別の Transaction Data を base64url JSON として組み立てる。 */
function paymentTransactionData(): string {
  const payload = {
    type: 'payment',
    credential_ids: ['haip-cred-1'],
    amount: '42.00',
    currency: 'EUR',
    payee: 'Merchant BVBA',
  };
  return base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(payload)));
}

/** テキスト → base64url SHA-256（KB-JWT の transaction_data_hashes 期待値）。 */
function b64uSha256(text: string): string {
  return base64urlnopad.encode(sha256(new TextEncoder().encode(text)));
}

function baseTxInput() {
  return {
    issuer: issuerSigner(),
    issuerKey: ISSUER_JWK,
    holder: holderSigner(),
    credential: credentialInput(),
    requestedClaims: ['nickname'] as const,
    nonce: NONCE,
    audience: AUD,
    transactionData: [paymentTransactionData()],
    iatSeconds: IAT,
  };
}

describe('HAIP Transaction Data 提示 — 相互運用', () => {
  it('Transaction Data 付き提示が検証成功する', () => {
    const result = runInteropTxPair(baseTxInput());
    expect(result.verified.keyBindingVerified).toBe(true);
    expect(result.extracted.length).toBe(1);
    expect(result.extracted[0]?.type).toBe('payment');
  });

  it('KB-JWT に transaction_data_hashes が生 base64url の SHA-256 として格納される', () => {
    const td = paymentTransactionData();
    const result = runInteropTxPair({ ...baseTxInput(), transactionData: [td] });
    const kb = result.presented.split('~').at(-1) as string;
    const kbPayload = JSON.parse(
      new TextDecoder().decode(base64urlnopad.decode(kb.split('.')[1] as string)),
    );
    expect(kbPayload.transaction_data_hashes).toEqual([b64uSha256(td)]);
    expect(kbPayload.transaction_data_hashes_alg).toBe('sha-256');
  });

  it('cnf 非対応鍵で署名した Transaction Data KB-JWT は HOLDER_BIND_MISMATCH（3012）', () => {
    expect(() => runInteropTxPair({ ...baseTxInput(), holder: foreignHolderSigner() })).toThrow(
      new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH),
    );
  });

  it('不正な base64url Transaction Data は抽出時に拒否される（8030）', () => {
    expect(() =>
      runInteropTxPair({ ...baseTxInput(), transactionData: ['%%%not-base64%%%'] }),
    ).toThrow(new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED));
  });
});
