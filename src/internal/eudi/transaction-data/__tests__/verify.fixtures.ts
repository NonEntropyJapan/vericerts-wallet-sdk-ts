/**
 * `verifyTransactionDataHashes` テストの共有フィクスチャ。
 *
 * 実鍵・実 SD-JWT・実 KB-JWT を組み立てる helper 群。モックは使わない。
 * `verify.test.ts`（突合の本体）と `verify.alg.test.ts`（アルゴリズムの fail-closed）で共有する。
 * 1 ファイル 300 行の上限（`.linterly.yml`）に収めるため、テスト本体から分離している。
 */

import { expect } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import {
  type ConfirmationClaim,
  createSdJwt,
  selectDisclosures,
} from '../../../credential/sdjwt/sdjwt.js';
import type { CredentialAlg } from '../../../credential/vc/jws.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { extractTransactionData } from '../extract.js';
import { addKeyBindingWithTransactionData } from '../hashes.js';
import { verifyTransactionDataHashes } from '../verify.js';

export const ISSUER_KEY = new Uint8Array(32).fill(7);
export const HOLDER_KEY = new Uint8Array(32).fill(11);

export function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

export const HOLDER_JWK = toJwk(getSecp256k1PublicKey(HOLDER_KEY, false), 'secp256k1');
export const CNF: ConfirmationClaim = { jwk: HOLDER_JWK };
export const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
export const HOLDER_SIGNER: CredentialSigner = createPrivateKeySigner(
  HOLDER_KEY,
  'ES256K' as CredentialAlg,
);
export const VCT = 'https://example.com/credentials/identity';

/** Authorization Request 上の `transaction_data` 要素（base64url JSON）を作る。 */
export function encodeTd(obj: Record<string, unknown>): string {
  return base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(obj)));
}

export const PAYMENT_TD = encodeTd({
  type: 'payment',
  credential_ids: ['pid'],
  amount: '1200',
  payee: 'ACME Store',
});
export const SHIPPING_TD = encodeTd({
  type: 'shipping',
  credential_ids: ['pid'],
  destination: 'Tokyo',
  carrier: 'Yamato',
});

/** 選択的開示済みの提示部（KB-JWT なし、末尾 `~`）を作る。 */
export function presentationBase(): string {
  const sdJwt = createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    issuer: 'did:example:issuer',
    disclosureClaims: ['name'],
    claims: { name: 'Alice', sub: 'holder-1' },
    cnf: CNF,
  });
  return selectDisclosures(sdJwt, ['name']);
}

/** 指定 Transaction Data に束縛した提示（KB-JWT 付き）を作る。 */
export function present(encoded: readonly string[]): string {
  return addKeyBindingWithTransactionData(presentationBase(), HOLDER_SIGNER, {
    nonce: 'nonce-1',
    audience: 'did:example:verifier',
    transactionData: extractTransactionData(encoded),
    iatSeconds: 1_767_225_600,
  });
}

/** 任意の KB-JWT payload を実鍵で署名し、提示部末尾へ連結する（モックなしの手組み KB-JWT）。 */
export function presentWithKbPayload(payload: Record<string, unknown>): string {
  const base = presentationBase();
  const seg = (o: unknown): string =>
    base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(o)));
  const signingInput = `${seg({ alg: 'ES256K', typ: 'kb+jwt' })}.${seg(payload)}`;
  const signature = HOLDER_SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${base}${signingInput}.${base64urlnopad.encode(signature)}`;
}

/** 実際に格納された `transaction_data_hashes` を KB-JWT から取り出す。 */
export function receivedHashes(presentation: string): readonly string[] {
  const kb = presentation.split('~').at(-1) as string;
  const payload = JSON.parse(
    new TextDecoder().decode(base64urlnopad.decode(kb.split('.')[1] as string)),
  );
  return payload.transaction_data_hashes;
}

/** 手組み KB-JWT payload の共通部（`sd_hash` 等は本 helper の検証対象外）。 */
export const KB_BASE = {
  nonce: 'nonce-1',
  aud: 'did:example:verifier',
  iat: 1_767_225_600,
  sd_hash: 'not-verified-by-this-helper',
  transaction_data_hashes_alg: 'sha-256',
};

/** 手組み KB-JWT payload（`KB_BASE` を上書き）を持つ提示を PAYMENT_TD 要求で突合する。 */
export function verifyKbPayload(overrides: Record<string, unknown>): void {
  verifyTransactionDataHashes({
    requested: extractTransactionData([PAYMENT_TD]),
    presentation: presentWithKbPayload({ ...KB_BASE, ...overrides }),
  });
}

/** 10402 で拒否されることを確認する。`reason` 指定時は判別トークンも固定する。 */
export function expect10402(fn: () => void, reason?: string): void {
  let thrown: unknown;
  try {
    fn();
  } catch (e) {
    thrown = e;
  }
  expect(thrown).toBeInstanceOf(VericertsError);
  expect((thrown as VericertsError).code).toBe(ErrorCodes.TRANSACTION_DATA_HASH_MISMATCH);
  if (reason !== undefined) {
    expect((thrown as VericertsError).context?.reason).toBe(reason);
  }
}
