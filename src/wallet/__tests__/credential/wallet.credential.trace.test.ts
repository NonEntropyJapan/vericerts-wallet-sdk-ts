/**
 * Wallet ファサードの `vc.verify` トレース配線のテスト。
 *
 * `createWallet({ tracer })` に記録トレーサを注入し、did:key の自己発行 → 自己検証（実署名・
 * ネット非依存）で Span の属性・ステータス・例外記録・`end()` を検証する。ログ配線側の検証は
 * `wallet.credential.test.ts` にあり、両者は 独立して積まれる。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { VericertsError } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import { findSpan, recordingTracer } from '../metrics/tracer.fixtures.js';

// BIP-39 公式オールゼロ・エントロピーのニーモニック（passphrase なし）。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** 記録トレーサを注入した Wallet で自己発行した JWT-VC を用意する。 */
async function setupWithTracer() {
  const { tracer, spans } = recordingTracer();
  const wallet = await createWallet({ storage: new MemoryStorage(), tracer });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  const document = await wallet.createDID('key', { keyID: keyPair.id });
  const vc: VerifiableCredential = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: document.id,
    credentialSubject: { id: document.id, name: 'Alice' },
    issuanceDate: '2026-01-01T00:00:00Z',
  };
  const jwt = await wallet.issueCredential(vc, keyPair.id);
  return { wallet, jwt, spans, did: document.id };
}

describe('Wallet.verifyCredentialStrict のトレース配線', () => {
  it('検証成功で vc.format / vc.issuer（ハッシュ 16 桁）/ vc.result=success を積んで閉じる', async () => {
    const { wallet, jwt, spans, did } = await setupWithTracer();

    await wallet.verifyCredentialStrict(jwt);

    const span = findSpan(spans, 'vc.verify');
    expect(span?.attributes['vc.format']).toBe('jwt');
    expect(span?.attributes['vc.result']).toBe('success');
    expect(span?.status).toEqual({ status: 'ok', description: undefined });
    expect(span?.ended).toBe(true);
    // `vc.issuer` は `sha256(issuer)` の先頭 16 桁。生の DID は載せない。
    const expected = bytesToHex(sha256(new TextEncoder().encode(did))).slice(0, 16);
    expect(span?.attributes['vc.issuer']).toBe(expected);
    expect(span?.attributes['vc.issuer']).not.toBe(did);
    // 本経路はステータスリスト失効確認を行わないため `vc.status_check` は載せない。
    expect(span?.attributes['vc.status_check']).toBeUndefined();
  });

  it('検証失敗で recordException / vc.result=failure / error(コード) を積んで閉じる', async () => {
    const { tracer, spans } = recordingTracer();
    const wallet = await createWallet({ storage: new MemoryStorage(), tracer });
    // iss を持たない最小 JWS（`verifyCredential` は 3002 で失敗する）。
    const header = Buffer.from(JSON.stringify({ alg: 'ES256K', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ foo: 'bar' })).toString('base64url');

    await expect(wallet.verifyCredentialStrict(`${header}.${payload}.AA`)).rejects.toBeInstanceOf(
      VericertsError,
    );

    const span = findSpan(spans, 'vc.verify');
    expect(span?.attributes['vc.format']).toBe('jwt');
    expect(span?.attributes['vc.result']).toBe('failure');
    expect(span?.status).toEqual({ status: 'error', description: '3002' });
    expect(span?.exceptions[0]).toBeInstanceOf(VericertsError);
    expect(span?.ended).toBe(true);
    // 発行者が判らない失敗では `vc.issuer` を推測しない。
    expect(span?.attributes['vc.issuer']).toBeUndefined();
  });

  it('tracer 未注入でも verifyCredentialStrict の挙動は変わらない（no-op）', async () => {
    const { jwt, did } = await setupWithTracer();
    const plain = await createWallet({ storage: new MemoryStorage() });

    const verified = await plain.verifyCredentialStrict(jwt);

    expect(verified.payload.iss).toBe(did);
  });
});
