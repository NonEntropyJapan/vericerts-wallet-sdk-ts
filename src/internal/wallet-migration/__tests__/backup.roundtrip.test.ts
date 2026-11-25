/**
 * W2W バックアップのラウンドトリップ / 改ざん検知テスト。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../errors.js';
import { exportBackup, importBackup } from '../backup.js';
import type { BackupSource, ExportOptions } from '../types.js';
import { OTHER_PRIVATE_KEY, testPublicKeyJwk, testSigner } from './fixtures.js';

const PASSPHRASE = 'correct-horse-battery';

const SOURCE: BackupSource = {
  walletId: 'urn:uuid:wallet-1',
  walletProvider: 'vericerts',
  credentials: [
    { id: 'vc-1', format: 'vc+sd-jwt', data: 'eyJ...vc1' },
    { id: 'vc-2', format: 'mso_mdoc', data: 'base64-mdoc-2' },
    { id: 'vc-demo', format: 'ephemeral-demo-vc', data: 'demo' },
  ],
  personas: [{ id: 'persona-0', data: JSON.stringify({ index: 0, label: 'private' }) }],
  dids: [{ id: 'did:key:zAbc', data: JSON.stringify({ did: 'did:key:zAbc' }) }],
  settings: JSON.stringify({ locale: 'ja' }),
};

// テストを高速化するため PBKDF2 反復回数を小さく設定する（暗号設計は同一）。
const OPTS: ExportOptions = { passphrase: PASSPHRASE, iterations: 1000 };

describe('exportBackup / importBackup roundtrip', () => {
  it('restores all entries with matching plaintext', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, OPTS);
    const result = await importBackup(backup, PASSPHRASE, signer.publicKeyJwk);

    expect(result.summary.vcCount).toBe(3);
    expect(result.summary.personaCount).toBe(1);
    expect(result.summary.didCount).toBe(1);
    expect(result.conflicts).toEqual([]);

    const vc1 = result.credentials.find((c) => c.id === 'vc-1');
    expect(vc1?.data).toBe('eyJ...vc1');
    expect(vc1?.format).toBe('vc+sd-jwt');
    expect(result.personas[0]?.data).toBe(JSON.stringify({ index: 0, label: 'private' }));
    expect(result.dids[0]?.data).toBe(JSON.stringify({ did: 'did:key:zAbc' }));
    expect(result.settings).toBe(JSON.stringify({ locale: 'ja' }));
  });

  it('sets the container header fields', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, OPTS);
    expect(backup.version).toBe('1.0');
    expect(backup.encryption.alg).toBe('A256GCM');
    expect(backup.encryption.kdf).toBe('PBKDF2-SHA-256');
    // 範囲内のカスタム反復回数はそのままヘッダに載る（エクスポート側の範囲検査の正常系）。
    expect(backup.encryption.kdfParams.iterations).toBe(1000);
    expect(backup.encryption.passphraseProtected).toBe(true);
    expect(backup.integrity.alg).toBe('ES256');
    expect(backup.integrity.signerKeyId).toBe('did:key:test#0');
    expect(backup.walletId).toBe('urn:uuid:wallet-1');
  });

  it('respects excludeFormats (drops ephemeral-demo-vc)', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, {
      ...OPTS,
      excludeFormats: ['ephemeral-demo-vc'],
    });
    const result = await importBackup(backup, PASSPHRASE, signer.publicKeyJwk);
    expect(result.summary.vcCount).toBe(2);
    expect(result.credentials.find((c) => c.id === 'vc-demo')).toBeUndefined();
  });

  it('omits VCs when includeVCs=false and personas when includePersonas=false', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, {
      ...OPTS,
      includeVCs: false,
      includePersonas: false,
    });
    const result = await importBackup(backup, PASSPHRASE, signer.publicKeyJwk);
    expect(result.summary.vcCount).toBe(0);
    expect(result.summary.personaCount).toBe(0);
    expect(result.summary.didCount).toBe(1);
  });

  it('rejects passphrases shorter than 10 chars (4032)', async () => {
    const signer = testSigner();
    const promise = exportBackup(SOURCE, signer, { passphrase: 'short' });
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: '4032' });
  });

  // パスフレーズ検査は最小 10 文字に加え zxcvbn スコア >= 3 を要求するが、文字数のみの
  // ガードでは 'aaaaaaaaaa'（ちょうど 10 文字、zxcvbn score 0）のような弱いパスフレーズが
  // 通ってしまっていた。
  it('rejects a 10-char passphrase that is weak per zxcvbn (score < 3, 4032)', async () => {
    const signer = testSigner();
    const promise = exportBackup(SOURCE, signer, { passphrase: 'aaaaaaaaaa' });
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: '4032' });
  });

  // 範囲外の `iterations` をエクスポート側で弾かないと、非整数ならインポート側の範囲検査
  // （4033）に必ず落ちる「開けないコンテナ」が、下限未満なら PBKDF2 1 回相当の弱いコンテナが
  // 黙って作られてしまう。
  it.each([
    ['ゼロ', 0],
    ['非整数', 1.5],
    ['上限超過', 50_000_000],
  ])('rejects an out-of-range iterations at export time (%s, 1051)', async (_label, iterations) => {
    const promise = exportBackup(SOURCE, testSigner(), { ...OPTS, iterations });
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: '1051' });
  });

  it('fails import with wrong passphrase (4032)', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, OPTS);
    const promise = importBackup(backup, 'wrong-passphrase-x', signer.publicKeyJwk);
    await expect(promise).rejects.toMatchObject({ code: '4032' });
  });

  it('fails import when integrity signature is tampered (4033)', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, OPTS);
    const tampered = {
      ...backup,
      walletId: 'urn:uuid:attacker',
    };
    const promise = importBackup(tampered, PASSPHRASE, signer.publicKeyJwk);
    await expect(promise).rejects.toMatchObject({ code: '4033' });
  });

  it('fails import when signed by a different key (4033)', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, OPTS);
    const otherPub = testPublicKeyJwk(OTHER_PRIVATE_KEY);
    const promise = importBackup(backup, PASSPHRASE, otherPub);
    await expect(promise).rejects.toMatchObject({ code: '4033' });
  });

  // jwkToUncompressedPublicKey の統合後も、署名者 JWK 自体が不正な場合は
  // 4033 ではなく 2001（INVALID_DID）が送出されることを固定する。
  it.each([
    ['crv 不一致', { ...testPublicKeyJwk(), crv: 'secp256k1' }],
    ['x が base64url でない', { ...testPublicKeyJwk(), x: '!!!' }],
  ])('fails import with 2001 for a malformed signer jwk (%s)', async (_label, jwk) => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, OPTS);
    const promise = importBackup(backup, PASSPHRASE, jwk);
    await expect(promise).rejects.toMatchObject({ code: '2001' });
  });

  it('fails import on unsupported version (4036)', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, OPTS);
    const wrongVersion = { ...backup, version: '2.0' as unknown as typeof backup.version };
    const promise = importBackup(wrongVersion, PASSPHRASE, signer.publicKeyJwk);
    await expect(promise).rejects.toMatchObject({ code: '4036' });
  });

  it('detects duplicate ids across kinds as conflicts', async () => {
    const signer = testSigner();
    const dupSource: BackupSource = {
      walletId: 'w',
      credentials: [{ id: 'shared', data: 'a' }],
      personas: [{ id: 'shared', data: 'b' }],
      dids: [],
    };
    const backup = await exportBackup(dupSource, signer, OPTS);
    const result = await importBackup(backup, PASSPHRASE, signer.publicKeyJwk);
    expect(result.conflicts).toContain('shared');
  });
});
