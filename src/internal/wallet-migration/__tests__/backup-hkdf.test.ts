/**
 * `recipientKey` 指定時の ECDH-ES + HKDF-SHA-256 経路のテスト。
 *
 * EncryptionHeader の kdf と recipientKey を検査する。
 *
 * 修正前は `recipientKey` がヘッダに記録されるだけの不活性なメタデータで、本文鍵は常に
 * パスフレーズ由来の PBKDF2 だった（= 受信者秘密鍵を持たなくてもパスフレーズだけで復号できた）。
 * 「パスフレーズのみでは開けない」ことを固定するのが本ファイルの主目的である。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { exportBackup, importBackup } from '../backup.js';
import { backupDigest } from '../backup-integrity.js';
import type { BackupSigner, BackupSource, ExportOptions, WalletBackup } from '../types.js';
import {
  OTHER_RECIPIENT_PRIVATE_KEY,
  RECIPIENT_PRIVATE_KEY,
  testPublicKeyJwk,
  testSigner,
} from './fixtures.js';

const PASSPHRASE = 'correct-horse-battery';

const SOURCE: BackupSource = {
  walletId: 'urn:uuid:wallet-1',
  credentials: [{ id: 'vc-1', format: 'dc+sd-jwt', data: 'eyJ...vc1' }],
  personas: [{ id: 'persona-0', data: JSON.stringify({ index: 0 }) }],
  dids: [{ id: 'did:key:zAbc', data: JSON.stringify({ did: 'did:key:zAbc' }) }],
  settings: JSON.stringify({ locale: 'ja' }),
};

/** 受信者の公開鍵 JWK（`ExportOptions.recipientKey`）。 */
const RECIPIENT_JWK = testPublicKeyJwk(RECIPIENT_PRIVATE_KEY);

const HKDF_OPTS: ExportOptions = { passphrase: PASSPHRASE, recipientKey: RECIPIENT_JWK };

/**
 * ヘッダを差し替えたコンテナに署名し直す。
 *
 * 署名検証（4033）は鍵導出より前に走るため、再署名しないと `kdfParams` 由来の失敗を検証できず
 * テストがトートロジーになる。
 */
function resign(backup: WalletBackup, signer: BackupSigner): WalletBackup {
  const { integrity: _integrity, ...unsigned } = backup;
  return {
    ...unsigned,
    integrity: {
      alg: 'ES256',
      signature: base64urlnopad.encode(signer.sign(backupDigest(unsigned))),
      signerKeyId: signer.keyId,
    },
  };
}

describe('exportBackup / importBackup with recipientKey (HKDF-SHA-256)', () => {
  it('switches the header to HKDF-SHA-256 with an epk and no PBKDF2 iterations', async () => {
    const backup = await exportBackup(SOURCE, testSigner(), HKDF_OPTS);
    expect(backup.encryption.kdf).toBe('HKDF-SHA-256');
    expect(backup.encryption.kdfParams.epk).toBeDefined();
    expect(backup.encryption.kdfParams.epk?.crv).toBe('P-256');
    expect(backup.encryption.kdfParams.iterations).toBeUndefined();
    expect(backup.encryption.recipientKey).toEqual(RECIPIENT_JWK);
    // 本文鍵はパスフレーズ由来ではない。
    expect(backup.encryption.passphraseProtected).toBe(false);
  });

  it('generates a fresh ephemeral key per export (no ECDH-ES key reuse)', async () => {
    const signer = testSigner();
    const first = await exportBackup(SOURCE, signer, HKDF_OPTS);
    const second = await exportBackup(SOURCE, signer, HKDF_OPTS);
    expect(first.encryption.kdfParams.epk?.x).not.toBe(second.encryption.kdfParams.epk?.x);
  });

  it('restores all entries with the matching recipient private key', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, HKDF_OPTS);
    const result = await importBackup(
      backup,
      PASSPHRASE,
      signer.publicKeyJwk,
      RECIPIENT_PRIVATE_KEY,
    );

    expect(result.summary).toEqual({ vcCount: 1, personaCount: 1, didCount: 1 });
    expect(result.credentials[0]?.data).toBe('eyJ...vc1');
    expect(result.credentials[0]?.format).toBe('dc+sd-jwt');
    expect(result.personas[0]?.data).toBe(JSON.stringify({ index: 0 }));
    expect(result.dids[0]?.data).toBe(JSON.stringify({ did: 'did:key:zAbc' }));
    expect(result.settings).toBe(JSON.stringify({ locale: 'ja' }));
  });

  // 以前は recipientKey が不活性だったためこの呼び出しが成功していた。
  it('fails with the correct passphrase but no recipient private key (4032)', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, HKDF_OPTS);
    const promise = importBackup(backup, PASSPHRASE, signer.publicKeyJwk);
    await expect(promise).rejects.toMatchObject({ code: '4032' });
  });

  it('fails with a different recipient private key (4032)', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, HKDF_OPTS);
    const promise = importBackup(
      backup,
      PASSPHRASE,
      signer.publicKeyJwk,
      OTHER_RECIPIENT_PRIVATE_KEY,
    );
    await expect(promise).rejects.toMatchObject({ code: '4032' });
  });

  // 「壊れたコンテナ」は 4033 に正規化する。オブジェクト形状の `epk` は `typeof` ガードを
  // 通過して ECDH に届くため、鍵合意層の 1050 が公開 API から漏れないことまで固定する。
  it.each([
    ['epk 欠落', undefined],
    ['epk が文字列', 'not-a-jwk'],
    ['epk が空オブジェクト', {}],
    ['epk の crv が非対応', { ...RECIPIENT_JWK, crv: 'P-521' }],
    ['epk が曲線上にない点', { ...RECIPIENT_JWK, x: base64urlnopad.encode(new Uint8Array(32)) }],
    ['epk.x が base64url でない', { ...RECIPIENT_JWK, x: '!!!' }],
  ])('fails when kdfParams.epk is malformed (%s, 4033)', async (_label, epk) => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, HKDF_OPTS);
    const broken = resign(
      {
        ...backup,
        encryption: {
          ...backup.encryption,
          kdfParams: {
            salt: backup.encryption.kdfParams.salt,
            ...(epk !== undefined ? { epk: epk as unknown as never } : {}),
          },
        },
      },
      signer,
    );
    const promise = importBackup(broken, PASSPHRASE, signer.publicKeyJwk, RECIPIENT_PRIVATE_KEY);
    await expect(promise).rejects.toMatchObject({ code: '4033' });
  });

  it('rejects an unknown kdf instead of falling back to PBKDF2 (4033)', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, { passphrase: PASSPHRASE, iterations: 1000 });
    const broken = resign(
      {
        ...backup,
        encryption: { ...backup.encryption, kdf: 'MD5' as unknown as never },
      },
      signer,
    );
    const promise = importBackup(broken, PASSPHRASE, signer.publicKeyJwk);
    await expect(promise).rejects.toMatchObject({ code: '4033' });
  });

  it('still enforces the passphrase policy when recipientKey is given (4032)', async () => {
    const promise = exportBackup(SOURCE, testSigner(), {
      passphrase: 'aaaaaaaaaa',
      recipientKey: RECIPIENT_JWK,
    });
    await expect(promise).rejects.toMatchObject({ code: '4032' });
  });

  it('rejects a malformed recipientKey at export time (1051)', async () => {
    const promise = exportBackup(SOURCE, testSigner(), {
      passphrase: PASSPHRASE,
      recipientKey: { ...RECIPIENT_JWK, x: '!!!' },
    });
    await expect(promise).rejects.toMatchObject({ code: '1051' });
  });
});
