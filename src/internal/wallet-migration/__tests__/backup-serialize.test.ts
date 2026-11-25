/**
 * シリアライズ（CBOR / JWE Compact）のラウンドトリップ・改ざん検知テスト。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import {
  exportBackup,
  exportBackupAsJweCompact,
  importBackup,
  importBackupFromJweCompact,
} from '../backup.js';
import {
  deserializeBackupFromCbor,
  deserializeBackupFromJweCompact,
  serializeBackupToCbor,
} from '../backup-serialize.js';
import type { BackupSource, ExportOptions } from '../types.js';
import { RECIPIENT_PRIVATE_KEY, testPublicKeyJwk, testSigner } from './fixtures.js';

const PASSPHRASE = 'correct-horse-battery';

const SOURCE: BackupSource = {
  walletId: 'urn:uuid:wallet-1',
  walletProvider: 'vericerts',
  credentials: [
    { id: 'vc-1', format: 'dc+sd-jwt', data: 'eyJ...vc1' },
    { id: 'vc-2', format: 'mso_mdoc', data: 'base64-mdoc-2' },
  ],
  personas: [{ id: 'persona-0', data: JSON.stringify({ index: 0 }) }],
  dids: [{ id: 'did:key:zAbc', data: JSON.stringify({ did: 'did:key:zAbc' }) }],
  settings: JSON.stringify({ locale: 'ja' }),
};

/** テスト高速化のため PBKDF2 反復回数を下げる（暗号設計は同一）。 */
const PBKDF2_OPTS: ExportOptions = { passphrase: PASSPHRASE, iterations: 1000 };
const HKDF_OPTS: ExportOptions = {
  passphrase: PASSPHRASE,
  recipientKey: testPublicKeyJwk(RECIPIENT_PRIVATE_KEY),
};

describe('serializeBackupToCbor / deserializeBackupFromCbor', () => {
  it.each([
    ['PBKDF2-SHA-256', PBKDF2_OPTS, undefined],
    ['HKDF-SHA-256', HKDF_OPTS, RECIPIENT_PRIVATE_KEY],
  ])('roundtrips a %s container through CBOR', async (_label, opts, recipientPrivateKey) => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, opts);

    const restored = deserializeBackupFromCbor(serializeBackupToCbor(backup));
    expect(restored).toEqual(backup);

    // 署名検証を含め、そのまま importBackup に通せること。
    const result = await importBackup(
      restored,
      PASSPHRASE,
      signer.publicKeyJwk,
      recipientPrivateKey,
    );
    expect(result.summary.vcCount).toBe(2);
    expect(result.credentials.find((c) => c.id === 'vc-1')?.data).toBe('eyJ...vc1');
    expect(result.settings).toBe(JSON.stringify({ locale: 'ja' }));
  });

  it('strips Object.prototype from the decoded container', async () => {
    const backup = await exportBackup(SOURCE, testSigner(), PBKDF2_OPTS);
    const restored = deserializeBackupFromCbor(serializeBackupToCbor(backup));
    expect(Object.getPrototypeOf(restored)).toBeNull();
    expect(Object.getPrototypeOf(restored.encryption)).toBeNull();
  });

  it.each([
    ['CBOR ではないバイト列', new Uint8Array([0xff, 0xff, 0xff, 0xff])],
    ['WalletBackup の形ではない', serializeBackupToCbor({ hello: 'world' } as never)],
  ])('rejects malformed CBOR input (%s, 4033)', (_label, bytes) => {
    expect(() => deserializeBackupFromCbor(bytes)).toThrow(
      expect.objectContaining({ code: '4033' }),
    );
  });
});

describe('exportBackupAsJweCompact / importBackupFromJweCompact', () => {
  it.each([
    ['PBKDF2-SHA-256', PBKDF2_OPTS, undefined],
    ['HKDF-SHA-256', HKDF_OPTS, RECIPIENT_PRIVATE_KEY],
  ])('roundtrips a %s container through JWE Compact', async (_label, opts, recipientPrivateKey) => {
    const signer = testSigner();
    const jwe = await exportBackupAsJweCompact(SOURCE, signer, opts);

    const segments = jwe.split('.');
    expect(segments).toHaveLength(5);
    // `alg: "dir"` では encrypted key セグメントは空（RFC 7516 §5.1）。
    expect(segments[1]).toBe('');
    const header = JSON.parse(
      new TextDecoder().decode(base64urlnopad.decode(segments[0] ?? '')),
    ) as Record<string, unknown>;
    expect(header.alg).toBe('dir');
    expect(header.enc).toBe('A256GCM');
    expect(header.kdf).toBe(opts.recipientKey !== undefined ? 'HKDF-SHA-256' : 'PBKDF2-SHA-256');

    const result = await importBackupFromJweCompact(
      jwe,
      PASSPHRASE,
      signer.publicKeyJwk,
      recipientPrivateKey,
    );
    expect(result.summary).toEqual({ vcCount: 2, personaCount: 1, didCount: 1 });
    expect(result.credentials.find((c) => c.id === 'vc-2')?.data).toBe('base64-mdoc-2');
    expect(result.settings).toBe(JSON.stringify({ locale: 'ja' }));
  });

  it('uses a fresh IV for every serialization of the same export', async () => {
    const signer = testSigner();
    const first = await exportBackupAsJweCompact(SOURCE, signer, PBKDF2_OPTS);
    const second = await exportBackupAsJweCompact(SOURCE, signer, PBKDF2_OPTS);
    expect(first.split('.')[2]).not.toBe(second.split('.')[2]);
  });

  // JWE 経路でも recipientKey 保護コンテナはパスフレーズだけでは開けない。
  it('fails without the recipient private key on an HKDF container (4032)', async () => {
    const signer = testSigner();
    const jwe = await exportBackupAsJweCompact(SOURCE, signer, HKDF_OPTS);
    const promise = importBackupFromJweCompact(jwe, PASSPHRASE, signer.publicKeyJwk);
    await expect(promise).rejects.toMatchObject({ code: '4032' });
  });

  it('fails with 4032 when a ciphertext byte is flipped', async () => {
    const signer = testSigner();
    const jwe = await exportBackupAsJweCompact(SOURCE, signer, PBKDF2_OPTS);
    const segments = jwe.split('.');
    const ciphertext = segments[3] ?? '';
    // base64url として妥当なまま 1 文字だけ差し替える（形式不正 4033 と区別するため）。
    segments[3] = (ciphertext[0] === 'A' ? 'B' : 'A') + ciphertext.slice(1);
    const promise = importBackupFromJweCompact(segments.join('.'), PASSPHRASE, signer.publicKeyJwk);
    await expect(promise).rejects.toMatchObject({ code: '4032' });
  });

  it.each([
    ['セグメント数が 5 でない', 'a.b.c'],
    ['protected header が base64url でない', '!!!..a.b.c'],
  ])('rejects a malformed JWE Compact string (%s, 4033)', async (_label, jwe) => {
    const promise = importBackupFromJweCompact(jwe, PASSPHRASE, testPublicKeyJwk());
    await expect(promise).rejects.toMatchObject({ code: '4033' });
  });

  it('fails with 4032 when deserialized with the wrong key', async () => {
    const signer = testSigner();
    const jwe = await exportBackupAsJweCompact(SOURCE, signer, PBKDF2_OPTS);
    const promise = deserializeBackupFromJweCompact(jwe, new Uint8Array(32));
    await expect(promise).rejects.toMatchObject({ code: '4032' });
  });
});

/** 正常系の protected header（`jweWithHeader` で 1 項目だけ差し替えて使う）。 */
const VALID_HEADER = {
  alg: 'dir',
  enc: 'A256GCM',
  kdf: 'PBKDF2-SHA-256',
  kdfParams: { iterations: 1000, salt: base64urlnopad.encode(new Uint8Array(32)) },
};

/**
 * 任意の protected header を持つ JWE Compact 文字列を作る。
 *
 * 本文（iv / ciphertext / tag）は中身こそダミーだが、**base64url として妥当な長さ**にする。
 * 形式不正で早期に 4033 になってしまうとヘッダ検査のテストがトートロジーになるためで、
 * ヘッダを通過した場合は GCM タグ検証の 4032 に落ちる。
 */
function jweWithHeader(header: Record<string, unknown>): string {
  const protectedSegment = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(header)));
  return [
    protectedSegment,
    '',
    base64urlnopad.encode(new Uint8Array(12)),
    base64urlnopad.encode(new Uint8Array(32)),
    base64urlnopad.encode(new Uint8Array(16)),
  ].join('.');
}

describe('readJweProtectedEncryption (署名検証前に読まれるヘッダの検査)', () => {
  // protected header は署名で保護されないため、`iterations` は攻撃者が選べる。上限がないと
  // 巨大値で呼び出し側スレッドを占有できてしまう（DoS）。
  it.each([
    ['上限超過', 30_000_000],
    ['ゼロ', 0],
    ['負の値', -1],
    ['非整数', 1.5],
    ['文字列', '1000'],
    // `null` は「未指定」ではない。既定値へフォールバックせず壊れたコンテナとして弾く。
    ['null', null],
  ])('rejects a hostile kdfParams.iterations (%s, 4033)', async (_label, iterations) => {
    const jwe = jweWithHeader({
      ...VALID_HEADER,
      kdfParams: { ...VALID_HEADER.kdfParams, iterations },
    });
    const startedAt = performance.now();
    const promise = importBackupFromJweCompact(jwe, PASSPHRASE, testPublicKeyJwk());
    await expect(promise).rejects.toMatchObject({ code: '4033' });
    // 上限超過の値をそのまま PBKDF2 に渡していれば数十秒かかる（= fail-fast の回帰検知）。
    expect(performance.now() - startedAt).toBeLessThan(2000);
  });

  // RFC 7516 §4.1.1 / §4.1.2: 未対応の `alg` / `enc` は解釈せず拒否する（4032 に化けさせない）。
  it.each([
    ['alg が dir でない', { alg: 'ECDH-ES' }],
    ['alg 欠落', { alg: undefined }],
    ['enc が A256GCM でない', { enc: 'A128CBC-HS256' }],
    ['enc 欠落', { enc: undefined }],
  ])('rejects an unsupported JWE alg/enc (%s, 4033)', async (_label, override) => {
    const promise = importBackupFromJweCompact(
      jweWithHeader({ ...VALID_HEADER, ...override }),
      PASSPHRASE,
      testPublicKeyJwk(),
    );
    await expect(promise).rejects.toMatchObject({ code: '4033' });
  });
});
