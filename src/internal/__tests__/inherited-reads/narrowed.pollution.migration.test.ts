/**
 * wallet-migration のバックアップ検証と did:webvh 更新の継続性ガードが、必須宣言のプロパティを省略した入力に対して
 * `Object.prototype` 汚染前後で結果を変えないことの回帰テスト。他の箇所は `narrowed.pollution.test.ts`。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { generateKey, signEntry } from '../../identity/webvh/__tests__/webvh-fixtures.js';
import { createDidWebVh, updateDidWebVh } from '../../identity/webvh/method-webvh.js';
import { importBackup } from '../../wallet-migration/backup.js';
import { deriveContainerKey } from '../../wallet-migration/backup-container-key.js';
import { decryptEntry } from '../../wallet-migration/backup-entry.js';
import { verifyIntegrity } from '../../wallet-migration/backup-integrity.js';
import type {
  EncryptedEntry,
  EncryptionHeader,
  WalletBackup,
} from '../../wallet-migration/types.js';
import {
  withPollutedPrototype,
  withPollutedPrototypeAsync,
} from '../prototype-pollution.fixtures.js';

function outcome(fn: () => unknown): string {
  try {
    return `ok:${JSON.stringify(fn())}`;
  } catch (error) {
    return `err:${(error as { code?: unknown }).code ?? (error as Error).name}`;
  }
}

describe('wallet-migration のバックアップ検証は汚染値で分岐しない', () => {
  const jwk = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } as PublicKeyJwk;

  it('verifyIntegrity: integrity を省略した backup は汚染 integrity で検証に進まない', () => {
    const backup = { version: '1.0' } as unknown as WalletBackup;
    expect(verifyIntegrity(backup, jwk)).toBe(false);
    expect(
      withPollutedPrototype({ integrity: { alg: 'ES256', signature: 'AAAA' } }, () =>
        verifyIntegrity(backup, jwk),
      ),
    ).toBe(false);
  });

  it('importBackup: version を省略した backup は汚染 version で受理に進まない', async () => {
    const backup = {} as unknown as WalletBackup;
    const attempt = async (): Promise<string> =>
      importBackup(backup, 'pass', jwk).then(
        () => 'ok',
        (error: { code?: unknown }) => `err:${String(error.code)}`,
      );
    const clean = await attempt();
    expect(clean).toBe(`err:${ErrorCodes.W2W_INCOMPATIBLE_VERSION}`);
    expect(await withPollutedPrototypeAsync({ version: '1.0' }, attempt)).toBe(clean);
  });

  it('deriveContainerKey: kdfParams を省略したヘッダは汚染 kdfParams で鍵導出しない', async () => {
    const header = {} as unknown as EncryptionHeader;
    const attempt = (): Promise<string> =>
      deriveContainerKey(header, 'pass').then(
        () => 'ok',
        (error: { code?: unknown }) => `err:${String(error.code)}`,
      );
    const clean = await attempt();
    expect(clean.startsWith('err:')).toBe(true);
    expect(
      await withPollutedPrototypeAsync(
        { kdf: 'PBKDF2-SHA-256', kdfParams: { salt: 'AAAA', iterations: 1 } },
        attempt,
      ),
    ).toBe(clean);
  });

  it('decryptEntry: iv / ciphertext / id / kind を省略したエントリは汚染値で復号に進まない', async () => {
    const entry = {} as unknown as EncryptedEntry;
    const attempt = (): Promise<string> =>
      decryptEntry(new Uint8Array(32), entry).then(
        () => 'ok',
        (error: { code?: unknown }) => `err:${String(error.code)}`,
      );
    const clean = await attempt();
    expect(clean).toBe(`err:${ErrorCodes.W2W_PASSPHRASE_WRONG}`);
    expect(
      await withPollutedPrototypeAsync(
        {
          iv: 'AAAAAAAAAAAAAAAA',
          ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          id: 'x',
          kind: 'credential',
        },
        attempt,
      ),
    ).toBe(clean);
  });
});

describe('did:webvh 更新の継続性ガードは汚染 id を採用しない', () => {
  it('state が id を省略したとき、汚染 id が前版と一致しても更新を受理しない', () => {
    const key = generateKey();
    const { did, logEntry } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
    });
    const attempt = (): unknown =>
      updateDidWebVh({
        previousLog: [signEntry(logEntry, key)],
        state: {
          '@context': ['https://www.w3.org/ns/did/v1'],
          verificationMethod: [],
          authentication: [],
          assertionMethod: [],
        } as never,
      });
    expect(outcome(attempt).startsWith('err:')).toBe(true);
    expect(withPollutedPrototype({ id: did }, () => outcome(attempt))).toBe(outcome(attempt));
  });
});
