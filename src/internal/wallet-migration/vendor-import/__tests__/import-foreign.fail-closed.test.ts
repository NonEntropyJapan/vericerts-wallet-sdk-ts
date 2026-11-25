/**
 * 別ベンダーコンテナ取り込みの fail-closed 挙動。
 *
 * 検証内容:
 * - 準拠フォーマットを名乗るエントリの暗号検証失敗は**全体拒否（4033）**であり、警告付き
 *   スキップ（部分インポート）にはならない。
 * - 発行者鍵の解決器が失敗した場合も同じく全体拒否。
 * - 解決器の未注入も fail-closed（検証を黙って省かない）。
 *
 * 「reject すること」だけでなく「部分結果を返さないこと」を明示的に確認する。署名検証失敗を
 * スキップ扱いにする実装は前者では落ちず後者で落ちるため。
 */

import { describe, expect, it } from 'bun:test';
import type { PublicKeyJwk } from '../../../identity/did.js';
import type { ImportForeignBackupDependencies } from '../import-foreign.js';
import { importForeignBackup } from '../import-foreign.js';
import {
  containerJson,
  issueSdJwt,
  OTHER_ISSUER_JWK,
  RESOLVE_ISSUER_KEY,
  tamperDisclosure,
} from './fixtures.js';

describe('importForeignBackup の暗号検証失敗（全体拒否）', () => {
  it('Disclosure を改竄したエントリがあるとコンテナ全体を 4033 で拒否する', async () => {
    const json = containerJson([
      { format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-1' },
      { format: 'dc+sd-jwt', data: tamperDisclosure(issueSdJwt()), id: 'vc-2' },
      { format: 'vc+sd-jwt', data: issueSdJwt(), id: 'vc-3' },
    ]);

    const promise = importForeignBackup(json, RESOLVE_ISSUER_KEY);

    // resolve して「vc-2 だけ warnings に載った部分結果」を返す実装ではここで落ちる。
    await expect(promise).rejects.toMatchObject({ code: '4033' });
  });

  it('別鍵で検証すると（署名不一致）全体を 4033 で拒否する', async () => {
    const json = containerJson([{ format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-1' }]);
    const deps: ImportForeignBackupDependencies = {
      resolveIssuerKey: (): PublicKeyJwk => OTHER_ISSUER_JWK,
    };

    await expect(importForeignBackup(json, deps)).rejects.toMatchObject({ code: '4033' });
  });

  it('検証失敗時は他エントリを含む部分結果を一切返さない', async () => {
    const json = containerJson([
      { format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-1' },
      { format: 'jwt_vc_json', data: 'a.b.c', id: 'vc-2' },
      { format: 'dc+sd-jwt', data: tamperDisclosure(issueSdJwt()), id: 'vc-3' },
    ]);

    let resolved: unknown;
    try {
      resolved = await importForeignBackup(json, RESOLVE_ISSUER_KEY);
    } catch (error) {
      expect(error).toMatchObject({ code: '4033' });
    }
    expect(resolved).toBeUndefined();
  });

  it('例外にクレーム値・VC 本文を含めない', async () => {
    const tampered = tamperDisclosure(issueSdJwt());
    const json = containerJson([{ format: 'dc+sd-jwt', data: tampered, id: 'vc-1' }]);

    const error = await importForeignBackup(json, RESOLVE_ISSUER_KEY).catch((e: unknown) => e);

    const serialized = JSON.stringify({
      message: (error as Error).message,
      rest: error,
    });
    expect(serialized).not.toContain(tampered);
    expect(serialized).not.toContain('Mallory');
  });
});

describe('importForeignBackup の発行者鍵解決失敗（全体拒否）', () => {
  it('resolveIssuerKey が throw したら 4033 で全体拒否する', async () => {
    const json = containerJson([
      { format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-1' },
      { format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-2' },
    ]);
    const deps: ImportForeignBackupDependencies = {
      resolveIssuerKey: (entry): PublicKeyJwk => {
        throw new Error(`no trust anchor for ${entry.format}`);
      },
    };

    await expect(importForeignBackup(json, deps)).rejects.toMatchObject({ code: '4033' });
  });

  it('resolveIssuerKey が reject したら 4033 で全体拒否する', async () => {
    const json = containerJson([{ format: 'vc+sd-jwt', data: issueSdJwt(), id: 'vc-1' }]);
    const deps: ImportForeignBackupDependencies = {
      resolveIssuerKey: (): Promise<PublicKeyJwk> => Promise.reject(new Error('lookup failed')),
    };

    await expect(importForeignBackup(json, deps)).rejects.toMatchObject({ code: '4033' });
  });

  it('resolveIssuerKey 未注入は「全件スキップ + 警告」ではなく 4033 で拒否する', async () => {
    const json = containerJson([{ format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-1' }]);

    const promise = importForeignBackup(json, {} as ImportForeignBackupDependencies);

    await expect(promise).rejects.toMatchObject({ code: '4033' });
  });
});
