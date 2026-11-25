/**
 * 別ベンダーコンテナ取り込みの `Object.prototype` 汚染耐性。
 *
 * 本経路のコンテナは**本 SDK 自身の署名付きコンテナより信頼度が低い外部入力**で、キーは攻撃者が
 * 自由に選べる。検証内容:
 *
 * - `__proto__` / `constructor` を含むコンテナで `Object.prototype` を汚染できない
 *   （`parseJsonWithoutPrototype` によるパース境界での遮断）。
 * - 既に `Object.prototype` が汚染された環境でも、汚染値を「コンテナに入っていた値」として
 *   拾わない（`ownProperty` による own 限定読み）。
 * - DI（`JSON.parse` を通らないため上記が効かない）の `resolveIssuerKey` も汚染値を拾わない。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import type { PublicKeyJwk } from '../../../identity/did.js';
import type { ImportForeignBackupDependencies } from '../import-foreign.js';
import { importForeignBackup } from '../import-foreign.js';
import {
  containerJson,
  ISSUER_JWK,
  issueSdJwt,
  OTHER_ISSUER_JWK,
  RESOLVE_ISSUER_KEY,
} from './fixtures.js';

/** テストで生やした `Object.prototype` のプロパティ名（後始末用）。 */
const POLLUTED_KEYS = ['polluted', 'credentials', 'format', 'data', 'id', 'resolveIssuerKey'];

describe('importForeignBackup の Object.prototype 汚染耐性', () => {
  afterEach(() => {
    for (const key of POLLUTED_KEYS) {
      delete (Object.prototype as Record<string, unknown>)[key];
    }
  });

  it.each([
    '__proto__',
    'constructor',
  ])('%s キーを含むコンテナで Object.prototype を汚染できない', async (key) => {
    const json = `{"${key}":{"polluted":true},"credentials":[]}`;

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(result.summary.vcCount).toBe(0);
  });

  it('エントリ内の __proto__ キーでも汚染されず、正当なエントリは復元される', async () => {
    const sdJwt = issueSdJwt();
    const json = `{"credentials":[{"__proto__":{"polluted":true},"format":"dc+sd-jwt","data":${JSON.stringify(sdJwt)},"id":"vc-1"}]}`;

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(result.credentials).toEqual([{ id: 'vc-1', format: 'dc+sd-jwt', data: sdJwt }]);
  });

  it('汚染された credentials を「コンテナに入っていた」と見なさない（4036 のまま）', async () => {
    (Object.prototype as Record<string, unknown>).credentials = [
      { format: 'dc+sd-jwt', data: issueSdJwt(), id: 'injected' },
    ];

    await expect(importForeignBackup('{}', RESOLVE_ISSUER_KEY)).rejects.toMatchObject({
      code: '4036',
    });
  });

  it('汚染された format / data でエントリの欠落を埋めない（4036 のまま）', async () => {
    // SD-JWT の発行は汚染前に済ませる（@noble の署名オプションも鎖読みするため、汚染下では
    // 被検体ではなくフィクスチャ生成側が落ちてテストが意味を失う）。
    const sdJwt = issueSdJwt();
    (Object.prototype as Record<string, unknown>).format = 'dc+sd-jwt';
    (Object.prototype as Record<string, unknown>).data = sdJwt;

    const promise = importForeignBackup('{"credentials":[{}]}', RESOLVE_ISSUER_KEY);

    await expect(promise).rejects.toMatchObject({ code: '4036' });
  });

  it('汚染された id を復元エントリの ID に採用しない', async () => {
    const json = containerJson([{ format: 'dc+sd-jwt', data: issueSdJwt() }]);
    (Object.prototype as Record<string, unknown>).id = 'attacker-chosen-id';

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(result.credentials[0]?.id).toBe('foreign-vc-0');
  });

  it('汚染された resolveIssuerKey を注入済み DI と見なさない（4033）', async () => {
    (Object.prototype as Record<string, unknown>).resolveIssuerKey = (): PublicKeyJwk =>
      OTHER_ISSUER_JWK;
    const json = containerJson([{ format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-1' }]);

    const promise = importForeignBackup(json, {} as ImportForeignBackupDependencies);

    await expect(promise).rejects.toMatchObject({ code: '4033' });
  });

  it('プロトタイプメソッドとして実装された正当な解決器は受理する', async () => {
    class TrustList {
      resolveIssuerKey(): PublicKeyJwk {
        return ISSUER_JWK;
      }
    }
    const json = containerJson([{ format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-1' }]);

    const result = await importForeignBackup(json, new TrustList());

    expect(result.summary.vcCount).toBe(1);
  });
});
