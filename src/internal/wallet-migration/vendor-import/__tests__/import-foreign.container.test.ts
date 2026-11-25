/**
 * 別ベンダーコンテナの形状検証。
 *
 * 受理プロファイル（`container.ts`）に合致しないコンテナは、部分インポートの対象にせず
 * 一律 4036（W2W_INCOMPATIBLE_VERSION）で拒否する。「未知の形状は既定値で救済」へ倒さない。
 */

import { describe, expect, it } from 'bun:test';
import { importForeignBackup } from '../import-foreign.js';
import { issueSdJwt, RESOLVE_ISSUER_KEY } from './fixtures.js';

/** 4036 で拒否されるべきコンテナ文字列（ケース名 → JSON 文字列）。 */
const MALFORMED: readonly (readonly [string, string])[] = [
  ['JSON として解析できない', 'not-json-at-all'],
  ['空文字列', ''],
  ['トップレベルがオブジェクトでない（配列）', '[]'],
  ['トップレベルがオブジェクトでない（文字列）', '"container"'],
  ['トップレベルが null', 'null'],
  ['credentials がない', '{"version":"1.0"}'],
  ['credentials が配列でない', '{"credentials":{"0":{"format":"dc+sd-jwt","data":"x"}}}'],
  ['credentials が null', '{"credentials":null}'],
  ['エントリがオブジェクトでない', '{"credentials":["dc+sd-jwt"]}'],
  ['エントリに data がない', '{"credentials":[{"format":"dc+sd-jwt"}]}'],
  ['エントリに format がない', '{"credentials":[{"data":"x"}]}'],
  ['format が文字列でない', '{"credentials":[{"format":42,"data":"x"}]}'],
  ['data が文字列でない', '{"credentials":[{"format":"dc+sd-jwt","data":{"jwt":"x"}}]}'],
  ['id が文字列でない', '{"credentials":[{"format":"dc+sd-jwt","data":"x","id":7}]}'],
];

describe('importForeignBackup のコンテナ形状検証（4036）', () => {
  it.each(MALFORMED)('%s コンテナを 4036 で拒否する', async (_name, json) => {
    await expect(importForeignBackup(json, RESOLVE_ISSUER_KEY)).rejects.toMatchObject({
      code: '4036',
    });
  });

  it('形状不正のエントリが 1 件でもあれば他の正当なエントリも復元しない', async () => {
    const json = JSON.stringify({
      credentials: [{ format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-1' }, { format: 'ldp_vc' }],
    });

    await expect(importForeignBackup(json, RESOLVE_ISSUER_KEY)).rejects.toMatchObject({
      code: '4036',
    });
  });

  it('credentials が空配列のコンテナは空の結果として受理する', async () => {
    const result = await importForeignBackup('{"credentials":[]}', RESOLVE_ISSUER_KEY);

    expect(result.summary).toEqual({ vcCount: 0, personaCount: 0, didCount: 0 });
    expect(result.credentials).toEqual([]);
    expect(result.warnings).toEqual([]);
  });

  it('プロファイル外の追加フィールドは無視して受理する', async () => {
    const json = JSON.stringify({
      version: 'vendor-x/2.1',
      exportedAt: '2026-09-17T00:00:00Z',
      credentials: [{ format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-1' }],
    });

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(result.summary.vcCount).toBe(1);
  });
});
