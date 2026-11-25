/**
 * 別ベンダーコンテナの取り込み（`importForeignBackup`）の受理・部分インポート挙動。
 *
 * 検証内容:
 * - 対応形式のコンテナ（`dc+sd-jwt` / `vc+sd-jwt`）は全件復元し警告ゼロ。
 * - 未対応フォーマットは**警告付きスキップ**で、残りは復元される（部分インポート）。
 * - `mso_mdoc` は「検証器未実装」であることを非準拠とは別文言で警告してスキップする。
 * - 警告文にクレーム値・VC 本文が漏れない。
 */

import { describe, expect, it } from 'bun:test';
import { importForeignBackup } from '../import-foreign.js';
import {
  containerJson,
  issueSdJwt,
  RESOLVE_ISSUER_KEY,
  SECRET_CLAIM_VALUE,
  SECRET_EMAIL,
} from './fixtures.js';

describe('importForeignBackup（対応形式のコンテナ）', () => {
  it('dc+sd-jwt / vc+sd-jwt を全件復元し警告も競合も出ない', async () => {
    const first = issueSdJwt();
    const second = issueSdJwt('https://example.com/credentials/diploma');
    const json = containerJson([
      { format: 'dc+sd-jwt', data: first, id: 'vendor-vc-1' },
      { format: 'vc+sd-jwt', data: second, id: 'vendor-vc-2' },
    ]);

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(result.warnings).toEqual([]);
    expect(result.conflicts).toEqual([]);
    expect(result.summary).toEqual({ vcCount: 2, personaCount: 0, didCount: 0 });
    expect(result.credentials).toEqual([
      { id: 'vendor-vc-1', format: 'dc+sd-jwt', data: first },
      { id: 'vendor-vc-2', format: 'vc+sd-jwt', data: second },
    ]);
  });

  it('Persona / DID / 設定は本プロファイルに含まれないため空で返る', async () => {
    const json = containerJson([{ format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-1' }]);

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(result.personas).toEqual([]);
    expect(result.dids).toEqual([]);
    expect(result.settings).toBeUndefined();
  });

  it('ベンダー ID 未指定のエントリには添字由来の ID を採番する', async () => {
    const sdJwt = issueSdJwt();
    const json = containerJson([
      { format: 'dc+sd-jwt', data: sdJwt, id: 'vendor-vc-1' },
      { format: 'dc+sd-jwt', data: sdJwt },
    ]);

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(result.credentials.map((c) => c.id)).toEqual(['vendor-vc-1', 'foreign-vc-1']);
  });

  it('復元後に ID が重複したら conflicts に載る（全体拒否にはしない）', async () => {
    const sdJwt = issueSdJwt();
    const json = containerJson([
      { format: 'dc+sd-jwt', data: sdJwt, id: 'dup' },
      { format: 'vc+sd-jwt', data: sdJwt, id: 'dup' },
    ]);

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(result.conflicts).toEqual(['dup']);
    expect(result.summary.vcCount).toBe(2);
  });
});

describe('importForeignBackup（未対応フォーマットの警告付き部分インポート）', () => {
  it('非準拠フォーマットだけをスキップし、準拠エントリは復元する', async () => {
    const first = issueSdJwt();
    const second = issueSdJwt('https://example.com/credentials/diploma');
    const json = containerJson([
      { format: 'dc+sd-jwt', data: first, id: 'vc-1' },
      { format: 'jwt_vc_json', data: 'eyJhbGciOiJFUzI1NiJ9.payload.sig', id: 'vc-2' },
      { format: 'vc+sd-jwt', data: second, id: 'vc-3' },
    ]);

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    // 「異常が 1 件でもあれば全体拒否」の実装だとここで reject するため落ちる。
    expect(result.credentials.map((c) => c.id)).toEqual(['vc-1', 'vc-3']);
    expect(result.summary.vcCount).toBe(2);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('jwt_vc_json');
    expect(result.warnings[0]).toContain('vc-2');
    expect(result.warnings[0]).not.toMatch(/\.md\b/);
  });

  it('ldp_vc など 未対応フォーマットは一律スキップする', async () => {
    const json = containerJson([
      { format: 'ldp_vc', data: '{"@context":[]}', id: 'vc-1' },
      { format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-2' },
    ]);

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(result.credentials.map((c) => c.id)).toEqual(['vc-2']);
    expect(result.warnings[0]).toContain('ldp_vc');
  });

  it('ID 未指定の非準拠エントリは添字で識別できる警告になる', async () => {
    const json = containerJson([
      { format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-0' },
      { format: 'jwt_vc_json', data: 'a.b.c' },
    ]);

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(result.warnings[0]).toContain('for entry #1: skipped');
  });
});

describe('importForeignBackup（mso_mdoc は検証器未実装としてスキップ）', () => {
  it('COSE 署名検証が未実装である旨を非準拠とは別文言で警告する', async () => {
    const json = containerJson([
      { format: 'dc+sd-jwt', data: issueSdJwt(), id: 'vc-1' },
      { format: 'mso_mdoc', data: 'omdkb2NUeXBl...', id: 'mdl-1' },
      { format: 'vc+sd-jwt', data: issueSdJwt(), id: 'vc-2' },
    ]);

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(result.credentials.map((c) => c.id)).toEqual(['vc-1', 'vc-2']);
    expect(result.warnings).toHaveLength(1);
    const warning = result.warnings[0] ?? '';
    expect(warning).toContain('mso_mdoc');
    expect(warning).toContain('mdl-1');
    // 「フォーマット非準拠」ではなく「本ビルドでは検証不能」であることが読み取れること。
    expect(warning).toContain('COSE');
    expect(warning).not.toContain('unsupported format');
  });

  it('非準拠フォーマットと mso_mdoc の警告文は区別できる', async () => {
    const json = containerJson([
      { format: 'mso_mdoc', data: 'omdkb2NUeXBl...', id: 'mdl-1' },
      { format: 'jwt_vc_json', data: 'a.b.c', id: 'vc-1' },
    ]);

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    expect(result.warnings[0]).not.toBe(result.warnings[1]);
    expect(result.warnings[1]).toContain('unsupported format');
    expect(result.warnings[1]).not.toContain('COSE');
  });
});

describe('importForeignBackup（警告文へのクレーム漏洩防止）', () => {
  it('警告文に VC 本文・クレーム値を含めない', async () => {
    const sdJwt = issueSdJwt();
    const json = containerJson([
      { format: 'mso_mdoc', data: 'SECRET-MDOC-BYTES', id: 'mdl-1' },
      { format: 'jwt_vc_json', data: sdJwt, id: 'vc-1' },
    ]);

    const result = await importForeignBackup(json, RESOLVE_ISSUER_KEY);

    for (const warning of result.warnings) {
      expect(warning).not.toContain(SECRET_CLAIM_VALUE);
      expect(warning).not.toContain(SECRET_EMAIL);
      expect(warning).not.toContain(sdJwt);
      expect(warning).not.toContain('SECRET-MDOC-BYTES');
    }
  });
});
