/**
 * Credential Manifest の GET は、リダイレクトをホップごとに公開 HTTPS へ縛って追従する。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../auth/oid4vci/oid4vci.js';
import { ErrorCodes } from '../../../errors.js';
import { fetchCredentialManifest } from '../parse.js';

describe('fetchCredentialManifest のリダイレクト拘束', () => {
  it.each([
    'https://10.0.0.5/manifest.json',
    'https://169.254.169.254/latest',
    'http://issuer.example/manifest.json',
  ])('公開ホストから %s へ 302 されても 2 ホップ目の fetch を呼ばず 3034 で失敗する', async (location) => {
    const hops: Array<{ url: string; redirect: RequestRedirect | undefined }> = [];
    const fetchImpl: FetchLike = async (url, init) => {
      hops.push({ url, redirect: init.redirect });
      return new Response(null, { status: 302, headers: { Location: location } });
    };
    await expect(
      fetchCredentialManifest('https://issuer.example/manifest.json', { fetchImpl }),
    ).rejects.toMatchObject({ code: ErrorCodes.MANIFEST_FETCH_FAILED });
    expect(hops).toEqual([{ url: 'https://issuer.example/manifest.json', redirect: 'manual' }]);
  });

  it('追従されて最終 URL が内部ホストになった応答は採用しない', async () => {
    const fetchImpl: FetchLike = async () => {
      const response = new Response('{}', { status: 200 });
      Object.defineProperty(response, 'url', { value: 'https://10.0.0.5/manifest.json' });
      return response;
    };
    await expect(
      fetchCredentialManifest('https://issuer.example/manifest.json', { fetchImpl }),
    ).rejects.toMatchObject({ code: ErrorCodes.MANIFEST_FETCH_FAILED });
  });
});
