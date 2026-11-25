/**
 * did:plc の公開（`submitPlcOperation`）。公開先の制約と送信前の検査を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { submitPlcOperation } from '../lifecycle.js';
import { DIRECTORY, expectVericertsError, genesis, makeKey } from './plc.fixtures.js';

describe('submitPlcOperation', () => {
  const capture = () => {
    const calls: { url: string; init: RequestInit | undefined }[] = [];
    const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      return new Response('', { status: 200 });
    }) as unknown as typeof fetch;
    return { calls, fetchFn };
  };

  it('POST <directoryUrl>/<did> へ JSON で署名済み操作を送る', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const { calls, fetchFn } = capture();
    await submitPlcOperation(g.did, g.operation, { fetchFn });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(`${DIRECTORY}/${g.did}`);
    expect(calls[0]?.init?.method).toBe('POST');
    expect(calls[0]?.init?.redirect).toBe('manual');
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual(g.operation);
  });

  it('directoryUrl を指定でき、末尾スラッシュは除く', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const { calls, fetchFn } = capture();
    await submitPlcOperation(g.did, g.operation, {
      fetchFn,
      directoryUrl: 'https://plc.example.org/',
    });
    expect(calls[0]?.url).toBe(`https://plc.example.org/${g.did}`);
  });

  it('http: や非公開ホストの directoryUrl は送信せず 2003', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const { calls, fetchFn } = capture();
    for (const directoryUrl of [
      'http://plc.example.org',
      'https://127.0.0.1',
      'https://u:p@plc.example.org',
      'nope',
    ]) {
      await expectVericertsError(
        () => submitPlcOperation(g.did, g.operation, { fetchFn, directoryUrl }),
        ErrorCodes.DID_NOT_FOUND,
        'insecure_directory_url',
      );
    }
    expect(calls).toHaveLength(0);
  });

  it('ジェネシスの DID が再計算と一致しなければ送信せず 2001', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const { calls, fetchFn } = capture();
    await expectVericertsError(
      () => submitPlcOperation('did:plc:aaaaaaaaaaaaaaaaaaaaaaaa', g.operation, { fetchFn }),
      ErrorCodes.INVALID_DID,
    );
    await expectVericertsError(
      () => submitPlcOperation('did:plc:UPPER', g.operation, { fetchFn }),
      ErrorCodes.INVALID_DID,
    );
    expect(calls).toHaveLength(0);
  });

  it('構造不正の操作は送信せず 2001', async () => {
    const { calls, fetchFn } = capture();
    await expectVericertsError(
      () =>
        submitPlcOperation(
          'did:plc:ewvi7nxzyoun6zhxrhs64oiz',
          { type: 'plc_operation', prev: null, sig: 'x' } as never,
          {
            fetchFn,
          },
        ),
      ErrorCodes.INVALID_DID,
    );
    expect(calls).toHaveLength(0);
  });

  it('非 2xx・ネットワークエラー・リダイレクトは 2003（plc_submit_failed / insecure_directory_url）', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const reply = (response: Response | Error) =>
      (async () => {
        if (response instanceof Error) {
          throw response;
        }
        return response;
      }) as unknown as typeof fetch;
    await expectVericertsError(
      () =>
        submitPlcOperation(g.did, g.operation, {
          fetchFn: reply(new Response('bad', { status: 400 })),
        }),
      ErrorCodes.DID_NOT_FOUND,
      'plc_submit_failed',
    );
    await expectVericertsError(
      () => submitPlcOperation(g.did, g.operation, { fetchFn: reply(new Error('down')) }),
      ErrorCodes.DID_NOT_FOUND,
      'plc_submit_failed',
    );
    await expectVericertsError(
      () =>
        submitPlcOperation(g.did, g.operation, {
          fetchFn: reply(
            new Response('', { status: 302, headers: { location: 'https://evil.example/' } }),
          ),
        }),
      ErrorCodes.DID_NOT_FOUND,
      'insecure_directory_url',
    );
  });
});
