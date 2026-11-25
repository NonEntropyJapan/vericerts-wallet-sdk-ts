/**
 * 共通取得層（`fetchResolverJson`）の本文上限超過は `2003` + `reason: oversized_body`。
 */

import { describe, it } from 'bun:test';
import { ErrorCodes } from '../../errors.js';
import { MAX_DOCUMENT_BYTES, OVERSIZED_BODY_REASON } from '../../http/body-limit.js';
import { fetchResolverJson } from '../network/http-resolver.js';
import { expectRejects } from './network-method.fixtures.js';

function request(headers: Record<string, string>) {
  const body = JSON.stringify({ pad: 'x'.repeat(MAX_DOCUMENT_BYTES) });
  const fetchFn = (async () =>
    new Response(body, {
      status: 200,
      headers: { 'content-type': 'application/json', ...headers },
    })) as unknown as typeof fetch;
  return fetchResolverJson({
    url: 'https://node.example.org/x',
    accept: 'application/json',
    contentTypes: ['application/json'],
    fetchFn,
  });
}

describe('fetchResolverJson の本文上限超過', () => {
  it('content-length の自己申告が上限超過なら 2003（oversized_body）', async () => {
    await expectRejects(
      request({ 'content-length': String(MAX_DOCUMENT_BYTES + 1) }),
      ErrorCodes.DID_NOT_FOUND,
      OVERSIZED_BODY_REASON,
    );
  });

  it('content-length が無くても実バイト数で打ち切り 2003（oversized_body）', async () => {
    await expectRejects(request({}), ErrorCodes.DID_NOT_FOUND, OVERSIZED_BODY_REASON);
  });
});
