import { describe, expect, test } from 'bun:test';
import {
  MAX_LINKED_DIDS as ROOT_MAX_LINKED_DIDS,
  VericertsError as RootError,
} from '../../index.js';
import {
  ErrorCodes,
  type FetchLike,
  fetchWellKnownJson,
  isPublicHttpsUrl,
  parseJsonWithoutPrototype,
  VericertsError,
  type WellKnownJsonFailure,
} from '../common.js';
import { MAX_LINKED_DIDS } from '../identity.js';

const issuer = 'https://issuer.example';
const path = '/.well-known/openid-credential-issuer';
const failure: WellKnownJsonFailure = (reason) =>
  new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED, { context: { reason } });
const parameterFailure: Parameters<typeof fetchWellKnownJson>[3] = failure;
const assignBack: WellKnownJsonFailure = parameterFailure;

describe('common and identity public entries', () => {
  test('well-known JSON rejects an insecure issuer before calling fetch', async () => {
    let calls = 0;
    const fetchImpl: FetchLike = async () => {
      calls += 1;
      return new Response('{}');
    };

    await expect(
      fetchWellKnownJson('http://issuer.example', path, fetchImpl, assignBack),
    ).rejects.toMatchObject({
      context: { reason: 'non_https_issuer' },
    });
    expect(calls).toBe(0);
  });

  test('well-known JSON preserves the caller error mapping and final-origin binding', async () => {
    const fetched: string[] = [];
    const fetchImpl: FetchLike = async (url) => {
      fetched.push(url);
      return url === `${issuer}${path}`
        ? new Response(null, { status: 302, headers: { location: 'https://other.example/doc' } })
        : new Response('{}', { headers: { 'content-type': 'application/json' } });
    };

    const caught = await fetchWellKnownJson(issuer, path, fetchImpl, failure, issuer).catch(
      (error: unknown) => error,
    );
    expect(caught).toBeInstanceOf(RootError);
    expect(caught).toMatchObject({
      code: ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      context: { reason: 'cross_origin_redirect' },
    });
    expect(fetched).toEqual([`${issuer}${path}`, 'https://other.example/doc']);
  });

  test('JSON parser keeps prototype safety and HTTPS guard is public-host aware', () => {
    const parsed = parseJsonWithoutPrototype('{"__proto__":{"polluted":true}}');
    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect(Object.hasOwn(parsed as object, '__proto__')).toBe(true);
    expect(isPublicHttpsUrl('https://127.0.0.1/')).toBe(false);
    expect(isPublicHttpsUrl(issuer)).toBe(true);
  });

  test('identity limit shares the root definition', () => {
    expect(MAX_LINKED_DIDS).toBe(32);
    expect(MAX_LINKED_DIDS).toBe(ROOT_MAX_LINKED_DIDS);
  });
});
