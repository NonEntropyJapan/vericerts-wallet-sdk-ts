/**
 * Federation 取得の SSRF 防止: 取得前の公開ホスト検査と、リダイレクトのホップごとの検査。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import { entityConfigurationUrl, resolveEntityConfiguration } from '../../entity-configuration.js';
import { nowFn } from '../federation-fixtures.js';

const ENTITY_ID = 'https://leaf.example.eu';
const WELL_KNOWN = `${ENTITY_ID}/.well-known/openid-federation`;

async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
}

describe('resolveEntityConfiguration - 公開ホスト限定', () => {
  it('entity_id が内部ホストなら取得前に TRUST_CHAIN_INVALID', async () => {
    let called = false;
    const fetchFn = (async () => {
      called = true;
      return new Response('x', { status: 200 });
    }) as unknown as typeof fetch;
    for (const id of ['https://10.0.0.5', 'https://169.254.169.254', 'https://localhost']) {
      expect(() => entityConfigurationUrl(id)).toThrow(VericertsError);
      await expectRejectCode(
        resolveEntityConfiguration(id, { fetchFn, now: nowFn }),
        ErrorCodes.TRUST_CHAIN_INVALID,
      );
    }
    expect(called).toBe(false);
  });

  it('公開ホストから内部ホストへのリダイレクトは追従せず FEDERATION_FETCH_FAILED', async () => {
    const requested: string[] = [];
    const modes: Array<RequestRedirect | undefined> = [];
    const fetchFn = (async (input: string | URL, init?: RequestInit) => {
      requested.push(String(input));
      modes.push(init?.redirect);
      return new Response(null, { status: 302, headers: { Location: 'https://10.0.0.5/x' } });
    }) as typeof fetch;
    await expectRejectCode(
      resolveEntityConfiguration(ENTITY_ID, { fetchFn, now: nowFn }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    expect(requested).toEqual([WELL_KNOWN]);
    expect(modes).toEqual(['manual']);
  });
});
