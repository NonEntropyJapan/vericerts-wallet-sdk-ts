/**
 * Offer / Issuer Metadata の入力量上限。件数 × 長さの積で CPU を占有させない。
 * 実時間ではなく、拒否される境界・走査回数（Proxy の読み取り数）・予算消費量（`WorkMeter.spent`）で pin する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { newWorkMeter } from '../../../../primitives/bounded-input.js';
import {
  AUTHORIZATION_SERVERS_LIMITS,
  CREDENTIAL_CONFIGURATION_ID_LIMITS,
  CREDENTIAL_DEFINITION_TYPE_LIMITS,
  MAX_AUTHORIZATION_SERVER_LENGTH,
  MAX_METADATA_TYPE_SCAN_UNITS,
} from '../../../../primitives/oid4vci-input-limits.js';
import {
  CREDENTIAL_URL,
  createStubFetch,
  ISSUER,
  jsonResponse,
  METADATA_URL,
  TOKEN_URL,
} from '../../../eudi/issuance/__tests__/issuance-fixtures.js';
import { fetchIssuerMetadata } from '../../../eudi/issuance/metadata.js';
import {
  resolveCredentialDefinitionTypes,
  resolveCredentialFormats,
} from '../../../eudi/issuance/metadata-configurations.js';
import { resolveAuthorizationServer } from '../../identifier/authorization-server.js';
import { parseCredentialOffer } from '../../offer/oid4vci-offer.js';

function offerUri(offer: Record<string, unknown>): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

async function codeOf(run: () => unknown): Promise<string | undefined> {
  try {
    await run();
    return undefined;
  } catch (e) {
    return e instanceof VericertsError ? e.code : 'non-VericertsError';
  }
}

/** 添字読み取りを数える配列。 */
function countingArray<T>(items: T[]): { array: T[]; reads: () => number } {
  let reads = 0;
  const array = new Proxy(items, {
    get(target, prop, receiver) {
      if (typeof prop === 'string' && /^\d+$/.test(prop)) {
        reads++;
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  return { array, reads: () => reads };
}

describe('Offer の credential_configuration_ids 上限', () => {
  const max = CREDENTIAL_CONFIGURATION_ID_LIMITS;
  const base = { credential_issuer: ISSUER };

  // 形状: 多数の極小 / 少数の巨大 / 件数 × 長さの合計超過 / 同一 id の水増し。
  it.each([
    ['多数の極小 id', Array.from({ length: max.maxCount + 1 }, (_, i) => `c${i}`)],
    ['少数の巨大 id', ['x'.repeat(max.maxItemLength + 1)]],
    [
      '件数・1 件長は上限内だが合計が超過',
      Array.from({ length: max.maxCount }, (_, i) => `${i}`.padEnd(max.maxItemLength, 'a')),
    ],
    ['同一 id の水増し', Array.from({ length: 100_000 }, () => 'dup')],
    ['空 id を含む', ['a', '']],
  ])('%s は OFFER_URI_PARSE_FAILED', async (_label, ids) => {
    expect(
      await codeOf(() =>
        parseCredentialOffer(offerUri({ ...base, credential_configuration_ids: ids })),
      ),
    ).toBe(ErrorCodes.OFFER_URI_PARSE_FAILED);
  });

  it('上限ちょうどの件数は受理する', async () => {
    const ids = Array.from({ length: max.maxCount }, (_, i) => `c${i}`);
    const offer = await parseCredentialOffer(
      offerUri({ ...base, credential_configuration_ids: ids }),
    );
    expect(offer.credential_configuration_ids).toEqual(ids);
  });
});

describe('authorization_server の長さ上限', () => {
  const grantKey = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  const offerWith = (authorizationServer: string) =>
    offerUri({
      credential_issuer: ISSUER,
      credential_configuration_ids: ['c'],
      grants: {
        [grantKey]: { 'pre-authorized_code': 'x', authorization_server: authorizationServer },
      },
    });

  it('上限超過（末尾スラッシュの長大な連続）は OFFER_URI_PARSE_FAILED', async () => {
    const huge = `https://as.example${'/'.repeat(MAX_AUTHORIZATION_SERVER_LENGTH)}`;
    expect(await codeOf(() => parseCredentialOffer(offerWith(huge)))).toBe(
      ErrorCodes.OFFER_URI_PARSE_FAILED,
    );
  });

  it('通常の authorization_server は受理する', async () => {
    const offer = await parseCredentialOffer(offerWith('https://as.example/'));
    expect(offer.grants?.[grantKey]).toBeDefined();
  });
});

describe('resolveAuthorizationServer の照合量', () => {
  const grant = (authorization_server: string) => ({ authorization_server });

  // 形状: 件数過多（極小）/ 少数の巨大 / 宣言値が巨大。いずれも告知側の要素を読む前、または長さ判定で拒否する。
  it('告知件数が上限を超えれば 1 件も読まずに拒否する（件数過多）', async () => {
    const { array, reads } = countingArray(
      Array.from({ length: 100_000 }, () => 'https://as.example/'),
    );
    array.push('https://as.example');
    const code = await codeOf(() =>
      resolveAuthorizationServer(grant('https://as.example'), array, ISSUER),
    );
    expect(code).toBe(ErrorCodes.TOKEN_REQUEST_FAILED);
    expect(reads()).toBe(0);
  });

  it('告知が巨大（長さ超過）なら一致扱いにしない（少数の巨大）', async () => {
    const huge = `https://as.example${'/'.repeat(MAX_AUTHORIZATION_SERVER_LENGTH)}`;
    expect(
      await codeOf(() => resolveAuthorizationServer(grant('https://as.example'), [huge], ISSUER)),
    ).toBe(ErrorCodes.TOKEN_REQUEST_FAILED);
  });

  it('宣言値が巨大なら拒否する', async () => {
    const huge = `https://as.example${'/'.repeat(MAX_AUTHORIZATION_SERVER_LENGTH)}`;
    expect(
      await codeOf(() => resolveAuthorizationServer(grant(huge), ['https://as.example'], ISSUER)),
    ).toBe(ErrorCodes.TOKEN_REQUEST_FAILED);
  });

  it('末尾スラッシュの有無を無視して告知と一致する（上限ちょうどの件数）', () => {
    const servers = Array.from(
      { length: AUTHORIZATION_SERVERS_LIMITS.maxCount },
      (_, i) => `https://as${i}.example/`,
    );
    expect(resolveAuthorizationServer(grant('https://as15.example'), servers, ISSUER)).toBe(
      'https://as15.example',
    );
  });
});

describe('Issuer Metadata の authorization_servers 上限', () => {
  const metadata = (authorizationServers: unknown) => () =>
    jsonResponse({
      credential_issuer: ISSUER,
      credential_endpoint: CREDENTIAL_URL,
      token_endpoint: TOKEN_URL,
      authorization_servers: authorizationServers,
    });

  it.each([
    [
      '件数超過',
      Array.from(
        { length: AUTHORIZATION_SERVERS_LIMITS.maxCount + 1 },
        (_, i) => `https://as${i}.example`,
      ),
    ],
    ['1 件の長さ超過', [`https://as.example/${'a'.repeat(MAX_AUTHORIZATION_SERVER_LENGTH)}`]],
    [
      '合計長超過',
      Array.from(
        { length: AUTHORIZATION_SERVERS_LIMITS.maxCount },
        (_, i) => `https://as${i}.example/${'a'.repeat(MAX_AUTHORIZATION_SERVER_LENGTH - 40)}`,
      ).concat(['https://x.example/' + 'a'.repeat(100)]),
    ],
  ])('%s は ISSUER_COMMUNICATION_FAILED', async (_label, servers) => {
    const stub = createStubFetch({ [METADATA_URL]: metadata(servers) });
    expect(await codeOf(() => fetchIssuerMetadata(ISSUER, stub.fetchImpl))).toBe('3004');
  });

  it('通常の authorization_servers は受理する', async () => {
    const stub = createStubFetch({ [METADATA_URL]: metadata(['https://as.example/']) });
    const endpoints = await fetchIssuerMetadata(ISSUER, stub.fetchImpl);
    expect(endpoints.authorizationServers).toEqual(['https://as.example/']);
  });
});

describe('Metadata の credential_definition.type 解決量', () => {
  const typeMax = CREDENTIAL_DEFINITION_TYPE_LIMITS.maxCount;
  const idMax = CREDENTIAL_CONFIGURATION_ID_LIMITS.maxCount;
  const configs = (entries: Record<string, string[]>) => ({
    credential_configurations_supported: Object.fromEntries(
      Object.entries(entries).map(([id, type]) => [
        id,
        { format: 'jwt_vc_json', credential_definition: { type } },
      ]),
    ),
  });

  it('少数の巨大 type 配列は 1 要素も読まず予算も消費しない', () => {
    const { array, reads } = countingArray(Array.from({ length: 1_000_000 }, () => 'T'));
    const meter = newWorkMeter(MAX_METADATA_TYPE_SCAN_UNITS);
    expect(resolveCredentialDefinitionTypes(configs({ a: array }), ['a'], meter)).toBeUndefined();
    expect(reads()).toBe(0);
    expect(meter.spent).toBe(0);
  });

  it('多数の id × 上限ちょうどの type でも消費量は id 件数 × type 件数で頭打ち', () => {
    const ids = Array.from({ length: idMax }, (_, i) => `c${i}`);
    const entries = Object.fromEntries(
      ids.map((id) => [id, Array.from({ length: typeMax }, () => 'T')]),
    );
    const meter = newWorkMeter(MAX_METADATA_TYPE_SCAN_UNITS);
    const resolved = resolveCredentialDefinitionTypes(configs(entries), ids, meter);
    expect(resolved?.size).toBe(idMax);
    expect(meter.spent).toBe(MAX_METADATA_TYPE_SCAN_UNITS);
    expect(meter.remaining).toBe(0);
  });

  it('予算が尽きた後の id は走査せず未収載にする', () => {
    const meter = newWorkMeter(typeMax);
    const entries = { a: Array.from({ length: typeMax }, () => 'T'), b: ['T'] };
    const resolved = resolveCredentialDefinitionTypes(configs(entries), ['a', 'b'], meter);
    expect([...(resolved?.keys() ?? [])]).toEqual(['a']);
    expect(meter.spent).toBe(typeMax);
  });

  it('同一 id の水増しは 1 回しか解決しない', () => {
    const meter = newWorkMeter(MAX_METADATA_TYPE_SCAN_UNITS);
    const ids = Array.from({ length: idMax }, () => 'a');
    expect(
      resolveCredentialDefinitionTypes(configs({ a: ['T1', 'T2'] }), ids, meter)?.get('a'),
    ).toEqual(['T1', 'T2']);
    expect(meter.spent).toBe(2);
  });

  it('id 件数が上限を超える直接呼び出しは解決しない（type / format とも）', () => {
    const ids = Array.from({ length: idMax + 1 }, (_, i) => `c${i}`);
    const parsed = configs(Object.fromEntries(ids.map((id) => [id, ['T']])));
    expect(resolveCredentialDefinitionTypes(parsed, ids)).toBeUndefined();
    expect(resolveCredentialFormats(parsed, ids)).toBeUndefined();
  });

  it('通常の type / format は解決できる', () => {
    const parsed = configs({ a: ['VerifiableCredential', 'Diploma'] });
    expect(resolveCredentialDefinitionTypes(parsed, ['a'])?.get('a')).toEqual([
      'VerifiableCredential',
      'Diploma',
    ]);
    expect(resolveCredentialFormats(parsed, ['a'])?.get('a')).toBe('jwt_vc_json');
  });
});
