/**
 * JSON の絞り込み先の必須プロパティ（型では必須でも実体は外部入力で欠落し得る）を、`Object.prototype` 汚染下で
 * 読んだときに結果が変わらないことの回帰テスト。各ケースは「欠落した必須キーを汚染した後の結果」が
 * 「汚染前の結果」と一致することを見る。許可リスト（allowlist.ts）の根拠（デコーダが必須キーの欠落を汚染下でも拒否する）も確認する。
 */

import { describe, expect, it } from 'bun:test';
import { decodeDocument } from '../../../wallet/codec.js';
import { createTtlCache } from '../../cache/ttl-cache.js';
import { resolveSchemaUrl } from '../../credential/vc/credential-schema/validate.js';
import { didDocumentToVerifierKey } from '../../credential/vc/verifier-key.js';
import { decodeDelegatedDID } from '../../delegated-did/codec.js';
import { ErrorCodes } from '../../errors.js';
import { decodeBatchCredentialPool } from '../../eudi/batch/codec.js';
import { decodeCredentialRecord, decodeDashboardLogEntry } from '../../gdpr/codec.js';
import { verifyDashboardLogChain } from '../../gdpr/log-integrity/chain.js';
import { resolveDeletionRecords } from '../../gdpr/log-integrity/deletion-records.js';
import { readTailAnchor } from '../../gdpr/log-integrity/tail-anchor.js';
import type { DashboardLogEntry } from '../../gdpr/types.js';
import type { DIDDocument, PublicKeyJwk } from '../../identity/did.js';
import { createStatusListResolver } from '../../issuer/status-list-resolver.js';
import { correlationHeaders } from '../../observability/correlation.js';
import { decodeMetadata } from '../../persona/codec.js';
import { readTrustedListCache, storeTrustedListCache } from '../../trust/etsi-tsl/cache.js';
import { decodeTrustedIssuerList } from '../../trusted-issuer/codec.js';
import { buildTrustedIssuerIndex } from '../../trusted-issuer/issuer-index.js';
import { isTrustedIssuer } from '../../trusted-issuer/trusted-issuer-list-store.js';
import {
  withPollutedPrototype,
  withPollutedPrototypeAsync,
} from '../prototype-pollution.fixtures.js';

/** 必須キーとして読まれ得る名前を、検証を通りそうな文字列・数値で一斉に汚染する。 */
const POLLUTION: Record<string, unknown> = Object.fromEntries(
  [
    'id',
    'did',
    'controllerDID',
    'name',
    'status',
    'resolvedAt',
    'holderDID',
    'subjectDID',
    'relationship',
    'validFrom',
    'vct',
    'totalCount',
    'usedCount',
    'createdAt',
    'lastUsedAt',
    'index',
    'type',
    'recordedAt',
    'signature',
    'credential',
    'derivationPath',
    'address',
    'trustedIssuers',
    'listOperator',
    'listName',
    'issuedAt',
    'version',
    'prevHash',
    'rpIdentifier',
  ].map((key) => [key, 'x']),
);
POLLUTION.payload = {};
POLLUTION.index = 1;
POLLUTION.totalCount = 1;
POLLUTION.usedCount = 0;

const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

function outcome(fn: () => unknown): string {
  try {
    return `ok:${JSON.stringify(fn())}`;
  } catch (error) {
    return `err:${(error as { code?: unknown }).code ?? (error as Error).name}`;
  }
}

describe('allowlist の根拠: デコーダは必須キーを欠く入力を汚染下でも同じ結果（拒否）にする', () => {
  const decoders: readonly (readonly [string, (b: Uint8Array) => unknown])[] = [
    ['decodeDelegatedDID', decodeDelegatedDID],
    ['decodeBatchCredentialPool', decodeBatchCredentialPool],
    ['decodeMetadata', decodeMetadata],
    ['decodeCredentialRecord', decodeCredentialRecord],
    ['decodeDashboardLogEntry', decodeDashboardLogEntry],
    ['decodeTrustedIssuerList', decodeTrustedIssuerList],
    ['decodeDocument', decodeDocument],
  ];
  for (const [name, decode] of decoders) {
    it(`${name}`, () => {
      const clean = outcome(() => decode(bytes('{}')));
      // 検証を持たないデコーダ（decodeDocument）は `{}` を受理するが、結果は汚染前後で同じ（null プロトタイプなので継承値を含まない）。
      expect(withPollutedPrototype(POLLUTION, () => outcome(() => decode(bytes('{}'))))).toBe(
        clean,
      );
    });
  }
});

describe('Dashboard ログの chain 検証は汚染値で判定が変わらない', () => {
  const key = {
    alg: 'ES256' as const,
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } as PublicKeyJwk,
  };
  // id / prevHash / signature / type / recordedAt / payload をすべて省略した手組みエントリ。
  const bare = [{}, {}] as unknown as DashboardLogEntry[];

  it('verifyDashboardLogChain: issues が汚染前後で一致する', () => {
    const clean = JSON.stringify(verifyDashboardLogChain(bare, key));
    const polluted = withPollutedPrototype(
      {
        id: 'dashboard-log:00000000',
        type: 'consentGranted',
        recordedAt: '2026-01-01T00:00:00.000Z',
        prevHash: null,
        signature: 'a.b.c',
        payload: {},
      },
      () => JSON.stringify(verifyDashboardLogChain(bare, key)),
    );
    expect(polluted).toBe(clean);
    expect(JSON.parse(clean).ok).toBe(false);
  });

  it('resolveDeletionRecords: 汚染 type で削除記録を作らない', () => {
    const polluted = withPollutedPrototype(
      { type: 'logEntryDeleted', payload: { entries: [] }, signature: 'a.b.c' },
      () => resolveDeletionRecords(bare, key).size,
    );
    expect(polluted).toBe(resolveDeletionRecords(bare, key).size);
    expect(polluted).toBe(0);
  });

  it('readTailAnchor: 保存済みアンカーが欠く seq / hash を汚染値で補わない', async () => {
    const storage = { get: async () => bytes('{}') } as unknown as Parameters<
      typeof readTailAnchor
    >[0];
    const polluted = await withPollutedPrototypeAsync({ seq: 3, hash: 'evil' }, () =>
      readTailAnchor(storage, 'p'),
    );
    expect(polluted).toEqual({ kind: 'invalid' });
  });
});

describe('Trusted Issuer の信頼判定は汚染値で信頼エントリを作らない', () => {
  it('trustedIssuers を持たないリストは汚染 trustedIssuers を信頼しない', () => {
    const list = {} as never;
    const polluted = withPollutedPrototype(
      { trustedIssuers: [{ id: 'did:ex:evil', name: 'x' }] },
      () => ({
        direct: isTrustedIssuer(list, 'did:ex:evil'),
        index: buildTrustedIssuerIndex(list).size,
      }),
    );
    expect(polluted).toEqual({ direct: false, index: 0 });
  });

  it('id を持たないエントリは汚染 id で発行者に一致しない', () => {
    const list = { trustedIssuers: [{ name: 'anonymous' }] } as never;
    expect(
      withPollutedPrototype({ id: 'did:ex:evil' }, () => isTrustedIssuer(list, 'did:ex:evil')),
    ).toBe(false);
    expect(
      withPollutedPrototype({ id: 'did:ex:evil' }, () => buildTrustedIssuerIndex(list).size),
    ).toBe(0);
  });
});

describe('失効判定・スキーマ・鍵選択の参照先は汚染値で選ばれない', () => {
  it('status_list を省略した参照は汚染 uri / idx で解決しない（VC_SCHEMA_INVALID）', async () => {
    const fetched: string[] = [];
    const resolver = createStatusListResolver({
      fetchToken: async (uri: string) => {
        fetched.push(uri);
        throw new Error('unreachable');
      },
      issuerPublicKey: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
      purpose: 'revocation',
    } as never);
    for (const ref of [{}, { status_list: {} }]) {
      await withPollutedPrototypeAsync(
        {
          status_list: { idx: 0, uri: 'https://evil.example/sl' },
          idx: 0,
          uri: 'https://evil.example/sl',
        },
        async () => {
          await expect(resolver.resolve(ref as never)).rejects.toMatchObject({
            code: ErrorCodes.VC_SCHEMA_INVALID,
          });
        },
      );
    }
    expect(fetched).toEqual([]);
  });

  it('credentialSchema 参照が id を省略したら汚染 id のスキーマを取りに行かない', () => {
    const vc = { credentialSchema: { type: 'JsonSchema' } } as never;
    expect(() =>
      withPollutedPrototype({ id: 'https://evil.example/schema.json' }, () => resolveSchemaUrl(vc)),
    ).toThrow(expect.objectContaining({ code: ErrorCodes.SCHEMA_NOT_SPECIFIED }));
    const noType = { credentialSchema: { id: 'https://ok.example/s.json' } } as never;
    expect(() =>
      withPollutedPrototype({ type: 'JsonSchema' }, () => resolveSchemaUrl(noType)),
    ).toThrow(expect.objectContaining({ code: ErrorCodes.SCHEMA_NOT_SPECIFIED }));
  });

  it('didDocumentToVerifierKey: id を欠く VerificationMethod は汚染 id で選ばれない', () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' };
    const doc = {
      id: 'did:ex:a',
      verificationMethod: [{ type: 'JsonWebKey2020', controller: 'did:ex:a', publicKeyJwk: jwk }],
      authentication: ['did:ex:a#k'],
    } as unknown as DIDDocument;
    const attempt = (): unknown => didDocumentToVerifierKey(doc);
    const clean = outcome(attempt);
    expect(clean.startsWith('err:')).toBe(true);
    expect(withPollutedPrototype({ id: 'did:ex:a#k' }, () => outcome(attempt))).toBe(clean);
  });
});

describe('外向きヘッダ・TSL キャッシュは汚染値を採用しない', () => {
  it('correlationHeaders: 省略した traceparent / requestId を汚染値で補わない', () => {
    const clean = correlationHeaders({} as never);
    const polluted = withPollutedPrototype(
      {
        traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
        requestId: 'evil-req',
      },
      () => correlationHeaders({} as never),
    );
    expect(polluted).toEqual(clean);
    expect(polluted).toEqual({});
  });

  it('storeTrustedListCache: url / xml / type を欠くエントリは汚染値のキーで格納しない', () => {
    const cache = createTtlCache<never>({
      maxTtlSeconds: 3600,
      maxEntries: 8,
      nowSeconds: () => 0,
    });
    const entry = { nextUpdate: '2099-01-01T00:00:00Z' } as never;
    withPollutedPrototype({ url: 'https://evil.example/tl.xml', xml: '<x/>', type: 'tsl' }, () =>
      storeTrustedListCache(cache as never, entry, 1_700_000_000),
    );
    expect(
      readTrustedListCache(cache as never, 'https://evil.example/tl.xml', 1_700_000_000),
    ).toBeUndefined();
  });
});
